#!/usr/bin/env python3
"""
t90_fw_tool.py - Alientek T90 firmware analysis and patching tool

Usage:
    t90_fw_tool.py info <file.atk>          # Print firmware header information
    t90_fw_tool.py extract <file.atk> [out.bin]  # Strip header, decrypt to .bin
    t90_fw_tool.py patch [--only ...] <file.atk> [out.atk]
                                    # Apply patches (default: all)

The "no lie" patch removes the fake temperature reading display
compensation from the T90 soldering iron firmware by replacing a
conditional branch (BNE) with a NOP instruction. Scope: displayed
temperature only — tip control and measurement are unaffected.

The "nologo" patch skips the boot logo animation loop (mvn.w r4, #0x26
-> movs r4, #2; nop), reducing logo show time to zero while keeping
the boot state machine intact.

The "fastlcd" patch shortens the LCD controller init waits
(100,100,200 ms -> 70,70,120 ms), saving ~140 ms of blank-screen time
at boot. The trimmed values stay within the MIPI DCS minimums
(120 ms after reset, 120 ms after SLPOUT). Unlike the other two
patches it alters hardware timing, so use --only to skip it if the
panel ever fails to initialize on cold boot.

Firmware version extraction: the T90 firmware contains a version
self-check function (Thumb) that loads its own version as a
single integer (e.g. 114 = v1.1.4) from RAM and compares it against
a compile-time immediate, e.g.:

    ldrh r0, [r0, #4]     ; version word
    cmp  r0, #0x72        ; == 114 (v1.1.4)?
    beq  <ok>

The tool scans the decrypted firmware for this pattern and decodes
the version from the compare immediate. If the pattern cannot be
found (unknown firmware), the version falls back to the filename
(e.g. t90_v1.1.4.atk).
"""

import sys
import re
import struct
import argparse

# Firmware obfuscation: simple XOR with 0xFF
XOR_KEY = 0xFF

# FileType values from the firmware header
FILE_TYPE_NAMES = {
    0xA0: "Application",
    0xA1: "Logo",
    0xB0: "Bootloader",
}


def xor_decrypt(data):
    """Decrypt/encrypt firmware payload using XOR 0xFF."""
    return bytes([b ^ XOR_KEY for b in data])


def parse_atk_header(data):
    """
    Parse the 13-byte FirmInfo header from an .atk file.
    Returns a dict with header fields or raises ValueError on invalid header.
    """
    if len(data) < 13:
        raise ValueError("File too small: must be at least 13 bytes (header)")

    # Unpack the header (little-endian)
    dev_type, hw_rev, app_ver, file_type, data_len, bin_size = struct.unpack_from(
        "<HBBBBI", data, 0
    )
    year, month, day = struct.unpack_from("<BBB", data, 10)

    header = {
        "dev_type": dev_type,
        "hw_rev": hw_rev,
        "app_ver": app_ver,
        "file_type": file_type,
        "data_len": data_len,
        "bin_size": bin_size,
        "date": f"20{year:02d}-{month:02d}-{day:02d}",
    }

    # Validate dev_type (should be 0x0208 for T90)
    if dev_type != 0x0208:
        raise ValueError(
            f"Invalid dev_type: 0x{dev_type:04X} (expected 0x0208 for T90)"
        )

    return header


def cmd_info(args):
    """Print firmware file information."""
    with open(args.file, "rb") as f:
        data = f.read()

    try:
        header = parse_atk_header(data)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    payload = xor_decrypt(data[13:])

    # Extract SP and Reset vector from decrypted firmware
    sp, reset = struct.unpack_from("<II", payload, 0)

    # Extract the real firmware version from the code (self-check immediate)
    firmware_version = None
    version_checks = find_firmware_version(payload)
    if version_checks:
        version_ints = sorted({imm for _, imm in version_checks})
        if len(version_ints) == 1:
            firmware_version = format_version(version_ints[0])
        else:
            print(f"  WARNING: multiple version check matches: "
                  f"{[format_version(v) for v in version_ints]}", file=sys.stderr)
            firmware_version = format_version(version_ints[0])
    else:
        # Fall back to the version baked into the filename
        firmware_version = parse_version_from_filename(args.file)

    print(f"File: {args.file}")
    print(f"Size: {len(data)} bytes (header: 13 + payload: {len(data) - 13})")
    print()
    print("=== Firmware Header (FirmInfo) ===")
    print(f"  dev_type:  0x{header['dev_type']:04X} (T90)")
    print(f"  hw_rev:    {header['hw_rev']}")
    print(f"  app_ver:   1.{header['app_ver'] // 10}.{header['app_ver'] % 10}" if header['app_ver'] >= 0x10 else f"  app_ver:   1.0.{header['app_ver']:02d}")
    file_type_name = FILE_TYPE_NAMES.get(header["file_type"], f"0x{header['file_type']:02X}")
    print(f"  file_type: {file_type_name}")
    print(f"  data_len:  {header['data_len']} bytes (chunk size)")
    print(f"  bin_size:  {header['bin_size']} bytes ({header['bin_size']} payload)")
    print(f"  date:      {header['date']}")
    print()
    print("=== Firmware Version ===")
    print(f"  version:   {firmware_version if firmware_version else 'unknown'}")
    if version_checks:
        print(f"  source:    code self-check immediates "
              f"({len(version_checks)} at payload offsets "
              f"{', '.join(f'0x{off:04X}' for off, _ in version_checks)})")
    elif firmware_version:
        print(f"  source:    filename (code self-check pattern not found)")
    else:
        print(f"  source:    unsure")
    print()
    print("=== Decrypted Vector Table ===")
    print(f"  Initial SP:    0x{sp:08X}")
    print(f"  Reset Vector:  0x{reset:08X}")
    print()
    print("=== Validation ===")

    # Check if file size matches expected
    expected_size = 13 + header["bin_size"]
    if len(data) == expected_size:
        print(f"  File size matches bin_size + header ({expected_size} bytes) - OK")
    else:
        print(f"  WARNING: File size ({len(data)}) does not match expected ({expected_size})")

    # Validate vector table addresses
    if 0x20000000 <= sp <= 0x20020000:
        print(f"  SP address in RAM range (0x2000xxxx) - OK")
    else:
        print(f"  WARNING: SP (0x{sp:08X}) outside expected RAM range")

    if 0x08000000 <= reset <= 0x08040000:
        print(f"  Reset vector in Flash range - OK")
    else:
        print(f"  WARNING: Reset vector (0x{reset:08X}) outside expected Flash range")

    print()
    print("=== Patches ===")

    patch_offset = find_function_location(payload, instruction=None)
    patched_offset = find_function_location(payload, instruction=THUMB_NOP)

    if patch_offset is not None:
        print(f"  nolie:    not patched (BNE at payload offset 0x{patch_offset:04X}, "
              f"ARM 0x{0x08005000 + patch_offset:08X})")
    elif patched_offset is not None:
        print(f"  nolie:    already patched (NOP at payload offset 0x{patched_offset:04X}, "
              f"ARM 0x{0x08005000 + patched_offset:08X})")
    else:
        print(f"  nolie:    unknown ('lie' function signature not found - "
              f"unsupported firmware version?)")

    anim_off = find_logo_anim(payload)
    if anim_off is not None:
        arm = 0x08005000 + anim_off
        print(f"  nologo:   not patched (mvn.w r4, #0x26 at payload offset 0x{anim_off:05X}, "
              f"ARM 0x{arm:08X})")
    elif find_logo_anim_patch(payload) is not None:
        print(f"  nologo:   already patched (movs r4, #2; nop present, logo skipped)")
    else:
        print(f"  nologo:   unknown (logo animation pattern not found - "
              f"unsupported firmware version?)")

    lcd = find_lcd_waits(payload, patched=False)
    lcd_patched = find_lcd_waits(payload, patched=True)
    if lcd is not None:
        vals = ", ".join(f"{v} ms" for _, v in lcd)
        print(f"  fastlcd:  not patched (LCD waits: {vals})")
    elif lcd_patched is not None:
        vals = ", ".join(f"{v} ms" for _, v in lcd_patched)
        print(f"  fastlcd:  already patched (LCD waits: {vals})")
    else:
        print(f"  fastlcd:  unknown (LCD init wait pattern not found - "
              f"unsupported firmware version?)")

    return 0


def cmd_extract(args):
    """Strip header and decrypt firmware to .bin file."""
    with open(args.file, "rb") as f:
        data = f.read()

    try:
        header = parse_atk_header(data)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Decrypt the payload
    payload = xor_decrypt(data[13:])

    # Determine firmware version (used when naming the output file)
    version = determine_firmware_version(payload, args.file)

    # Determine output file name
    if args.output:
        output_file = args.output
    else:
        if args.file.endswith(".atk"):
            output_file = args.file[:-4] + ".bin"
        else:
            output_file = args.file + ".bin"

    # Add the firmware version to the name if it's not already there
    output_file = make_versioned_filename(output_file, version)

    with open(output_file, "wb") as f:
        f.write(payload)

    print(f"Extracted firmware to: {output_file}")
    print(f"  Payload size: {len(payload)} bytes")
    print(f"  Image base: 0x08005000 (ARM Cortex-M4)")
    if version:
        print(f"  Firmware version: {version}")

    return 0


# Thumb instruction patterns (decrypted)
THUMB_PUSH_R4R5R6LR = 0xB570  # PUSH {R4, R5, R6, LR}
THUMB_MOV_R4_R0 = 0x4604       # MOV R4, R0
THUMB_MOV_R5_R1 = 0x460D       # MOV R5, R1
THUMB_MOV_R6_R2 = 0x4616       # MOV R6, R2
THUMB_CMP_R5_R4 = 0x42AC       # CMP R5, R4
THUMB_NOP = 0xBF00             # NOP
THUMB_MOV_R0_R4 = 0x4620       # MOV R0, R4
THUMB_POP_R4R5R6PC = 0xBD70    # POP {R4, R5, R6, PC}


def format_version(value):
    """Format a packed version integer (e.g. 114) as '1.1.4'."""
    if 100 <= value <= 999:
        return f"{value // 100}.{(value % 100) // 10}.{value % 10}"
    return str(value)


def find_firmware_version(payload):
    """
    Extract the firmware version from decrypted payload.

    The firmware contains a version self-check (Thumb). It loads its
    own version as a single integer (e.g. 114 = v1.1.4) from RAM and
    compares it with a compile-time immediate:

        ldrh Rt, [Rn, #4]     opcode 1000_1 imm5=2 (Rn, #4)
        cmp  Rt, #imm8        opcode 001_01 Rd=Rt
        beq  <skip>           opcode 1101 cond=0 (EQ)

    Returns a list of tuples (payload_offset, version_int) for every
    match of this pattern (typically there is exactly one).
    """
    checks = []
    n = len(payload)
    code_end = min(n - 4, 0x18000)  # stop before string/locale data

    for i in range(0x800, code_end, 2):
        hw = struct.unpack_from("<H", payload, i)[0]

        # LDRH Rt, [Rn, #4]  (T1: 1000_1 imm5(5) Rn(3) Rt(3), imm5*2 == 4)
        if not (0x8800 <= (hw & 0xFF00) <= 0x8F00):
            continue
        if ((hw >> 6) & 0x1F) != 2:
            continue
        rt = hw & 0x7

        # CMP Rt, #imm8 (T2: 001_01 Rd(3) imm8(8)) within 3 halfwords
        for gap in range(1, 4):
            pos = i + gap * 2
            if pos + 2 > n:
                break
            chw = struct.unpack_from("<H", payload, pos)[0]
            if (chw >> 11) != 0b00101:
                continue
            if ((chw >> 8) & 0x7) != rt:
                continue
            imm = chw & 0xFF

            # B EQ right after the compare (cond == 0)
            bpos = pos + 2
            if bpos + 2 > n:
                break
            bhw = struct.unpack_from("<H", payload, bpos)[0]
            if (bhw >> 12) == 0xD and ((bhw & 0x0F00) >> 8) == 0x0:
                checks.append((i, imm))

    return checks


def parse_version_from_filename(filename):
    """
    Fall back: parse the version from the firmware filename,
    e.g. maximize_t90_v1.1.4.atk -> '1.1.4'. Returns None if not found.
    """
    import re
    match = re.search(r"t90[_s-]*v?(\d+)\.(\d+)\.(\d+)", filename, re.IGNORECASE)
    if match:
        return ".".join(match.groups())
    return None


def determine_firmware_version(payload, input_file):
    """
    Determine the firmware version string ('1.1.4') of a firmware image.

    Prefers the version self-check immediates found in the decrypted
    code; falls back to the version baked into the input file name.
    Returns None if the version cannot be determined.
    """
    version_checks = find_firmware_version(payload)
    if version_checks:
        version_ints = sorted({imm for _, imm in version_checks})
        if len(version_ints) != 1:
            print(f"  WARNING: multiple version check matches: "
                  f"{[format_version(v) for v in version_ints]}", file=sys.stderr)
        return format_version(version_ints[0])
    return parse_version_from_filename(input_file)


def version_in_filename(filename, version):
    """
    Check whether a firmware version is already present in a file name.

    Matches dotted forms like '1.1.4' or 'v1.1.4' (optionally preceded by
    more version text), and also consults the same filename heuristics as
    parse_version_from_filename. Returns False if version is None.
    """
    if not version:
        return False
    escaped = re.escape(version)
    if re.search(rf"(?<![0-9])v?{escaped}(?![0-9])", filename, re.IGNORECASE):
        return True
    return parse_version_from_filename(filename) == version


def make_versioned_filename(filename, version):
    """
    Insert the firmware version into a file name, e.g.
    't90_nolie.atk' + '1.1.4' -> 't90_nolie_v1.1.4.atk'.

    Leaves the name untouched if the version is unknown or is already
    part of the file name, or if the name was supplied by the user.
    """
    if not version or version_in_filename(filename, version):
        return filename
    dot = filename.rfind(".")
    if dot > 0:
        return f"{filename[:dot]}_v{version}{filename[dot:]}"
    return f"{filename}_v{version}"


def find_function_location(payload, instruction=None):
    """
    Search for the 'lie' function signature in decrypted firmware.

    Searches for the 7-instruction sequence:
        PUSH {R4, R5, R6, LR}
        MOV  R4, R0
        MOV  R5, R1
        MOV  R6, R2
        CMP  R5, R4
        <instruction>     <- BNE (unpatched) or NOP (already patched)
        MOV  R0, R4
        POP  {R4, R5, R6, PC}

    Args:
        payload: The decrypted firmware bytes.
        instruction: What to expect at the 6th slot.
            - None:  match BNE with offset 0x01 (unpatched firmware)
            - THUMB_NOP: match NOP (already-patched firmware)

    Returns the payload offset of the 6th instruction, or None if not found.
    """
    signature = [
        THUMB_PUSH_R4R5R6LR,    # PUSH {R4, R5, R6, LR}
        THUMB_MOV_R4_R0,         # MOV R4, R0
        THUMB_MOV_R5_R1,         # MOV R5, R1
        THUMB_MOV_R6_R2,         # MOV R6, R2
        THUMB_CMP_R5_R4,         # CMP R5, R4
        instruction,             # BNE (None) or NOP (already patched)
        THUMB_MOV_R0_R4,         # MOV R0, R4 (early return body)
        THUMB_POP_R4R5R6PC,      # POP {R4, R5, R6, PC}
    ]

    for i in range(len(payload) - 7 * 2):
        match = True
        for j, expected in enumerate(signature):
            hw = struct.unpack_from("<H", payload, i + j * 2)[0]
            if expected is not None:
                if hw != expected:
                    match = False
                    break
            else:
                # BNE check: condition field == 0x01 (NE), opcode D000-DF00
                if (hw & 0xF000) != 0xD000:
                    match = False
                    break
                if (hw & 0x0F00) != 0x0100:  # NE condition
                    match = False
                    break
                if (hw & 0xFF) != 0x01:  # imm == 0x01 (BNE #2 -> skip +6)
                    match = False
                    break

        if match:
            return i + 5 * 2  # offset of the BNE/NOP instruction

    return None


def cmd_patch(args):
    """Apply the selected patches (default: nolie + nologo + fastlcd)."""
    selected = set(args.only) if args.only else {"nolie", "nologo", "fastlcd"}
    do_nolie = "nolie" in selected
    do_nologo = "nologo" in selected
    do_fastlcd = "fastlcd" in selected

    with open(args.file, "rb") as f:
        data = bytearray(f.read())

    try:
        header = parse_atk_header(data)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Decrypt the payload
    payload = xor_decrypt(bytes(data[13:]))

    # Determine firmware version (used when naming the output file)
    version = determine_firmware_version(payload, args.file)

    new_payload = bytearray(payload)

    if do_nolie:
        # Find the patch location
        patch_offset = find_function_location(new_payload, instruction=None)

        if patch_offset is None:
            if find_function_location(new_payload, instruction=THUMB_NOP) is not None:
                print("Error: firmware is already patched (NOP found instead of BNE).",
                      file=sys.stderr)
            else:
                print("Error: Could not find the 'lie' patch location in firmware.", file=sys.stderr)
                print("  The function signature pattern was not found.", file=sys.stderr)
                print("  This may be a different firmware version or already patched.", file=sys.stderr)
            return 1

        print(f"Patch location found at payload offset 0x{patch_offset:04X} "
            f"(ARM 0x{0x08005000 + patch_offset:08X})")

        # Read the current instruction (should be BNE)
        current_hw = struct.unpack_from("<H", new_payload, patch_offset)[0]
        arm_addr = 0x08005000 + patch_offset

        print(f"Current instruction at 0x{arm_addr:08X}: 0x{current_hw:04X}")

        # Decode it to show what we're replacing
        if (current_hw & 0xFF00) == 0xD100 and (current_hw & 0x0F00) == 0x0100:
            imm = current_hw & 0xFF
            target_offset = patch_offset + imm * 2 + 4
            target_addr = 0x08005000 + target_offset
            print(f"  BNE #{imm*2+4:+d} -> jumps to 0x{target_addr:08X} (the 'lie' code)")
        else:
            print(f"  WARNING: Expected BNE, found different instruction", file=sys.stderr)
            print(f"  Not patching - aborting for safety", file=sys.stderr)
            return 1

        # Check if already patched (NOP)
        if current_hw == THUMB_NOP:
            print("Firmware is already patched (NOP found instead of BNE)", file=sys.stderr)
            return 1

        # Apply patch: BNE -> NOP
        struct.pack_into("<H", new_payload, patch_offset, THUMB_NOP)

        print(f"  New instruction: 0x{THUMB_NOP:04X} (NOP)")
        print(f"  This removes the 'lie' temperature display compensation")

    if do_nologo:
        # Apply logo animation skip: mvn.w r4, #0x26 -> movs r4, #2; nop
        anim_off = find_logo_anim(new_payload)
        if anim_off is None:
            if find_logo_anim_patch(new_payload) is not None:
                print(f"Logo animation already skipped (patch present).")
            else:
                print("Error: logo animation pattern not found.", file=sys.stderr)
                print("  Unsupported firmware version?", file=sys.stderr)
                return 1
        else:
            print(f"Logo animation init at payload offset 0x{anim_off:05X} "
                  f"(ARM 0x{0x08005000 + anim_off:08X}): mvn.w r4, #0x26 (-39)")
            for desc, _, actual, ok in verify_logo_anim(new_payload, anim_off):
                print(f"    {'OK ' if ok else 'FAIL'}  {desc}: {actual}")
                if not ok:
                    print(f"  Surrounding code mismatch - not patching for safety",
                          file=sys.stderr)
                    return 1
            new_payload[anim_off:anim_off + 4] = LOGO_ANIM_PATCH
            print(f"  Patched to: movs r4, #2; nop (loop runs zero times, logo skipped)")

    if do_fastlcd:
        # Shorten LCD controller init waits: 100,100,200 ms -> 70,70,120 ms.
        waits = find_lcd_waits(new_payload, patched=False)
        if waits is None:
            if find_lcd_waits(new_payload, patched=True) is not None:
                print(f"LCD waits already shortened (patch present).")
            else:
                print("Error: LCD init wait pattern not found.", file=sys.stderr)
                print("  Unsupported firmware version?", file=sys.stderr)
                return 1
        else:
            for (movs_off, old), new in zip(waits, LCD_WAIT_PATCH):
                arm = 0x08005000 + movs_off
                print(f"LCD wait at payload offset 0x{movs_off:05X} "
                      f"(ARM 0x{arm:08X}): movs r0, #{old} -> movs r0, #{new}")
                struct.pack_into("<H", new_payload, movs_off, 0x2000 | new)
            print(f"  Patched to: LCD waits {list(LCD_WAIT_PATCH)} ms "
                  f"(saves ~{sum(LCD_WAIT_ORIG) - sum(LCD_WAIT_PATCH)} ms of boot time)")

    # Re-encrypt the payload
    encrypted_payload = xor_decrypt(bytes(new_payload))

    # Build the output file
    output = bytearray(data[:13])  # Keep original header
    output.extend(encrypted_payload)

    suffix = ""
    for name in ("nolie", "nologo", "fastlcd"):
        if name in selected:
            suffix += "_" + name
    if not suffix:
        print("Error: no patches selected.", file=sys.stderr)
        return 1
    # Determine output file
    if args.output:
        output_file = args.output
    else:
        if args.file.endswith(".atk"):
            base, ext = args.file[:-4], ".atk"
        else:
            base, ext = args.file, ""
        # Strip any previous patch suffixes so re-runs never stack them.
        changed = True
        while changed:
            changed = False
            for old in ("_nolie", "_nologo", "_fastlcd"):
                if base.endswith(old):
                    base = base[:-len(old)]
                    changed = True
        # Version goes before the suffixes: t90_v1.1.4_nolie_nologo.atk
        output_file = make_versioned_filename(base, version) + suffix + ext

    # Add the firmware version to the name if it's not already there
    output_file = make_versioned_filename(output_file, version)

    with open(output_file, "wb") as f:
        f.write(output)

    print(f"\nPatched firmware written to: {output_file}")
    print(f"  Original size: {len(data)} bytes")
    print(f"  Output size:   {len(output)} bytes")
    if version:
        print(f"  Firmware version: {version}")

    return 0


# Boot logo animation: the logo task draws the 160x40 logo in a loop
# with a sliding Y-offset, starting at r4 = ~0x26 (-39) and stepping +2
# until r4 >= 2 (~21 fullscreen draws). This dominates boot time.
# Patching the loop init to r4 = 2 skips all draws (zero logo time)
# while keeping the state-machine tail intact.
LOGO_ANIM_ORIG = bytes([0x6F, 0xF0, 0x26, 0x04])  # mvn.w r4, #0x26
LOGO_ANIM_PATCH = bytes([0x02, 0x24, 0x00, 0xBF])  # movs r4, #2; nop

# Expected Thumb neighbours of the animation init, as (delta, mask, value,
# description). Register/offset fields that vary across firmware builds
# (branch targets, literal-pool offsets) are masked out; only the opcode
# class and fixed registers are checked.
LOGO_ANIM_SURROUND = [
    (-8, 0xF907, 0xB900, "CBNZ r0"),
    (-6, 0xFFFF, 0x2000, "MOVS r0, #0"),
    (-4, 0xF800, 0x4800, "LDR Rt, [PC, #imm] (r1)"),
    (-2, 0xFFFF, 0x7008, "STRB r0, [r1]"),
    (+4, 0xF800, 0xE000, "B <loop>"),
    (+6, 0xFFFF, 0x2C00, "CMP r4, #0"),
    (+8, 0xFF00, 0xDB00, "BLT <redraw>"),
    (+10, 0xFFFF, 0x2400, "MOVS r4, #0"),
]

# Deltas at which the exact register also matters (LDR Rt must be r1).
LOGO_ANIM_LDR_RT = 1


def verify_logo_anim(payload, idx):
    """Check the instructions surrounding a logo-anim candidate.

    Returns a list of (description, expected, actual, ok) tuples, or
    None if the candidate is out of bounds.
    """
    n = len(payload)
    if idx < 8 or idx + 14 > n:
        return None
    results = []
    for delta, mask, value, desc in LOGO_ANIM_SURROUND:
        hw = struct.unpack_from("<H", payload, idx + delta)[0]
        if delta == -4:
            # LDR: opcode class + Rt == r1 must both hold.
            ok = (hw & 0xF800) == 0x4800 and ((hw >> 8) & 0x7) == LOGO_ANIM_LDR_RT
            results.append((desc, f"0x4800|Rt=1", f"0x{hw:04X}", ok))
        else:
            results.append((desc, f"0x{value:04X}", f"0x{hw:04X}",
                            (hw & mask) == value))
    return results


def find_logo_anim(payload):
    """Find payload offset of the logo animation init (mvn.w r4, #0x26).

    Every raw byte-match is validated against its surrounding code; a
    candidate whose neighbours do not decode as expected is skipped, so
    a stray 0x6FF02604 inside bitmap/data cannot be mispatched. Returns
    the offset or None.
    """
    raw = bytes(payload)
    start = 0
    while True:
        idx = raw.find(LOGO_ANIM_ORIG, start)
        if idx < 0:
            return None
        results = verify_logo_anim(payload, idx)
        if results is not None and all(ok for _, _, _, ok in results):
            return idx
        start = idx + 1


def find_logo_anim_patch(payload):
    """Find payload offset of an applied logo-skip patch, if surroundings fit."""
    raw = bytes(payload)
    start = 0
    while True:
        idx = raw.find(LOGO_ANIM_PATCH, start)
        if idx < 0:
            return None
        results = verify_logo_anim(payload, idx)
        if results is not None and all(ok for _, _, _, ok in results):
            return idx
        start = idx + 1


# Millisecond busy-wait used all over the firmware (LCD init, beep, task
# pacing). Shape (identical bytes in v1.1.4/v1.1.5/v1.1.6, address varies):
#     push {r4, lr}; mov r4, r0; b <loop>; mov.w r0, #0x3E8; bl <tick>;
#     subs; sub.w; bne <loop>; pop {r4, pc}
# so delay_ms(n) waits n * delay_us(1000).
MS_DELAY_HEAD = bytes([0x10, 0xB5, 0x04, 0x46, 0x03, 0xE0,
                       0x4F, 0xF4, 0x7A, 0x70])

# LCD controller init waits (ms) and their trimmed replacements.
# MIPI DCS requires >=120 ms after reset and >=120 ms after SLPOUT;
# stock uses a conservative 200/200. Trimmed values keep spec compliance.
LCD_WAIT_ORIG = (100, 100, 200)
LCD_WAIT_PATCH = (70, 70, 120)


def _bl_target(payload, addr):
    """Decode a 32-bit Thumb BL at ARM address addr; None if not a BL."""
    import ctypes
    off = addr - 0x08005000
    h1 = struct.unpack_from("<H", payload, off)[0]
    h2 = struct.unpack_from("<H", payload, off + 2)[0]
    if (h1 >> 11) != 0b11110:
        return None
    if (h2 & 0xF000) != 0xF000 or not (h2 & 0x1000):
        return None
    s = (h1 >> 10) & 1
    j1 = (h2 >> 13) & 1
    j2 = (h2 >> 11) & 1
    v = (s << 24) | ((~(j1 ^ s) & 1) << 23) | ((~(j2 ^ s) & 1) << 22) \
        | ((h1 & 0x3FF) << 12) | ((h2 & 0x7FF) << 1)
    v = ctypes.c_int32((v << 7) & 0xFFFFFFFF).value >> 7
    return (addr + 4 + v) & 0xFFFFFFFF


def find_ms_delay(payload):
    """Find the payload offset of the delay_ms() routine.

    Anchored on the LCD init SLPOUT wait: the unique sequence
        movs r0, #0x11; bl <cmd>; movs r0, #0xC8; bl <delay>;
        ...; movs r0, #0x29
    The delay callee is verified by its distinctive head bytes.
    Returns the payload offset, or None.
    """
    raw = bytes(payload)
    start = 0
    while True:
        idx = raw.find(bytes([0x11, 0x20]), start)  # movs r0, #0x11
        if idx < 0:
            return None
        # Expect: movs(2) bl32(4) movs(2) bl32(4), then 0x29 0x20 nearby.
        # The middle movs holds the SLPOUT wait (200 stock, 120 patched).
        if idx + 12 <= len(raw) and raw[idx + 6] in (0xC8, 0x78) \
                and raw[idx + 7] == 0x20 \
                and bytes([0x29, 0x20]) in raw[idx:idx + 16]:
            h1 = struct.unpack_from("<H", payload, idx + 2)[0]
            h1b = struct.unpack_from("<H", payload, idx + 8)[0]
            if (h1 >> 11) == 0b11110 and (h1b >> 11) == 0b11110:
                target = _bl_target(payload, 0x08005000 + idx + 8)
                if target is not None:
                    doff = target - 0x08005000
                    if 0 <= doff < len(payload) - len(MS_DELAY_HEAD) \
                            and raw[doff:doff + len(MS_DELAY_HEAD)] == MS_DELAY_HEAD:
                        return doff
        start = idx + 1


def find_lcd_waits(payload, patched=False):
    """Find the three LCD-init wait arguments (movs r0, #imm before BL delay).

    Unpatched: two adjacent `movs r0, #100` (post-reset settle) plus the
    single `movs r0, #200` inside the SLPOUT(0x11)..DISPON(0x29) cluster.
    Patched: same sites with 70/70/120. Other delay_ms() callers (beep,
    task pacing, touch init) use different values and are never matched.

    Returns [(movs_offset, imm)] x3 in code order, or None.
    """
    delay_off = find_ms_delay(payload)
    if delay_off is None:
        return None
    delay_addr = 0x08005000 + delay_off
    want = LCD_WAIT_PATCH if patched else LCD_WAIT_ORIG

    # Collect every (bl_addr, imm) calling delay_ms via `movs r0, #imm`.
    callers = []
    for off in range(0, len(payload) - 2, 2):
        if (struct.unpack_from("<H", payload, off)[0] >> 11) != 0b11110:
            continue
        h2 = struct.unpack_from("<H", payload, off + 2)[0]
        if (h2 & 0xF000) != 0xF000 or not (h2 & 0x1000):
            continue
        if _bl_target(payload, 0x08005000 + off) != delay_addr:
            continue
        h = struct.unpack_from("<H", payload, off - 2)[0]
        imm = h & 0xFF if (h & 0xFF00) == 0x2000 else None
        callers.append((off - 2, imm))  # movs offset, imm

    by_addr = dict(callers)
    # Site C: the unique caller with the wanted 3rd value inside the
    # SLPOUT..DISPON cluster (anchor-verified).
    site_c = None
    raw = bytes(payload)
    start = 0
    while True:
        idx = raw.find(bytes([0x11, 0x20]), start)
        if idx < 0:
            break
        cand = idx + 6  # movs offset of the wait inside the cluster
        if by_addr.get(cand) == want[2] \
                and bytes([0x29, 0x20]) in raw[idx:idx + 16]:
            site_c = cand
            break
        start = idx + 1
    if site_c is None:
        return None
    # Sites A/B: the unique adjacent pair with the wanted 1st/2nd values.
    sites_ab = None
    addrs = sorted(by_addr)
    for a, b in zip(addrs, addrs[1:]):
        if b - a == 6 and by_addr[a] == want[0] and by_addr[b] == want[1]:
            if sites_ab is not None:  # ambiguous - refuse to patch
                return None
            sites_ab = (a, b)
    if sites_ab is None:
        return None
    return [(sites_ab[0], want[0]), (sites_ab[1], want[1]), (site_c, want[2])]


def main():
    parser = argparse.ArgumentParser(
        description="Alientek T90 firmware analysis and patching tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
    info    Print firmware header and vector table information
    extract Strip header and decrypt firmware payload to .bin file
    patch   Apply patches (default: all; --only to select)

The firmware uses simple XOR 0xFF obfuscation on the payload bytes.
Image base: 0x08005000 (Cortex-M4F)
""",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Info command
    parser_info = subparsers.add_parser("info", help="Print firmware information")
    parser_info.add_argument("file", help="Input .atk firmware file")

    # Extract command
    parser_extract = subparsers.add_parser(
        "extract", help="Extract and decrypt firmware payload to .bin"
    )
    parser_extract.add_argument("file", help="Input .atk firmware file")
    parser_extract.add_argument("output", nargs="?", help="Output .bin file (optional)")

    # Patch command
    parser_patch = subparsers.add_parser(
        "patch", help="Apply patches (default: all)"
    )
    parser_patch.add_argument("file", help="Input .atk firmware file")
    parser_patch.add_argument("output", nargs="?", help="Output .atk file (optional)")
    parser_patch.add_argument(
        "--only", action="append", choices=("nolie", "nologo", "fastlcd"),
        default=None, metavar="PATCH",
        help="Apply only the selected patch; repeat for several "
             "(default: all three)",
    )

    args = parser.parse_args()

    if args.command == "info":
        return cmd_info(args)
    elif args.command == "extract":
        return cmd_extract(args)
    elif args.command == "patch":
        return cmd_patch(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
