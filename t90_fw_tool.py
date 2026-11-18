#!/usr/bin/env python3
"""
t90_fw_tool.py - Alientek T90 firmware analysis and patching tool

Usage:
    t90_fw_tool.py info <file.atk>          # Print firmware header information
    t90_fw_tool.py extract <file.atk> [out.bin]  # Strip header, decrypt to .bin
    t90_fw_tool.py patch [--only ... | --skip ...] <file.atk> [out.atk]
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

Menu item 16 "Ver Info" shows the model variant and firmware version.
Any patch run also stamps a one-letter-per-patch designation onto that
line (N=nolie, L=nologo, F=fastlcd, E=earlykey, P=fastpd, S=fastsettle,
'-'=absent), e.g. 'T90A1.1.4NLFEPS' fully patched, 'T90A1.1.4NLFEP-'
default; stock firmware keeps the vendor string. The stamp reuses
padding bytes inside the existing string footprint, so no address moves.

The "fastpd" patch shortens the CH224Q PD-settle pre-wait (100x20 ms
passes -> 5 passes), saving ~1.9 s of blank-screen time with a dead
button at boot. Only the dead wait before the first charger detect is
trimmed; the 31/41-sample stability settle that protects the PD
voltage-profile request is left intact, and a wrong early request
self-corrects on the next heater-path re-evaluation. Present only on
firmwares with the pre-wait counter (v1.1.6); older versions settle
without it, so the patch reports "not applicable" there and skips.

The "fastsettle" patch trims the CH224Q PD-settle stability thresholds
(31/41 consecutive stable reads -> 17/22), saving ~300 ms of
blank-screen time with a dead button at boot. Unlike the dead pre-wait,
the settle debounces the charger link before the voltage-profile
request, so this patch stays opt-in (--only fastsettle) until
hardware-validated on several chargers. Present on all versions with
the same shape (v1.1.4/v1.1.5/v1.1.6). Both thresholds are tunable via
--fastsettle MS,MS (0..600 ms each, rounded to the 20 ms charger tick;
0 disables the debounce); --fastlcd MS,MS tunes the LCD post-reset and
SLPOUT waits (below-MIPI values warn but are applied). A parameter flag
implies its patch; custom values show as `custom` in `info`.

The "earlykey" patch captures keypresses during boot waits: all
delay_ms() callers are redirected to a polling-delay routine in an
empty flash cave (ARM 0x08006040) that samples the key-scan routine
every 8th ms with unchanged timing. So a heater start press made
during LCD init is acted on as soon as the main loop starts. Applied
by default since retesting (an apparent T90B heat-up regression was
traced to a Type-C connection issue, not the patch); use --skip earlykey
to opt out.

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

    lcd_sites = read_lcd_waits(payload)
    if lcd_sites is not None:
        vals = ", ".join(f"{v} ms" for _, v in lcd_sites)
        cur = [v for _, v in lcd_sites]
        if cur == list(LCD_WAIT_ORIG):
            print(f"  fastlcd:  not patched (LCD waits: {vals})")
        elif cur == list(LCD_WAIT_PATCH):
            print(f"  fastlcd:  already patched (LCD waits: {vals})")
        else:
            print(f"  fastlcd:  custom (LCD waits: {vals})")
    else:
        print(f"  fastlcd:  unknown (LCD init wait pattern not found - "
              f"unsupported firmware version?)")

    pd_state, pd_off = find_pd_prewait(payload)
    if pd_state == "stock":
        print(f"  fastpd:   not patched (PD pre-wait {PD_PREWAIT_ORIG} passes "
              f"({PD_PREWAIT_ORIG * 20} ms) at payload "
              f"offset 0x{pd_off:05X}, ARM 0x{0x08005000 + pd_off:08X})")
    elif pd_state == "patched":
        print(f"  fastpd:   already patched (PD pre-wait {PD_PREWAIT_NEW} "
              f"passes ({PD_PREWAIT_NEW * 20} ms) "
              f"at payload offset 0x{pd_off:05X})")
    elif pd_state == "absent":
        if find_pd_task(payload):
            print(f"  fastpd:   not applicable (no PD pre-wait counter in "
                  f"this firmware version)")
        else:
            print(f"  fastpd:   unknown (PD settle task pattern not found - "
                  f"unsupported firmware version?)")
    else:
        print(f"  fastpd:   unknown (ambiguous PD pre-wait pattern - "
              f"unsupported firmware version?)")

    st_state, st_offs = find_pd_settle(payload)
    if st_state == "stock":
        o = ", ".join(f"0x{off:05X}" for off in st_offs)
        print(f"  fastsettle: not patched (PD settle 31/41 passes "
              f"(620/820 ms) at payload offsets {o})")
    elif st_state in ("patched", "custom"):
        sites = read_pd_settle(payload)
        imms = sites[1]
        passes = f"{imms[0] + 1}/{imms[1] + 1}"
        ms = f"{(imms[0] + 1) * 20}/{(imms[1] + 1) * 20} ms"
        if st_state == "patched":
            print(f"  fastsettle: already patched (PD settle "
                  f"{passes} passes ({ms}))")
        else:
            print(f"  fastsettle: custom (PD settle {passes} passes ({ms}))")
    elif st_state == "absent":
        print(f"  fastsettle: unknown (PD settle pattern not found - "
              f"unsupported firmware version?)")
    else:
        print(f"  fastsettle: unknown (ambiguous PD settle pattern - "
              f"unsupported firmware version?)")

    ver_off = find_ver_info(payload)
    if ver_off is not None:
        letters = ver_info_letters(payload, ver_off)
        shown = letters if letters is not None else "(none)"
        print(f"  verinfo:  '{shown}' on the Ver Info screen "
              f"(menu 16, payload offset 0x{ver_off:05X})")
    else:
        print(f"  verinfo:  unknown (Ver Info string pattern not found - "
              f"unsupported firmware version?)")

    ek, cave_off, _, keyscan_off = find_earlykey(payload)
    if ek == "clean":
        print(f"  earlykey: not patched (key-scan at payload offset "
              f"0x{keyscan_off:05X}, ARM 0x{0x08005000 + keyscan_off:08X})")
    elif ek == "patched":
        print(f"  earlykey: already patched (polling delay at ARM "
              f"0x{0x08005000 + cave_off:08X})")
    else:
        print(f"  earlykey: unknown (delay caller pattern not found - "
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

    # Determine output file name. A user-supplied name is used verbatim;
    # only auto-generated names get the firmware version inserted.
    if args.output:
        output_file = args.output
    else:
        if args.file.endswith(".atk"):
            output_file = args.file[:-4] + ".bin"
        else:
            output_file = args.file + ".bin"
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
    """Apply the selected patches (default: nolie + nologo + fastlcd + earlykey + fastpd).

    fastsettle is opt-in only (--only ...): it trims a guard that
    debounces the charger link and awaits hardware validation. It is
    never applied by default.
    """
    if args.only:
        selected = {p for group in args.only for p in group}
    elif args.skip:
        selected = set(DEFAULT_PATCHES) - {p for group in args.skip for p in group}
    else:
        selected = set(DEFAULT_PATCHES)
    # A parameter flag implies selecting its patch; combining it with
    # --skip of the same patch is a contradiction - fail closed.
    skipped = {p for group in (args.skip or []) for p in group}
    for flag, name in ((args.fastsettle, "fastsettle"),
                       (args.fastlcd, "fastlcd")):
        if flag is not None:
            if name in skipped:
                print(f"Error: --{name} MS,MS conflicts with --skip {name}.",
                      file=sys.stderr)
                return 1
            selected.add(name)
    do_nolie = "nolie" in selected
    do_nologo = "nologo" in selected
    do_fastlcd = "fastlcd" in selected
    do_earlykey = "earlykey" in selected
    do_fastpd = "fastpd" in selected
    do_fastsettle = "fastsettle" in selected

    # Resolve tunable targets (defaults when the flag is absent).
    # fastsettle thresholds are charger-task ticks (20 ms each); non-
    # multiples of 20 round to the nearest tick, half-up.
    if args.fastsettle is not None:
        raw = args.fastsettle
        rounded = (round20(raw[0]), round20(raw[1]))
        if rounded != tuple(raw):
            print(f"Note: --fastsettle {raw[0]},{raw[1]} ms rounded to "
                  f"{rounded[0]},{rounded[1]} ms (20 ms tick).")
        settle_new = tuple(settle_ms_to_imm(m) for m in rounded)
        settle_ms = rounded
    else:
        settle_new = PD_SETTLE_NEW
        settle_ms = tuple((imm + 1) * 20 for imm in PD_SETTLE_NEW)
    if args.fastlcd is not None:
        reset_ms, slpout_ms = args.fastlcd
        if reset_ms < LCD_WAIT_PATCH[0]:
            print(f"Warning: post-reset {reset_ms} ms is below the "
                  f"default {LCD_WAIT_PATCH[0]} ms (MIPI DCS needs 120 ms "
                  f"after reset; the panel may fail to init).")
        if slpout_ms < LCD_WAIT_PATCH[2]:
            print(f"Warning: SLPOUT {slpout_ms} ms is below the "
                  f"default {LCD_WAIT_PATCH[2]} ms (MIPI DCS needs 120 ms "
                  f"after SLPOUT; the panel may fail to init).")
        lcd_new = (reset_ms, reset_ms, slpout_ms)
    else:
        lcd_new = LCD_WAIT_PATCH

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

    # Patches already present in the input stay in the output, so the
    # output name must reflect them too - not just the requested ones.
    already = set()
    if find_function_location(payload, instruction=THUMB_NOP) is not None:
        already.add("nolie")
    if find_logo_anim_patch(payload) is not None:
        already.add("nologo")
    lcd_sites = read_lcd_waits(payload)
    if lcd_sites is not None \
            and [v for _, v in lcd_sites] != list(LCD_WAIT_ORIG):
        already.add("fastlcd")
    if find_earlykey(payload)[0] == "patched":
        already.add("earlykey")
    if find_pd_prewait(payload)[0] == "patched":
        already.add("fastpd")
    if find_pd_settle(payload)[0] in ("patched", "custom"):
        already.add("fastsettle")
    # fastpd exists only where the PD pre-wait counter exists (v1.1.6);
    # older firmwares settle without it, so there is nothing to shorten.
    na = set()
    if "fastpd" in selected and find_pd_prewait(payload)[0] == "absent" \
            and find_pd_task(payload):
        na.add("fastpd")
    effective = (selected - na) | already

    new_payload = bytearray(payload)

    if do_nolie:
        # Find the patch location
        patch_offset = find_function_location(new_payload, instruction=None)

        if patch_offset is None:
            if find_function_location(new_payload, instruction=THUMB_NOP) is not None:
                print(f"Nolie patch already applied (NOP present).")
            else:
                print("Error: Could not find the 'lie' patch location in firmware.", file=sys.stderr)
                print("  The function signature pattern was not found.", file=sys.stderr)
                print("  This may be a different firmware version or already patched.", file=sys.stderr)
                return 1
        else:
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

            # Apply patch: BNE -> NOP
            struct.pack_into("<H", new_payload, patch_offset, THUMB_NOP)

            print(f"  New instruction: 0x{THUMB_NOP:04X} (NOP)")
            print(f"  This removes the 'lie' temperature display compensation")

    if do_nologo:
        # Apply logo animation skip: mvn.w r4, #0x26 -> movs r4, #2; nop
        anim_off = find_logo_anim(new_payload)
        if anim_off is None:
            if find_logo_anim_patch(new_payload) is not None:
                print(f"Logo animation already applied (patch present).")
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
        # Shorten LCD controller init waits (default 100,100,200 ms ->
        # 70,70,120 ms, or the --fastlcd MS,MS tune). The sites are
        # located regardless of their current values, so re-tuning a
        # custom-patched image rewrites them in place.
        sites = read_lcd_waits(new_payload)
        if sites is None:
            print("Error: LCD init wait pattern not found.", file=sys.stderr)
            print("  Unsupported firmware version?", file=sys.stderr)
            return 1
        cur = [v for _, v in sites]
        if cur == list(lcd_new):
            print(f"LCD waits already at {list(lcd_new)} ms (patch present).")
        else:
            for (movs_off, old), new in zip(sites, lcd_new):
                arm = 0x08005000 + movs_off
                print(f"LCD wait at payload offset 0x{movs_off:05X} "
                      f"(ARM 0x{arm:08X}): movs r0, #{old} -> movs r0, #{new}")
                struct.pack_into("<H", new_payload, movs_off, 0x2000 | new)
            print(f"  Patched to: LCD waits {list(lcd_new)} ms "
                  f"(saves ~{sum(LCD_WAIT_ORIG) - sum(lcd_new)} ms of boot time)")

    if do_earlykey:
        # Redirect all delay_ms() callers to a polling delay in the cave:
        # same timing, but samples the key-scan routine every 8th ms so a
        # keypress during boot waits (LCD init included) is captured and
        # acted on as soon as the main loop starts.
        state, _, delay_off, keyscan_off = find_earlykey(new_payload)
        if state == "patched":
            print(f"Earlykey polling delay already applied (patch present).")
        elif state != "clean":
            print("Error: delay_ms caller pattern not found.", file=sys.stderr)
            print("  Unsupported firmware version?", file=sys.stderr)
            return 1
        else:
            callers, _ = find_delay_callers(new_payload)
            delay_addr = 0x08005000 + delay_off
            keyscan_addr = 0x08005000 + keyscan_off
            cave_off = EARLYKEY_CAVE_ADDR - 0x08005000
            cave = build_earlykey_cave(EARLYKEY_CAVE_ADDR, delay_addr,
                                       keyscan_addr)
            if any(b != 0 for b in new_payload[cave_off:cave_off + len(cave)]):
                print(f"Error: cave at ARM 0x{EARLYKEY_CAVE_ADDR:08X} "
                      f"is not empty - refusing to patch.", file=sys.stderr)
                return 1
            new_payload[cave_off:cave_off + len(cave)] = cave
            for bl_off in callers:
                new_payload[bl_off:bl_off + 4] = _bl_encode(
                    0x08005000 + bl_off, EARLYKEY_CAVE_ADDR)
            print(f"Key-scan routine at payload offset 0x{keyscan_off:05X} "
                  f"(ARM 0x{keyscan_addr:08X})")
            print(f"Polling delay installed at ARM 0x{EARLYKEY_CAVE_ADDR:08X} "
                  f"({len(cave)} bytes); {len(callers)} delay_ms callers "
                  f"redirected (keys sampled every 8th ms of every wait)")

    if do_fastpd:
        # Shorten the dead PD pre-wait: the 100x20 ms counter becomes 5
        # passes (100 ms, still covering the CH224 power-on reset). The
        # 31/41-sample stability settle afterwards is untouched.
        if "fastpd" in na:
            print(f"fastpd: not applicable to this firmware version "
                  f"(no PD pre-wait counter); skipping.")
        else:
            state, cmp_off = find_pd_prewait(new_payload)
            if cmp_off is None:
                print("Error: PD pre-wait counter pattern not found.", file=sys.stderr)
                print("  Unsupported firmware version?", file=sys.stderr)
                return 1
            elif state == "patched":
                print(f"PD pre-wait already shortened (patch present).")
            else:
                arm = 0x08005000 + cmp_off
                print(f"PD pre-wait counter at payload offset 0x{cmp_off:05X} "
                      f"(ARM 0x{arm:08X}): cmp r0, #{PD_PREWAIT_ORIG} "
                      f"-> cmp r0, #{PD_PREWAIT_NEW}")
                struct.pack_into("<H", new_payload, cmp_off,
                                 0x2800 | PD_PREWAIT_NEW)
                print(f"  Patched to: PD pre-wait {PD_PREWAIT_NEW} passes "
                      f"(saves ~{(PD_PREWAIT_ORIG - PD_PREWAIT_NEW) * 20} ms "
                      f"of blank-screen time)")

    if do_fastsettle:
        # Trim the PD stability settle (default 31/41 consecutive stable
        # reads -> 17/22, or the --fastsettle MS,MS tune). The sites are
        # located regardless of their current values, so re-tuning a
        # custom-patched image rewrites them in place. 0 ms disables the
        # debounce: one 20 ms pass still samples the charger.
        sites = read_pd_settle(new_payload)
        if sites is None:
            print("Error: PD settle threshold pattern not found.", file=sys.stderr)
            print("  Unsupported firmware version?", file=sys.stderr)
            return 1
        cmp_offs, cur = sites
        if cur == settle_new:
            print(f"PD settle already at {settle_ms[0]}/{settle_ms[1]} ms "
                  f"({settle_new[0] + 1}/{settle_new[1] + 1} passes, "
                  f"patch present).")
        else:
            for cmp_off, old, new in zip(cmp_offs, cur, settle_new):
                arm = 0x08005000 + cmp_off
                print(f"PD settle threshold at payload offset 0x{cmp_off:05X} "
                      f"(ARM 0x{arm:08X}): cmp r0, #{old} -> cmp r0, #{new}")
                struct.pack_into("<H", new_payload, cmp_off, 0x2800 | new)
            print(f"  Patched to: PD settle {settle_ms[0]}/{settle_ms[1]} ms "
                  f"({settle_new[0] + 1}/{settle_new[1] + 1} passes)")

    if effective:
        # Stamp the designation letters onto the Ver Info screen: the
        # string drops the " V" separator and grows up to 6 letters,
        # all inside the existing footprint.  A stamp from an
        # earlier (subset) run is normalized via the stock spelling, so
        # incremental patching just works.  Fail closed on any mismatch.
        ver_off = find_ver_info(new_payload)
        if ver_off is None:
            print("Error: Ver Info string pattern not found.", file=sys.stderr)
            print("  Unsupported firmware version?", file=sys.stderr)
            return 1
        present = {
            name: ("patched" if name in effective else "stock")
            for name, _ in VER_INFO_LETTERS
        }
        letters = ver_info_expected_letters(**present)
        have = ver_info_letters(new_payload, ver_off)
        if have is None:
            stamped = stamp_ver_info(new_payload, ver_off, letters)
            print(f"Ver Info designation at payload offset 0x{ver_off:05X} "
                  f"(ARM 0x{0x08005000 + ver_off:08X}): '{stamped}'")
        elif have == letters:
            print(f"Ver Info designation already stamped ('{have}').")
        else:
            try:
                unstamp_ver_info(new_payload, ver_off)
                stamped = stamp_ver_info(new_payload, ver_off, letters)
            except ValueError as e:
                print(f"Error: cannot re-stamp Ver Info string: {e}.",
                      file=sys.stderr)
                return 1
            print(f"Ver Info designation updated '{have}' -> '{stamped}' "
                  f"(payload offset 0x{ver_off:05X})")
    # Re-encrypt the payload
    encrypted_payload = xor_decrypt(bytes(new_payload))

    # Build the output file
    output = bytearray(data[:13])  # Keep original header
    output.extend(encrypted_payload)

    if not effective:
        if na:
            print(f"Nothing to patch for this firmware version "
                  f"({', '.join(sorted(na))} not applicable).")
            return 0
        print("Error: no patches selected.", file=sys.stderr)
        return 1
    suffix = ""
    for name in ("nolie", "nologo", "fastlcd", "earlykey", "fastpd",
                 "fastsettle"):
        if name in effective:
            suffix += "_" + name
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
            for old in ("_nolie", "_nologo", "_fastlcd", "_earlykey",
                        "_fastpd", "_fastsettle"):
                if base.endswith(old):
                    base = base[:-len(old)]
                    changed = True
        # Version goes before the suffixes: t90_v1.1.4_nolie_nologo.atk
        output_file = make_versioned_filename(base, version) + suffix + ext
    # else: a user-supplied name is written verbatim (no version inserted)

    with open(output_file, "wb") as f:
        f.write(output)

    print(f"\nPatched firmware written to: {output_file}")
    print(f"  Original size: {len(data)} bytes")
    print(f"  Output size:   {len(output)} bytes")
    if version:
        print(f"  Firmware version: {version}")

    return 0


# Ver Info screen designation (menu item 16, "T90%s  V:%1d.%1d.%1d").
# The string lives in a literal-pool gap: the NUL is followed by up to
# 4 zero bytes before the next pool word, so the stamp extends into
# that padding without moving any address (the single ADR reference is
# PC-relative to the string start).
# Stock spelling keeps the vendor's double space and colon; any patch
# presence drops the " V" separator and appends one letter per patch, so
# the padded area encodes the designation (16-char base + up to 7
# letters + NUL fit the 24-byte window):
# N/L/F/E/P/S = present, - = absent.
VER_INFO_STOCK = "T90%s%1d.%1d.%1d"
VER_INFO_STOCK_RAW = b"T90%s  V:%1d.%1d.%1d\x00"
VER_INFO_LETTERS = (("nolie", "N"), ("nologo", "L"), ("fastlcd", "F"),
                   ("earlykey", "E"), ("fastpd", "P"), ("fastsettle", "S"))
VER_INFO_MAX_LEN = 24  # string + NUL + the 4 free padding bytes
VER_INFO_ADR_RD = 1  # fmt pointer is loaded into r1 (adr r1, #imm)


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


def find_ver_info(payload):
    """Find the Ver Info format string (stock or stamped + letters).

    Locates every candidate of the right shape and keeps only those with
    exactly one PC-relative ADR reference loading the string start, as
    observed on all real firmware versions.  Returns the payload offset
    of the string start, or None.
    """
    raw = bytes(payload)
    cands = []
    start = 0
    while True:
        idx = raw.find(b"T90", start)
        if idx < 0:
            break
        tail = raw[idx:idx + VER_INFO_MAX_LEN + 8]
        m = re.match(rb"T90%s(?: {1,2}V:?)?%1d\.%1d\.%1d([-NLFEPS]{3,8})?\x00", tail)
        if m:
            end = idx + m.end()  # just past the NUL
            # Padded dots up to the next pool word must be zeros, and the
            # word itself nonzero (stock: exactly 4 free bytes).
            pad = end
            while pad < len(raw) and raw[pad] == 0 and pad - end < 4:
                pad += 1
            if pad - end <= 4 and pad + 4 <= len(raw) \
                    and int.from_bytes(raw[pad:pad + 4], "little") != 0:
                cands.append((idx, m.group(1).decode() if m.group(1) else None))
        start = idx + 1

    good = [c for c in cands if _ver_info_refs(payload, c[0]) == 1]
    if len(good) != 1 or len(cands) != 1:
        return None
    return good[0][0]


def _ver_info_refs(payload, string_off):
    """Count halfword-aligned instructions referencing a string address.

    Matches ADR (PC-relative to the string start) and LDR-literal words
    holding the string address, mirroring how the format-string pointer
    reaches the snprintf call.
    """
    refs = 0
    addr = 0x08005000 + string_off
    n = len(payload)
    for off in range(0, n - 1, 2):
        hw = struct.unpack_from("<H", payload, off)[0]
        # ADR Rd, #imm8<<2: target = (Align(PC,4)) + imm.
        if (hw & 0xF800) == 0xA000 and (hw >> 8) & 0x7 == VER_INFO_ADR_RD:
            if ((off + 0x08005000 + 4) & ~3) + (hw & 0xFF) * 4 == addr:
                refs += 1
        # LDR-literal Rd, [PC, #imm8<<2] dereferencing a pool word == addr.
        elif (hw & 0xF800) == 0x4800:
            lit = ((off + 0x08005000 + 4) & ~3) + (hw & 0xFF) * 4
            loff = lit - 0x08005000
            if 0 <= loff + 4 <= n and \
                    struct.unpack_from("<I", payload, loff)[0] == addr:
                refs += 1
    return refs


def ver_info_letters(payload, string_off=None):
    """Read the designation letters stamped on the Ver Info string.

    Returns e.g. 'NLFEPS' (all patched) / '------' (none) / None when
    the string is missing or held no stamp.
    """
    if string_off is None:
        string_off = find_ver_info(payload)
    if string_off is None:
        return None
    tail = bytes(payload[string_off:string_off + VER_INFO_MAX_LEN + 8])
    m = re.match(rb"T90%s(?: {1,2}V:?)?%1d\.%1d\.%1d([-NLFEPS]{3,8})?\x00", tail)
    if not m or not m.group(1):
        return None
    return m.group(1).decode()


def unstamp_ver_info(payload, string_off=None):
    """Restore the vendor spelling of a stamped Ver Info string.

    Rewrites 'T90%s…<letters>' back to 'T90%s␣␣V:…' in place and
    zeroes the padding window, so the result is byte-identical to the
    vendor string.  Accepts legacy stamps (with the " V" separator and
    3-5 letters).  Raises ValueError when the string holds no stamp.
    """
    if string_off is None:
        string_off = find_ver_info(payload)
        if string_off is None:
            raise ValueError("Ver Info string pattern not found")
    tail = bytes(payload[string_off:string_off + VER_INFO_MAX_LEN + 8])
    m = re.match(rb"T90%s(?: {1,2}V:?)?%1d\.%1d\.%1d([-NLFEPS]{3,8})\x00", tail)
    if not m or not m.group(1):
        raise ValueError(f"Ver Info string holds no stamp: {tail[:24]!r}")
    payload[string_off:string_off + len(VER_INFO_STOCK_RAW)] = \
        VER_INFO_STOCK_RAW
    # Clear any leftover stamp bytes (a 4-letter stamp extends 2 bytes
    # past the stock NUL); the window is zero padding on stock firmware.
    pad_end = string_off + VER_INFO_MAX_LEN
    pad_start = string_off + len(VER_INFO_STOCK_RAW)
    payload[pad_start:pad_end] = bytes(pad_end - pad_start)
    return VER_INFO_STOCK_RAW[:-1].decode()


def ver_info_expected_letters(nolie, nologo, fastlcd, earlykey="stock",
                              fastpd="stock", fastsettle="stock"):
    """Designation letters for a patch set ('-' = patch absent)."""
    letters = dict(VER_INFO_LETTERS)
    return "".join(
        letters[patch] if state == "patched" else "-"
        for patch, state in (
            ("nolie", nolie), ("nologo", nologo),
            ("fastlcd", fastlcd), ("earlykey", earlykey),
            ("fastpd", fastpd), ("fastsettle", fastsettle)
        )
    )


def stamp_ver_info(payload, string_off, letters):
    """Stamp the designation letters onto the Ver Info string in place.

    Rewrites 'T90%s␣␣V:…' to 'T90%s…<letters>' inside the existing
    footprint (extends at most into the free padding bytes).  The
    string start never moves, so the ADR reference needs no fixup.
    Returns the stamped string (without NUL).
    """
    old = VER_INFO_STOCK_RAW
    seg = bytes(payload[string_off:string_off + len(old)])
    if seg != old:
        raise ValueError(
            "already stamped or unexpected Ver Info string: "
            f"{seg!r} (expected stock {old!r})"
        )
    stamped = (VER_INFO_STOCK + letters).encode("ascii") + b"\x00"
    assert len(stamped) <= VER_INFO_MAX_LEN, stamped
    payload[string_off:string_off + len(stamped)] = stamped
    return stamped[:-1].decode()


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


def find_ms_delay(payload, any_wait=False):
    """Find the payload offset of the delay_ms() routine.

    Anchored on the LCD init SLPOUT wait: the unique sequence
        movs r0, #0x11; bl <cmd>; movs r0, #<wait>; bl <delay>;
        ...; movs r0, #0x29
    The delay callee is verified by its distinctive head bytes.
    With any_wait=False only the known stock/patched waits (200/120)
    anchor the search; any_wait=True accepts any wait value (needed to
    recognize custom --fastlcd tunes). Returns the payload offset, or None.
    """
    raw = bytes(payload)
    start = 0
    while True:
        idx = raw.find(bytes([0x11, 0x20]), start)  # movs r0, #0x11
        if idx < 0:
            return None
        # Expect: movs(2) bl32(4) movs(2) bl32(4), then 0x29 0x20 nearby.
        # The middle movs holds the SLPOUT wait (200 stock, 120 patched,
        # arbitrary with a custom --fastlcd tune).
        if idx + 12 <= len(raw) and raw[idx + 7] == 0x20 \
                and (any_wait or raw[idx + 6] in (0xC8, 0x78)) \
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
                    # Maybe redirected through an earlykey polling-delay
                    # cave: resolve its inner BL to the real delay_ms.
                    inner_off, _ = _validate_cave(payload, target)
                    if inner_off is not None:
                        return inner_off
        start = idx + 1


def read_lcd_waits(payload):
    """Find the three LCD-init wait arguments regardless of value.

    Sites: two adjacent `movs r0, #imm` (post-reset settle) plus the
    single `movs r0, #imm` inside the SLPOUT(0x11)..DISPON(0x29) cluster.
    Other delay_ms() callers (beep, task pacing, touch init) are never
    adjacent pairs, so exactly one pair exists on known firmwares.

    Returns [(movs_offset, imm)] x3 in code order, or None when the
    sites are missing or ambiguous (fail closed, do not patch).
    """
    delay_off = find_ms_delay(payload, any_wait=True)
    if delay_off is None:
        return None
    delay_addr = 0x08005000 + delay_off

    # Collect every (bl_addr, imm) calling delay_ms via `movs r0, #imm`
    # (directly, or through an earlykey polling-delay cave).
    callers = []
    for off in range(2, len(payload) - 2, 2):
        if (struct.unpack_from("<H", payload, off)[0] >> 11) != 0b11110:
            continue
        h2 = struct.unpack_from("<H", payload, off + 2)[0]
        if (h2 & 0xF000) != 0xF000 or not (h2 & 0x1000):
            continue
        if not _is_delay_caller(payload, off, delay_addr):
            continue
        h = struct.unpack_from("<H", payload, off - 2)[0]
        imm = h & 0xFF if (h & 0xFF00) == 0x2000 else None
        callers.append((off - 2, imm))  # movs offset, imm

    by_addr = dict(callers)
    # Site C: the unique delay caller inside the SLPOUT..DISPON cluster.
    site_c = None
    raw = bytes(payload)
    start = 0
    while True:
        idx = raw.find(bytes([0x11, 0x20]), start)
        if idx < 0:
            break
        cand = idx + 6  # movs offset of the wait inside the cluster
        if cand in by_addr \
                and bytes([0x29, 0x20]) in raw[idx:idx + 16]:
            if site_c is not None:  # ambiguous - refuse to patch
                return None
            site_c = cand
        start = idx + 1
    if site_c is None:
        return None
    # Sites A/B: the unique adjacent pair with a shared value (the two
    # post-reset sites always carry one value: stock 100/100, default
    # 70/70, or the single reset value of a custom --fastlcd tune).
    # Other adjacent delay callers (decoys, beep/pacing sequences) use
    # differing values and never match.
    sites_ab = None
    addrs = sorted(a for a in by_addr if a != site_c)
    for a, b in zip(addrs, addrs[1:]):
        if b - a == 6 and by_addr[a] is not None \
                and by_addr[a] == by_addr[b]:
            if sites_ab is not None:  # ambiguous - refuse to patch
                return None
            sites_ab = (a, b)
    if sites_ab is None:
        return None
    return [(sites_ab[0], by_addr[sites_ab[0]]),
            (sites_ab[1], by_addr[sites_ab[1]]),
            (site_c, by_addr[site_c])]


def find_lcd_waits(payload, patched=False):
    """Find the three LCD-init wait arguments (movs r0, #imm before BL delay).

    Unpatched: two adjacent `movs r0, #100` (post-reset settle) plus the
    single `movs r0, #200` inside the SLPOUT(0x11)..DISPON(0x29) cluster.
    Patched: same sites with 70/70/120. Other delay_ms() callers (beep,
    task pacing, touch init) use different values and are never matched.

    Returns [(movs_offset, imm)] x3 in code order, or None (missing,
    ambiguous, or held values other than the wanted set).
    """
    sites = read_lcd_waits(payload)
    if sites is None:
        return None
    want = LCD_WAIT_PATCH if patched else LCD_WAIT_ORIG
    if [v for _, v in sites] == list(want):
        return sites
    return None


def _bl_encode(src_addr, tgt_addr):
    """Encode a 32-bit Thumb BL from src_addr to tgt_addr (4 bytes)."""
    off = tgt_addr - src_addr - 4
    if not (-(1 << 23) <= off < (1 << 23)) or off % 2:
        raise ValueError(f"BL target out of range: {tgt_addr:#x} from {src_addr:#x}")
    s = (off >> 24) & 1
    i1 = (off >> 23) & 1
    i2 = (off >> 22) & 1
    j1 = 1 ^ (i1 ^ s)
    j2 = 1 ^ (i2 ^ s)
    h1 = (0b11110 << 11) | (s << 10) | ((off >> 12) & 0x3FF)
    h2 = (0b11111 << 11) | (j1 << 13) | (1 << 12) | (j2 << 11) | ((off >> 1) & 0x7FF)
    return struct.pack("<HH", h1, h2)


# Key-scan routine locator: the function containing `mov.w r1, #0x8000`
# (4FF40041, unique image-wide in v1.1.4/v1.1.5/v1.1.6). It polls the two
# key/encoder pins (GPIOA-15, GPIOC-4) and raises the key flag consumed by
# the heater control logic. Entry = the PUSH right before the anchor.
KEYSCAN_ANCHOR = bytes([0x4F, 0xF4, 0x00, 0x41])  # mov.w r1, #0x8000
KEYSCAN_PROBE = bytes([0x10, 0x21])              # movs r1, #0x10 (same func)

# Cave for the earlykey polling delay: 296 zero bytes at ARM 0x08006040
# (payload 0x1040) in all three firmware versions. Verified empty, no xrefs.
EARLYKEY_CAVE_ADDR = 0x08006040
RCC_APB2ENR = 0x40021018
EARLYKEY_POLL_DIV = 8  # poll keys every 8th ms slice


def find_keyscan(payload):
    """Find the payload offset of the key-scan routine, or None.

    Anchor: unique `mov.w r1, #0x8000`; entry is the PUSH just before it.
    The candidate is accepted only if `movs r1, #0x10` follows within the
    same function (the second key pin mask).
    """
    raw = bytes(payload)
    idx = raw.find(KEYSCAN_ANCHOR)
    if idx < 0 or raw.find(KEYSCAN_ANCHOR, idx + 1) >= 0:
        return None  # missing or ambiguous - refuse to patch
    # Walk back to the function entry PUSH (0xB5xx), at most 16 bytes.
    entry = None
    for back in range(2, 18, 2):
        h = struct.unpack_from("<H", payload, idx - back)[0]
        if (h & 0xFF00) == 0xB500:
            entry = idx - back
            break
        if (h & 0xFF00) not in (0x2000, 0x2100, 0x2200, 0x2300, 0x2400,
                                0x2500, 0x2600, 0x2700, 0x4600):
            return None  # unexpected prologue shape - refuse
    if entry is None:
        return None
    if KEYSCAN_PROBE not in raw[entry:entry + 0x120]:
        return None
    return entry


def _validate_cave(payload, cave_addr):
    """Check for a valid earlykey polling-delay cave at cave_addr.

    Returns (delay_off, keyscan_off), or (None, None) if the bytes do
    not decode as a cave built by build_earlykey_cave.
    """
    keyscan_off = find_keyscan(payload)
    if keyscan_off is None:
        return None, None
    if not (0x08005000 + 64 <= cave_addr < 0x08005000 + len(payload) - 64):
        return None, None
    # First BL of the cave sits at slot 11 (see build_earlykey_cave).
    inner = _bl_target(payload, cave_addr + 22)
    if inner is None:
        return None, None
    delay_off = inner - 0x08005000
    raw = bytes(payload)
    if not (0 <= delay_off < len(payload) - len(MS_DELAY_HEAD)):
        return None, None
    if raw[delay_off:delay_off + len(MS_DELAY_HEAD)] != MS_DELAY_HEAD:
        return None, None
    try:
        expect = build_earlykey_cave(cave_addr, inner,
                                     0x08005000 + keyscan_off)
    except ValueError:
        return None, None
    cave_off = cave_addr - 0x08005000
    if not (0 <= cave_off < len(payload) - len(expect)):
        return None, None
    if raw[cave_off:cave_off + len(expect)] != expect:
        return None, None
    return delay_off, keyscan_off


def _is_delay_caller(payload, bl_off, delay_addr):
    """True if the BL at bl_off waits via delay_ms (directly or via cave)."""
    t = _bl_target(payload, 0x08005000 + bl_off)
    if t == delay_addr:
        return True
    if t is None:
        return False
    inner_off, _ = _validate_cave(payload, t)
    return inner_off is not None and 0x08005000 + inner_off == delay_addr


def find_delay_callers(payload):
    """Find all BL sites calling delay_ms(). Returns ([bl_offsets], delay_off)."""
    # any_wait: the SLPOUT anchor may hold a custom --fastlcd value.
    delay_off = find_ms_delay(payload, any_wait=True)
    if delay_off is None:
        return None, None
    delay_addr = 0x08005000 + delay_off
    keyscan_off = find_keyscan(payload)
    keyscan_addr = 0x08005000 + keyscan_off if keyscan_off is not None else None
    callers = []
    for off in range(0, len(payload) - 4, 2):
        if (struct.unpack_from("<H", payload, off)[0] >> 11) != 0b11110:
            continue
        h2 = struct.unpack_from("<H", payload, off + 2)[0]
        if (h2 & 0xF000) != 0xF000 or not (h2 & 0x1000):
            continue
        if _is_delay_caller(payload, off, delay_addr):
            callers.append(off)
    # Drop the cave's own inner BLs: they sit inside a validated cave and
    # are part of the patch, not original delay_ms call sites.
    spans = []
    for t in {_bl_target(payload, 0x08005000 + o) for o in callers}:
        if t is None:
            continue
        inner_off, ks_off = _validate_cave(payload, t)
        if inner_off is not None:
            ln = len(build_earlykey_cave(t, 0x08005000 + inner_off,
                                        0x08005000 + ks_off))
            spans.append((t - 0x08005000, t - 0x08005000 + ln))
    callers = [o for o in callers
               if not any(s <= o < e for s, e in spans)]
    return callers, delay_off


def build_earlykey_cave(cave_addr, delay_addr, keyscan_addr):
    """Build the polling-delay routine placed at cave_addr.

    Same ABI as delay_ms(n): waits n ms in 1 ms slices (via the original
    delay_ms), enables the GPIO port clocks idempotently, and polls the
    key-scan routine every EARLYKEY_POLL_DIV slices so a keypress during
    any boot wait (LCD init included) is captured for the control loop.
    Clobbers r0-r3 only (like any BL callee); preserves r4-r5.
    """
    # Item list: ("h", halfword) | ("bl", target) | ("br", cond, label).
    # Labels mark halfword-slot positions resolved at emit time.
    items = [
        ("h", 0xB530),          # push {r4,r5,lr}
        ("h", 0x4B00),          # ldr r3, [pc, #lit] (imm patched below)
        ("h", 0x681A),          # ldr r2, [r3]
        ("h", 0x2114),          # movs r1, #0x14 (IOPA|IOPC)
        ("h", 0x430A),          # orrs r2, r1
        ("h", 0x601A),          # str r2, [r3]
        ("h", 0x4604),          # mov r4, r0
        ("h", 0x2500),          # movs r5, #0
        ("h", 0x2C00),          # cmp r4, #0
        ("br", 0xD000, "done"),  # beq done
        ("label", "loop"),
        ("h", 0x2001),          # movs r0, #1
        ("bl", delay_addr),     # bl delay_ms
        ("h", 0x3501),          # adds r5, #1
        ("h", 0x2D08),          # cmp r5, #8
        ("br", 0xDB00, "skip"),  # blt skip
        ("h", 0x2500),          # movs r5, #0
        ("bl", keyscan_addr),   # bl keyscan
        ("label", "skip"),
        ("h", 0x3C01),          # subs r4, #1
        ("br", 0xD100, "loop"),  # bne loop
        ("label", "done"),
        ("h", 0xBD30),          # pop {r4,r5,pc}
    ]
    # Assign halfword slots (a "bl" takes two).
    labels = {}
    slot_of_item = []
    slot = 0
    for it in items:
        if it[0] == "label":
            labels[it[1]] = slot
            slot_of_item.append(None)
        elif it[0] == "bl":
            slot_of_item.append(slot)
            slot += 2
        else:
            slot_of_item.append(slot)
            slot += 1
    nslots = slot
    lit_slot = nslots + (1 if (cave_addr + nslots * 2) % 4 else 0)
    code_addr = lambda s: cave_addr + s * 2  # slot -> ARM addr

    def br8(insn_addr, target_addr):
        rel = target_addr - (insn_addr + 4)
        if rel % 2 or not (-256 <= rel < 256):
            raise ValueError("branch out of range")
        return rel // 2 & 0xFF

    blob = bytearray()
    for it, sl in zip(items, slot_of_item):
        if it[0] == "label":
            continue
        if it[0] == "bl":
            blob += _bl_encode(code_addr(sl), it[1])
        elif it[0] == "br":
            blob += struct.pack("<H", it[1] | br8(code_addr(sl),
                                                  code_addr(labels[it[2]])))
        else:  # ("h", halfword); patch the LDR literal imm (slot 1)
            h = it[1]
            if sl == 1:
                aligned = (code_addr(1) + 4) // 4 * 4  # Align(PC, 4), round down
                lit_addr = cave_addr + lit_slot * 2
                if (lit_addr - aligned) % 4:
                    raise ValueError("literal misaligned")
                lit_imm = (lit_addr - aligned) // 4
                if not (0 <= lit_imm < 256):
                    raise ValueError("literal out of range")
                h |= lit_imm
            blob += struct.pack("<H", h)
    while len(blob) < lit_slot * 2:
        blob += struct.pack("<H", 0xBF00)  # NOP pad
    blob += struct.pack("<I", RCC_APB2ENR)
    assert len(blob) == lit_slot * 2 + 4
    return bytes(blob)


def find_earlykey(payload):
    """Check the earlykey patch state.

    Returns (state, cave_off, delay_off, keyscan_off) where state is one of:
      'clean'   - all delay_ms callers intact (patch not applied)
      'patched' - all callers target a valid polling-delay cave
      None      - pattern not recognized (unsupported firmware / mixed state)
    """
    callers, delay_off = find_delay_callers(payload)
    if not callers:
        return None, None, None, None
    keyscan_off = find_keyscan(payload)
    if keyscan_off is None:
        return None, None, None, None
    delay_addr = 0x08005000 + delay_off
    keyscan_addr = 0x08005000 + keyscan_off
    targets = {_bl_target(payload, 0x08005000 + o) for o in callers}
    if len(targets) == 1 and next(iter(targets)) == delay_addr:
        return "clean", None, delay_off, keyscan_off
    if len(targets) == 1:
        cave_addr = next(iter(targets))
        cave_off = cave_addr - 0x08005000
        if 0 <= cave_off < len(payload) - 64:
            expect = build_earlykey_cave(cave_addr, delay_addr, keyscan_addr)
            if bytes(payload[cave_off:cave_off + len(expect)]) == expect:
                # All call sites must point at this exact cave.
                if all(_bl_target(payload, 0x08005000 + o) == cave_addr
                       for o in callers):
                    return "patched", cave_off, delay_off, keyscan_off
    return None, None, None, None


# Patch names selectable via --only (comma-separated, in one flag).
PATCH_NAMES = ("nolie", "nologo", "fastlcd", "earlykey", "fastpd",
               "fastsettle")
# Patches applied by default. fastsettle is excluded: it trims the
# charger debounce guard and awaits validation on several chargers, so
# it stays opt-in via --only until hardware-validated. Detectors still
# recognize already-patched images.
# fastpd IS default: it trims only dead waiting (no code redirection),
# keeps the voltage-stability settle, and self-corrects on re-evaluation.
# earlykey IS default: retesting showed no degradation (the earlier T90B
# heat-up reboots were a Type-C connection issue, not the patch).
DEFAULT_PATCHES = ("nolie", "nologo", "fastlcd", "earlykey", "fastpd")


# CH224Q PD-settle pre-wait: the 20 ms charger task counts passes before
# its first detect (v1.1.6: 100 passes = 2.0 s of blank screen with a
# dead button), then needs 31/41 consecutive stable reads. Shape:
#     ldr r0, [pc, #imm]; ldrh r0, [r0]; adds r0, #1; uxth r0, r0;
#     ldr r1, [pc, #imm]; strh r0, [r1]; cmp r0, #<passes>; bge <on>;
#     [b <return>;] movs r0, #0; ldr r1, [pc, #imm]; strh r0, [r1]
# Only the cmp immediate is patched (100 -> 5 passes = 100 ms, still
# covering the CH224 power-on reset). v1.1.4/v1.1.5 have no such counter
# (their task settles the link directly), so the finder reports "absent"
# there and the patch skips instead of failing.
PD_PREWAIT_ORIG = 100
PD_PREWAIT_NEW = 5
# movw r0, #0x1388 (5000 mV profile label): marks the PD settle task's
# presence even where the pre-wait counter is absent.
PD_TASK_ANCHOR = bytes([0x41, 0xF2, 0x88, 0x30])


def _pd_prewait_offsets(payload, imm):
    """Payload offsets of the pre-wait `cmp r0, #imm` halfword.

    The two ldr-literal opcodes vary by firmware build (pool layout), so
    only their classes are matched; every fixed halfword around them
    must fit, including the bge that closes the gate and the
    counter-reset (movs/strh) that opens the detect path.
    """
    raw = bytes(payload)
    n = len(raw)
    hits = []
    for off in range(0, n - 24, 2):
        if raw[off + 1] != 0x48:  # ldr r0, [pc, #imm]
            continue
        if raw[off + 2] != 0x00 or raw[off + 3] != 0x88:  # ldrh r0, [r0]
            continue
        if raw[off + 4] != 0x40 or raw[off + 5] != 0x1C:  # adds r0, #1
            continue
        if raw[off + 6] != 0x80 or raw[off + 7] != 0xB2:  # uxth r0, r0
            continue
        if raw[off + 9] != 0x49:  # ldr r1, [pc, #imm]
            continue
        if raw[off + 10] != 0x08 or raw[off + 11] != 0x80:  # strh r0, [r1]
            continue
        if raw[off + 12] != imm or raw[off + 13] != 0x28:  # cmp r0, #imm
            continue
        hw = raw[off + 14] | (raw[off + 15] << 8)
        if (hw & 0xF000) != 0xD000 or ((hw >> 8) & 0xF) != 0xA:  # bge
            continue
        pos = off + 16
        tail = raw[pos] | (raw[pos + 1] << 8)
        if (tail & 0xF800) == 0xE000:  # optional b <return> on miss
            pos += 2
        if raw[pos] != 0x00 or raw[pos + 1] != 0x20:  # movs r0, #0
            continue
        if raw[pos + 3] != 0x49:  # ldr r1, [pc, #imm]
            continue
        if raw[pos + 4] != 0x08 or raw[pos + 5] != 0x80:  # strh r0, [r1]
            continue
        hits.append(off + 12)
    return hits


def find_pd_prewait(payload):
    """Locate the PD pre-wait counter compare.

    Returns (state, cmp_offset): "stock" (100 passes), "patched"
    (5 passes), "absent" (no counter in this firmware), or "unknown"
    (ambiguous - fail closed, do not patch).
    """
    stock = _pd_prewait_offsets(payload, PD_PREWAIT_ORIG)
    patched = _pd_prewait_offsets(payload, PD_PREWAIT_NEW)
    if len(stock) == 1 and not patched:
        return ("stock", stock[0])
    if len(patched) == 1 and not stock:
        return ("patched", patched[0])
    if not stock and not patched:
        return ("absent", None)
    return ("unknown", None)


def find_pd_task(payload):
    """True when the PD settle task is present (any version)."""
    return bytes(payload).find(PD_TASK_ANCHOR) >= 0


# CH224Q PD-settle stability thresholds: after the pre-wait, the 20 ms
# charger task counts consecutive stable reads per charger-response bit
# and only then requests the voltage profile. Stock needs 31 (cmp #0x1E
# + ble, bit #0x10 path) and 41 (cmp #0x28 + ble, bit #0x08 path)
# consecutive passes: 620/820 ms of blank screen with a dead button.
# Same counter-increment prefix as the pre-wait, but closed by BLE
# (stay in the settle loop) instead of BGE. Trimming both thresholds
# (17/22 passes, 340/440 ms) saves ~300 ms; a wrong early profile request
# self-corrects on the next heater-path re-evaluation, but this guard
# debounces the charger link, so the patch stays opt-in until
# hardware-validated. Present on all versions (same shape v1.1.4-v1.1.6).
PD_SETTLE_ORIG = (0x1E, 0x28)
PD_SETTLE_NEW = (0x10, 0x15)


def _pd_settle_offsets(payload, imm=None):
    """Payload offsets of settle `cmp r0, #imm` halfwords.

    Same fixed prefix as the pre-wait counter, but the gate closes with
    BLE (keep settling) rather than BGE. Register/literal-pool fields
    vary by build, so only opcode classes and fixed bytes are matched.
    With imm=None every threshold value matches; returns [(cmp_off, imm)].
    """
    raw = bytes(payload)
    n = len(raw)
    hits = []
    for off in range(0, n - 16, 2):
        if raw[off + 1] != 0x48:  # ldr r0, [pc, #imm]
            continue
        if raw[off + 2] != 0x00 or raw[off + 3] != 0x88:  # ldrh r0, [r0]
            continue
        if raw[off + 4] != 0x40 or raw[off + 5] != 0x1C:  # adds r0, #1
            continue
        if raw[off + 6] != 0x80 or raw[off + 7] != 0xB2:  # uxth r0, r0
            continue
        if raw[off + 9] != 0x49:  # ldr r1, [pc, #imm]
            continue
        if raw[off + 10] != 0x08 or raw[off + 11] != 0x80:  # strh r0, [r1]
            continue
        if raw[off + 13] != 0x28:  # cmp r0, #imm
            continue
        if imm is not None and raw[off + 12] != imm:
            continue
        hw = raw[off + 14] | (raw[off + 15] << 8)
        if (hw & 0xF000) != 0xD000 or ((hw >> 8) & 0xF) != 0xD:  # ble
            continue
        hits.append((off + 12, raw[off + 12]))
    return hits


def read_pd_settle(payload):
    """Locate the two PD settle threshold compares regardless of value.

    Returns ([off_a, off_b], (imm_a, imm_b)) in code order (A = bit #0x10
    path, lower address on all known versions), or None when the site
    count is not exactly two (missing or ambiguous - fail closed).
    """
    hits = sorted(_pd_settle_offsets(payload))
    if len(hits) != 2:
        return None
    return ([h[0] for h in hits], (hits[0][1], hits[1][1]))


def find_pd_settle(payload):
    """Locate the two PD settle threshold compares.

    Returns (state, [off_a, off_b]): "stock" (31/41 passes), "patched"
    (17/22 passes), "custom" (exactly two sites, other values),
    "absent" (no settle counter in this firmware), or "unknown"
    (ambiguous - fail closed, do not patch).
    """
    sites = read_pd_settle(payload)
    if sites is None:
        if not _pd_settle_offsets(payload):
            return ("absent", None)
        return ("unknown", None)
    offs, imms = sites
    if imms == PD_SETTLE_ORIG:
        return ("stock", offs)
    if imms == PD_SETTLE_NEW:
        return ("patched", offs)
    return ("custom", offs)


def _parse_only(value):
    """Parse a --only value: one patch name or several comma-separated."""
    names = [p.strip() for p in value.split(",") if p.strip()]
    unknown = [p for p in names if p not in PATCH_NAMES]
    if not names or unknown:
        bad = ", ".join(unknown) if unknown else repr(value)
        raise argparse.ArgumentTypeError(
            f"unknown patch(es): {bad} (choose from {', '.join(PATCH_NAMES)})"
        )
    return names


def _parse_ms_pair(value, what, count, lo, hi):
    """Parse a 'MS[,MS]' flag value into raw integer milliseconds."""
    parts = [p.strip() for p in value.split(",")]
    if len(parts) != count:
        raise argparse.ArgumentTypeError(
            f"{what} expects {count} comma-separated ms values "
            f"(got {value!r})"
        )
    try:
        ms = [int(p) for p in parts]
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{what} expects integer milliseconds (got {value!r})"
        )
    for m in ms:
        if not lo <= m <= hi:
            raise argparse.ArgumentTypeError(
                f"{what} values must be {lo}..{hi} ms (got {m})"
            )
    return tuple(ms)


def _parse_fastsettle(value):
    """Parse --fastsettle MS,MS (both thresholds, 0..600 ms each)."""
    return _parse_ms_pair(value, "--fastsettle", 2, 0, 600)


def _parse_fastlcd(value):
    """Parse --fastlcd MS,MS (post-reset, SLPOUT; 1..255 ms each)."""
    return _parse_ms_pair(value, "--fastlcd", 2, 1, 255)


def round20(ms):
    """Round ms to the nearest multiple of 20 (half-up)."""
    return (ms + 10) // 20 * 20


def settle_ms_to_imm(ms):
    """Convert a settle threshold in ms to a cmp immediate.

    The charger task ticks every 20 ms and the loop exits once the
    counter exceeds the immediate, so passes = imm + 1. 0 ms (no
    debounce) still needs one pass to sample the charger: imm 0.
    """
    return max(0, round20(ms) // 20 - 1)


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
        "patch", help="Apply patches (default: all)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""patches:
  nolie    remove fake temperature display compensation (BNE -> NOP)
  nologo   skip the boot logo animation (draw loop runs zero times)
  fastlcd  shorten the LCD init waits (100,100,200 ms -> 70,70,120 ms)
  earlykey capture keypresses during boot waits (on by default;
           use --skip earlykey to opt out; see README)
  fastpd   shorten the PD pre-wait (100x20 ms -> 5 passes, v1.1.6 only;
           no-op on versions without the counter)
  fastsettle trim the PD settle thresholds (31/41 -> 17/22 passes;
           opt-in until hardware-validated; see README)

tunable parameters (imply the patch; conflict with --skip of the same):
  --fastsettle MS,MS  settle thresholds in ms, 0..600 each (default 340,440);
           rounded to the 20 ms charger tick; 0 disables the debounce
  --fastlcd MS,MS     LCD waits in ms: post-reset (x2) and SLPOUT
           (default 70,120); values below the MIPI DCS 120 ms minimum
           warn but are applied

every patch run also stamps the Ver Info screen (menu 16):
  N/L/F/E/P/S = patch present, '-' = absent (e.g. 'T90A1.1.4NLFEPS',
  default run stamps 'NLFEP-')""",
    )
    parser_patch.add_argument("file", help="Input .atk firmware file")
    parser_patch.add_argument("output", nargs="?", help="Output .atk file (optional)")
    selector = parser_patch.add_mutually_exclusive_group()
    selector.add_argument(
        "--only", action="append", type=_parse_only, default=None,
        metavar="PATCH[,PATCH]",
        help="Apply only the selected patches, comma-separated "
             "(default: nolie,nologo,fastlcd,earlykey,fastpd; fastsettle opt-in)",
    )
    selector.add_argument(
        "--skip", action="append", type=_parse_only, default=None,
        metavar="PATCH[,PATCH]",
        help="Apply the default patches except the given ones, "
             "comma-separated (fastsettle never in the default set)",
    )
    parser_patch.add_argument(
        "--fastsettle", type=_parse_fastsettle, default=None,
        metavar="MS,MS",
        help="PD settle thresholds in ms, 0..600 each (default 340,440); "
             "rounded to the 20 ms tick; implies --only fastsettle",
    )
    parser_patch.add_argument(
        "--fastlcd", type=_parse_fastlcd, default=None,
        metavar="MS,MS",
        help="LCD post-reset and SLPOUT waits in ms (default 70,120); "
             "below-spec values warn but are applied; implies fastlcd",
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
