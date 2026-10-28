#!/usr/bin/env python3
"""
t90_tool.py - Alientek T90 firmware analysis and patching tool

Usage:
    t90_tool.py info <file.atk>          # Print firmware header information
    t90_tool.py extract <file.atk> [out.bin]  # Strip header, decrypt to .bin
    t90_tool.py patch <file.atk> [out.atk]    # Apply "no lie" temperature patch

The "no lie" patch removes the fake temperature reading compensation
from the T90 soldering iron firmware by replacing a conditional branch
(BNE) with a NOP instruction.

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
    't90_no_lie.atk' + '1.1.4' -> 't90_no_lie_v1.1.4.atk'.

    Leaves the name untouched if the version is unknown or is already
    part of the file name, or if the name was supplied by the user.
    """
    if not version or version_in_filename(filename, version):
        return filename
    dot = filename.rfind(".")
    if dot > 0:
        return f"{filename[:dot]}_v{version}{filename[dot:]}"
    return f"{filename}_v{version}"


def find_patch_location(payload):
    """
    Search for the 'lie' patch location in decrypted firmware.

    Searches for the function signature:
        PUSH {R4, R5, R6, LR}
        MOV  R4, R0
        MOV  R5, R1
        MOV  R6, R2
        CMP  R5, R4
        BNE  <offset>
        MOV  R0, R4
        POP  {R4, R5, R6, PC}

    Returns the payload offset of the BNE instruction, or None if not found.
    """
    # Build the signature pattern
    # We search for a 7-instruction sequence
    signature = [
        THUMB_PUSH_R4R5R6LR,    # PUSH {R4, R5, R6, LR}
        THUMB_MOV_R4_R0,         # MOV R4, R0
        THUMB_MOV_R5_R1,         # MOV R5, R1
        THUMB_MOV_R6_R2,         # MOV R6, R2
        THUMB_CMP_R5_R4,         # CMP R5, R4
        None,                    # BNE (we check the pattern)
        THUMB_MOV_R0_R4,         # MOV R0, R4 (early return body)
        THUMB_POP_R4R5R6PC,      # POP {R4, R5, R6, PC}
    ]

    for i in range(len(payload) - 7 * 2):
        match = True
        for j, expected in enumerate(signature):
            hw = struct.unpack_from("<H", payload, i + j * 2)[0]
            if expected is not None and hw != expected:
                match = False
                break
            if expected is None:
                # This should be BNE (D1xx)
                if (hw & 0xF000) != 0xD000:  # B<cond>
                    match = False
                    break
                # Check it's BNE specifically (condition 0x01)
                if (hw & 0x0F00) != 0x0100:  # NE condition
                    match = False
                    break
                # Check offset is positive and small (likely +6 = skip early return)
                imm = hw & 0xFF
                if imm != 0x01:  # BNE #2 -> offset is (imm * 2 + 4) = 6
                    match = False
                    break

        if match:
            # Found the pattern - the BNE is at offset i + 5*2
            return i + 5 * 2

    return None


def verify_patch_context(payload, patch_offset):
    """
    Verify the context around the patch location to ensure this is the right
    code block to patch.

    The expected function layout (from PUSH to POP) is:
        PUSH {R4, R5, R6, LR}   (patch_offset - 10)
        MOV  R4, R0             (patch_offset - 8)
        MOV  R5, R1             (patch_offset - 6)
        MOV  R6, R2             (patch_offset - 4)
        CMP  R5, R4             (patch_offset - 2)
        BNE  <offset>           (patch_offset)   <- PATCH TARGET
        MOV  R0, R4             (patch_offset + 2)  <- early return body
        POP  {R4, R5, R6, PC}   (patch_offset + 4)

    Returns True if context is valid, False otherwise.
    """
    # Check we have enough context (need 5 halfwords before and 2 after)
    if patch_offset < 10 or patch_offset + 6 > len(payload):
        return False

    # Verify the PUSH {R4, R5, R6, LR} at patch_offset - 10
    hw = struct.unpack_from("<H", payload, patch_offset - 10)[0]
    if hw != THUMB_PUSH_R4R5R6LR:
        return False

    # Verify CMP R5, R4 just before the BNE
    hw = struct.unpack_from("<H", payload, patch_offset - 2)[0]
    if hw != THUMB_CMP_R5_R4:
        return False

    # Verify the early return body after BNE: MOV R0, R4
    hw = struct.unpack_from("<H", payload, patch_offset + 2)[0]
    if hw != THUMB_MOV_R0_R4:
        return False

    # Verify POP {R4, R5, R6, PC} after MOV
    hw = struct.unpack_from("<H", payload, patch_offset + 4)[0]
    if hw != THUMB_POP_R4R5R6PC:
        return False

    return True


def cmd_patch(args):
    """Apply the 'no lie' patch to a T90 firmware file."""
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

    # Find the patch location
    patch_offset = find_patch_location(payload)

    if patch_offset is None:
        print("Error: Could not find the 'lie' patch location in firmware.", file=sys.stderr)
        print("  The function signature pattern was not found.", file=sys.stderr)
        print("  This may be a different firmware version or already patched.", file=sys.stderr)
        return 1

    # Verify context
    if not verify_patch_context(payload, patch_offset):
        print(f"Warning: Surrounding code context does not fully match expected pattern.",
              file=sys.stderr)
        print(f"  Patch location found at offset {patch_offset} (ARM 0x{0x08005000 + patch_offset:08X})",
              file=sys.stderr)
    else:
        print(f"Patch location verified at payload offset {patch_offset} "
              f"(ARM 0x{0x08005000 + patch_offset:08X})")

    # Read the current instruction (should be BNE)
    current_hw = struct.unpack_from("<H", payload, patch_offset)[0]
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
    new_payload = bytearray(payload)
    struct.pack_into("<H", new_payload, patch_offset, THUMB_NOP)

    print(f"  New instruction: 0x{THUMB_NOP:04X} (NOP)")
    print(f"  This removes the 'lie' temperature compensation")

    # Re-encrypt the payload
    encrypted_payload = xor_decrypt(bytes(new_payload))

    # Build the output file
    output = bytearray(data[:13])  # Keep original header
    output.extend(encrypted_payload)

    # Determine output file
    if args.output:
        output_file = args.output
    else:
        if args.file.endswith(".atk"):
            base, ext = args.file[:-4], ".atk"
        else:
            base, ext = args.file, ""
        if base.endswith("_no_lie"):
            base = base[:-len("_no_lie")]
        # Version goes before the '_no_lie' suffix: t90_v1.1.4_no_lie.atk
        output_file = make_versioned_filename(base, version) + "_no_lie" + ext

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


def main():
    parser = argparse.ArgumentParser(
        description="Alientek T90 firmware analysis and patching tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
    info    Print firmware header and vector table information
    extract Strip header and decrypt firmware to .bin file
    patch   Apply 'no lie' temperature patch (BNE -> NOP)

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
        "patch", help="Apply 'no lie' temperature patch"
    )
    parser_patch.add_argument("file", help="Input .atk firmware file")
    parser_patch.add_argument("output", nargs="?", help="Output .atk file (optional)")

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
