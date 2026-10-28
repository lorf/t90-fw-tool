# T90 Firmware Tool

Python tool for analyzing and patching Alientek T90 family soldering iron firmware (`.atk` files).

## Overview

This tool supports three operations on `.atk` firmware files:
- **info**: Display firmware header and vector table information
- **extract**: Strip the header and decrypt the firmware payload to a raw `.bin` file
- **patch**: Apply the "no lie" temperature patch to remove fake temperature compensation

### Firmware Format

The `.atk` container format consists of:

| Offset | Size | Field       | Description |
|--------|------|-------------|-------------|
| 0x0000 | 2    | `dev_type`  | Device model (0x0208 for T90) |
| 0x0002 | 1    | `hw_rev`    | Hardware revision |
| 0x0003 | 1    | `app_ver`   | Application version |
| 0x0004 | 1    | `file_type` | Image type (0xA0=App, 0xA1=Logo, 0xB0=Bootloader) |
| 0x0005 | 1    | `data_len`  | Flash chunk size (typically 32) |
| 0x0006 | 4    | `bin_size`  | Payload size in bytes |
| 0x000A | 3    | `date`      | Build date (year-2000, month, day) |
| 0x000D | N    | `payload`   | XOR-0xFF obfuscated firmware |

The firmware payload is XOR'd with `0xFF`. After decryption, the first 8 bytes form the ARM Cortex-M vector table (initial SP and Reset vector).

- **MCU**: Nationstech N32L40x (ARM Cortex-M4F)
- **Image base**: `0x08005000` (bootloader occupies `0x08000000`-`0x08004FFF`, not included in updates)

### The "No Lie" Patch

The T90 firmware contains temperature compensation code that can display inaccurate temperature readings. The "no lie" patch removes this behavior by:

1. **Finding** the function with the signature pattern:
   ```asm
   PUSH {R4, R5, R6, LR}
   MOV  R4, R0
   MOV  R5, R1
   MOV  R6, R2
   CMP  R5, R4          ; compare two parameters
   BNE  <lie_code>      ; branch to fake temperature adjustment
   MOV  R0, R4          ; return real value (early exit)
   POP  {R4, R5, R6, PC}
   ```

2. **Replacing** the `BNE` instruction with `NOP`, so the code always returns the real temperature value instead of applying compensation.

Unlike tools that patch at fixed byte offsets, this script:
- Searches for the function pattern across the firmware
- Verifies surrounding instructions match expected context
- Works across different firmware versions

## Installation

No dependencies required — Python 3 only (standard library).

```bash
chmod +x t90_fw_tool.py
```

## Usage

### Info

```bash
python3 t90_fw_tool.py info t90.atk
```

Output:
```
File: t90.atk
Size: 104461 bytes (header: 13 + payload: 104448)

=== Firmware Header (FirmInfo) ===
  dev_type:  0x0208 (T90)
  hw_rev:    10
  app_ver:   1.0.01
  file_type: Application
  data_len:  32 bytes (chunk size)
  bin_size:  104448 bytes (104448 payload)
  date:      2026-08-17

=== Decrypted Vector Table ===
  Initial SP:    0x20004DB8
  Reset Vector:  0x080052CD

=== No-Lie Patch ===
  Status:     not patched (BNE at payload offset 33290, ARM 0x0800D20A)

=== Validation ===
  File size matches bin_size + header (104461 bytes) - OK
  SP address in RAM range (0x2000xxxx) - OK
  Reset vector in Flash range - OK
```

### Extract

```bash
python3 t90_fw_tool.py extract t90.atk firmware.bin
```

Output:
```
Extracted firmware to: firmware.bin
  Payload size: 104448 bytes
  Image base: 0x08005000 (ARM Cortex-M4)
```

This produces a raw binary file loadable into IDA, Ghidra, or objdump at base address `0x08005000`.

### Patch

```bash
python3 t90_fw_tool.py patch t90.atk t90_no_lie.atk
```

Output:
```
Patch location verified at payload offset 33290 (ARM 0x0800D20A)
Current instruction at 0x0800D20A: 0xD101
  BNE #+6 -> jumps to 0x0800D210 (the 'lie' code)
  New instruction: 0xBF00 (NOP)
  This removes the 'lie' temperature compensation

Patched firmware written to: t90_no_lie.atk
  Original size: 104461 bytes
  Output size:   104461 bytes
```

Without explicit output:
```bash
python3 t90_fw_tool.py patch t90.atk
```
This writes `t90_no_lie.atk` (auto-appends `_no_lie` to the filename).

## Safety Features

- **Pattern matching**: Finds the correct code location dynamically, not hardcoded offsets
- **Context verification**: Validates surrounding instructions before patching
- **Already-patched detection**: Refuses to patch firmware that's already been modified
- **Header validation**: Rejects files with unexpected `dev_type` values

## Verified Compatibility

Tested against:
- `t90_v1.1.4.atk` → matches reference `t90_v1.1.4_no_lie.atk` byte-for-byte
- `t90_v1.1.5.atk` → matches reference `t90_v1.1.5_no_lie.atk` byte-for-byte
- `t90.atk` → successfully patched (unknown version, date 2026-08-17)

## References

- [atflash](https://github.com/mishka-zz/atflash) — Firmware flashing tool for T90
- [protocol.md](https://github.com/mishka-zz/atflash/blob/main/protocol.md) — Firmware upgrade protocol specification
- [t90-rev](https://github.com/truesurge/t90-rev) — Community reverse engineering collection
- [4PDA Forum](https://4pda.to/forum/index.php?showtopic=1061134) — Community discussion
- [Latest T90 firmware](https://www.openedv.com/ATK-Prod/ATK-T90/) - Latest official T90 firmware
