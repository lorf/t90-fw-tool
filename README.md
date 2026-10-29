# Alientek T90 (T90A/T90B/T90C) Firmware Tool

Python tool for analyzing and patching Alientek T90 family soldering iron firmware (`.atk` files).

## TL;DR

Patch the firmware in one command:

```bash
python3 t90_fw_tool.py patch t90.atk
```

This writes `t90_no_lie.atk` — the patched firmware with fake temperature compensation removed. You can flash it using [atflash](https://github.com/mishka-zz/atflash) or the official Alientek upgrade protocol.

## Overview

This tool supports three operations on `.atk` firmware files:
- **info**: Display firmware header and vector table information
- **extract**: Strip the header and decrypt the firmware payload to a raw `.bin` file
- **patch**: Apply the "no lie" temperature patch to remove fake temperature compensation

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

## References

- [atflash](https://github.com/mishka-zz/atflash) — Firmware flashing tool for T90
- [protocol.md](https://github.com/mishka-zz/atflash/blob/main/protocol.md) — Firmware upgrade protocol specification
- [t90-rev](https://github.com/truesurge/t90-rev) — Community reverse engineering collection
- [4PDA Forum](https://4pda.to/forum/index.php?showtopic=1061134) — Community discussion
- [Latest T90 firmware](https://www.openedv.com/ATK-Prod/ATK-T90/) - Latest official T90 firmware

## Acknowledgments

- [4asik](https://4pda.to/forum/index.php?showtopic=1061134&view=findpost&p=142761677) (4pda.to forums) — original author of the "no lie" patch
- [mishka-zz](https://github.com/mishka-zz) — reverse-engineered firmware header format and flash protocol (atflash), command line flash tool author

This tool was created with AI assistance.
