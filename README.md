# Alientek T90 (T90A/T90B/T90C) Firmware Tool

Python tool for analyzing and patching Alientek T90 family soldering iron firmware (`.atk` files).

## TL;DR

Patch the firmware in one command:

```bash
python3 t90_fw_tool.py patch t90.atk
```

This writes `t90_v<version>_nolie_nologo.atk` — the patched firmware with fake temperature display compensation removed and the boot logo animation skipped. You can flash it using [atflash](https://github.com/mishka-zz/atflash) or the official Alientek upgrade protocol.

## Overview

This tool supports three operations on `.atk` firmware files:
- **info**: Display firmware header, vector table, extracted firmware version, and patch status
- **extract**: Strip the header and decrypt the firmware payload to a raw `.bin` file
- **patch**: Apply the "nolie" temperature display patch and the "nologo" boot logo skip

> **Note:** The `app_ver` field in the firmware header is always `1.0.01` regardless of the actual version. The real firmware version is extracted from a Thumb self-check pattern in the decrypted payload, and falls back to the filename if the pattern is not found.

### The "Nolie" Patch

The T90 firmware contains display-only compensation code that offsets the **shown** temperature, so the display can read inaccurately. The "nolie" patch removes this display offset by:

1. **Finding** the function with the signature pattern:
   ```asm
   PUSH {R4, R5, R6, LR}
   MOV  R4, R0
   MOV  R5, R1
   MOV  R6, R2
   CMP  R5, R4          ; compare two parameters
   BNE  <lie_code>      ; branch to fake temperature display adjustment
   MOV  R0, R4          ; return real value (early exit)
   POP  {R4, R5, R6, PC}
   ```

2. **Replacing** the `BNE` instruction with `NOP`, so the code always returns the real temperature value instead of applying the display compensation.

> **Scope:** this patch only affects the **displayed** temperature. It changes neither the actual soldering iron tip temperature (heater control loop) nor the measured temperature — only the number shown on screen.

Unlike tools that patch at fixed byte offsets, this script:
- Searches for the function pattern across the firmware
- Verifies surrounding instructions match expected context
- Works across different firmware versions

### The "Nologo" Patch

At boot the firmware draws the 160x40 logo in a sliding-animation loop (~21 fullscreen redraws), which dominates startup time. The "nologo" patch skips the loop while keeping the boot state machine intact:

1. **Finding** the animation init with surrounding-code verification:
   ```asm
   CBNZ r0, <skip>
   MOVS r0, #0
   LDR  r1, [PC, #imm]  ; boot flag
   STRB r0, [r1]
   MVN.W r4, #0x26      ; loop counter = -39 (patched site)
   B    <loop>
   CMP  r4, #0
   BLT  <redraw>
   MOVS r4, #0
   ```

2. **Replacing** `mvn.w r4, #0x26` with `movs r4, #2; nop`, so the loop-exit condition (`r4 >= 2`) is already true and zero draws run. Every raw byte-match is validated against the neighbours above, so a stray byte sequence inside bitmap/data cannot be mispatched.

`patch` applies both patches in one run.

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

=== Firmware Version ===
  version:   1.1.4
  source:    code self-check immediates (1 at payload offset 0x0200)

=== Decrypted Vector Table ===
  Initial SP:    0x20004DB8
  Reset Vector:  0x080052CD

=== Validation ===
  File size matches bin_size + header (104461 bytes) - OK
  SP address in RAM range (0x2000xxxx) - OK
  Reset vector in Flash range - OK

=== Patches ===
  nolie:    not patched (BNE at payload offset 0x820A, ARM 0x0800D20A)
  nologo:   not patched (mvn.w r4, #0x26 at payload offset 0x0FB84, ARM 0x08014B84)
      OK   CBNZ r0: 0xBB30
      OK   MOVS r0, #0: 0x2000
      OK   LDR Rt, [PC, #imm] (r1): 0x493B
      OK   STRB r0, [r1]: 0x7008
      OK   B <loop>: 0xE015
      OK   CMP r4, #0: 0x2C00
      OK   BLT <redraw>: 0xDB00
      OK   MOVS r4, #0: 0x2400
```

### Extract

```bash
python3 t90_fw_tool.py extract t90.atk
```

Output:
```
Extracted firmware to: t90_v1.1.4.bin
  Payload size: 104448 bytes
  Image base: 0x08005000 (ARM Cortex-M4)
  Firmware version: 1.1.4
```

This produces a raw binary file named `<basename>_v<version>.bin` (e.g. `t90_v1.1.4.bin`), loadable into IDA, Ghidra, or objdump at base address `0x08005000`.

### Patch

```bash
python3 t90_fw_tool.py patch t90.atk t90_nolie_nologo.atk
```

Output:
```
Patch location found at payload offset 0x820A (ARM 0x0800D20A)
Current instruction at 0x0800D20A: 0xD101
  BNE #+6 -> jumps to 0x0800D210 (the 'lie' code)
  New instruction: 0xBF00 (NOP)
  This removes the 'lie' temperature display compensation
Logo animation init at payload offset 0x0FB84 (ARM 0x08014B84): mvn.w r4, #0x26 (-39)
    OK   CBNZ r0: 0xBB30
    OK   MOVS r0, #0: 0x2000
    OK   LDR Rt, [PC, #imm] (r1): 0x493B
    OK   STRB r0, [r1]: 0x7008
    OK   B <loop>: 0xE015
    OK   CMP r4, #0: 0x2C00
    OK   BLT <redraw>: 0xDB00
    OK   MOVS r4, #0: 0x2400
  Patched to: movs r4, #2; nop (loop runs zero times, logo skipped)

Patched firmware written to: t90_v1.1.4_nolie_nologo.atk
  Original size: 104461 bytes
  Output size:   104461 bytes
  Firmware version: 1.1.4
```

Without explicit output:
```bash
python3 t90_fw_tool.py patch t90.atk
```
This writes `t90_v1.1.4_nolie_nologo.atk` (auto-inserts the firmware version and `_nolie_nologo` suffix).

To apply only one patch:

```bash
python3 t90_fw_tool.py patch --only nolie t90.atk    # -> t90_v1.1.4_nolie.atk
python3 t90_fw_tool.py patch --only nologo t90.atk   # -> t90_v1.1.4_nologo.atk
```

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
