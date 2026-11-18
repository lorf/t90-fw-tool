# Alientek T90 (T90A/T90B/T90C) Firmware Tool

Python tool for analyzing and patching Alientek T90 family soldering iron firmware (`.atk` files).

## TL;DR

Patch the firmware in one command:

```bash
python3 t90_fw_tool.py patch t90.atk
```

This writes `t90_v<version>_nolie_nologo_fastlcd_fastpd.atk` — the patched firmware with fake temperature display compensation removed, the boot logo animation skipped, the LCD init waits shortened, and the PD-settle pre-wait shortened. You can flash it using [atflash](https://github.com/mishka-zz/atflash) or the official Alientek upgrade protocol.

## Overview

This tool supports three operations on `.atk` firmware files:
- **info**: Display firmware header, vector table, extracted firmware version, and patch status
- **extract**: Strip the header and decrypt the firmware payload to a raw `.bin` file
- **patch**: Apply the "nolie" temperature display patch, the "nologo" boot logo skip, the "fastlcd" LCD-timing trim, and the "fastpd" PD-settle pre-wait trim ("earlykey" boot key-capture is experimental, opt-in only); every run also stamps the patch designation onto the "Ver Info" screen

> **Note:** The `app_ver` field in the firmware header is always `1.0.01` regardless of the actual version. The real firmware version is extracted from a Thumb self-check pattern in the decrypted payload, and falls back to the filename if the pattern is not found.

### The "Nolie" Patch

The T90 firmware contains display-only compensation code that normalizes the **shown** temperature (hides the initial temperature overshoot, filters temperature fluctuations), so the display can read inaccurately. The "nolie" patch removes this display offset by:

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

`patch` applies the four stable patches in one run. (`earlykey` is excluded — see below.)

### The "Fastlcd" Patch

Even with the logo animation skipped, ~470 ms of fixed busy-wait delays remain on the boot path (measured by disassembly, identical layout in v1.1.4/v1.1.5/v1.1.6):

| Wait | Location | Purpose | Stock | Trimmed |
|------|----------|---------|-------|---------|
| post-reset settle ×2 | LCD init (`0x08009B70`) | panel power-on stabilization | 100 + 100 ms | 70 + 70 ms |
| SLPOUT → DISPON | LCD init (`0x0800A0BE`) | MIPI DCS power-on sequence (`0x11` … `0x29`) | 200 ms | 120 ms |
| boot pacing / beep | boot task | frame pacing, 20 ms beep | 20 + 20 ms | left as-is |
| panel/touch init | panel init | register setup | 5+10+2+10+2 ms | left as-is |

The two LCD waits are the only ones worth trimming: MIPI DCS requires ≥120 ms after reset and ≥120 ms after SLPOUT, so 140/120 ms keeps spec compliance (stock 200/200 is conservative). The remaining ~30 ms of small waits are left untouched — negligible gain, unknown hardware constraints.

The "fastlcd" patch rewrites the three `movs r0, #imm` delay arguments (single halfword each, 3 bytes total in the image). Sites are located version-agnostically: the delay routine is found via the unique SLPOUT…DISPON command cluster, then the waits are identified as its only `100/100`-adjacent and `200` callers. It is applied by default; to skip it (it alters hardware timing, unlike the other two patches), use `--skip` if the panel ever fails to initialize on cold boot:

```bash
python3 t90_fw_tool.py patch --skip fastlcd t90.atk   # -> t90_v1.1.4_nolie_nologo.atk
```

A plain `python3 t90_fw_tool.py patch t90.atk` applies the four stable patches (nolie, nologo, fastlcd, fastpd). On v1.1.4/v1.1.5, which settle the PD link without a pre-wait counter, `fastpd` reports "not applicable" and skips, so the run still succeeds.

Combined with nologo (which skips the ~21-draw logo animation loop entirely), this removes the last large fixed delay on the boot path: ~140 ms saved on top of the skipped animation.

### The "Fastpd" Patch

The blank screen at boot is not LCD init (~260 ms even untrimmed) but the
CH224Q charger task: on v1.1.6 it counts 100 × 20 ms passes (~2.0 s) before
its first charger detect, then needs 31/41 consecutive stable reads before
the voltage-profile request goes out. The "fastpd" patch shortens only the
dead pre-wait (100 → 5 passes, ~1.9 s saved), keeping the stability settle
that protects the PD request. A wrong early request self-corrects on the
next heater-path re-evaluation. It is default-on like `fastlcd`; use
`--skip fastpd` if the charger ever fails to negotiate on cold plug:

```bash
python3 t90_fw_tool.py patch --skip fastpd t90.atk   # -> t90_v1.1.4_nolie_nologo_fastlcd.atk
python3 t90_fw_tool.py patch --only fastpd t90.atk   # -> t90_v1.1.6_fastpd.atk
```

v1.1.4/v1.1.5 settle the PD link without this counter, so there the patch
is a no-op ("not applicable") rather than an error.

### The "Earlykey" Patch (EXPERIMENTAL — do not use yet)

> **Hardware test result (T90B): with `earlykey` applied, the start-heating button still has no effect for ~1 s after power-up, and spontaneous reboots occur during heat-up (stable again at target temp; reboots gone after reflashing without `earlykey`).** The patch is therefore **not applied by default** and stays opt-in (`--only earlykey`) until the cause is isolated. The `info` command still detects images that already contain it.

Even with the boot path shortened, the heater start button is dead until LCD init finishes: the firmware super-loop only samples keys in the main loop, after the blocking LCD init. The "earlykey" patch captures a press made during any boot wait so it acts as soon as the main loop starts:

1. **Finding** the key-scan routine version-agnostically via the unique image-wide `mov.w r1, #0x8000` (key pin mask), with entry at the preceding `PUSH` and a `movs r1, #0x10` (second key pin mask) required in the same function. All 14 `delay_ms()` callers are located via the SLPOUT…DISPON anchor.
2. **Installing** a 48-byte polling-delay routine into the zero-filled cave at ARM `0x08006040` (empty in v1.1.4/v1.1.5/v1.1.6). It keeps the exact `delay_ms(n)` ABI — n × 1 ms slices through the original routine — but enables the GPIO port clocks idempotently and polls the key-scan routine every 8th slice.
3. **Redirecting** all 14 `delay_ms()` BL call sites to the cave. Timing is unchanged (the key poll costs ~µs against a 1 ms slice); keypresses during LCD init or any other wait are now captured for the control loop.

The patch refuses to apply unless every pattern is unambiguous (single anchor match, empty cave, all callers resolved) and composes with the other patches in either order. Detectors see through the redirection, so `info` still reports `fastlcd` state and re-running is idempotent. It is opt-in only:

```bash
python3 t90_fw_tool.py patch --only earlykey t90.atk   # -> t90_v1.1.4_earlykey.atk
```

## Installation

No dependencies required — Python 3 only (standard library).

```bash
chmod +x t90_fw_tool.py
```

## Running tests

The test suite (pytest) covers the header parser, XOR crypto, version
extraction, the patch scanners, and end-to-end CLI runs against
synthetic `.atk` images built from the real firmware layout, plus
sanity checks against the real firmware archive:

```bash
pip install pytest          # dev-only dependency
python3 -m pytest
```

Archive tests read `~/apps/atflash/firmware/` (override with
`T90_FIRMWARE_DIR=...`) and skip automatically when the directory is
missing.

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
  fastlcd:  not patched (LCD waits: 100 ms, 100 ms, 200 ms)
  verinfo:  '(none)' on the Ver Info screen (menu 16, payload offset 0x11814)
  earlykey: not patched (key-scan at payload offset 0x0C3D8, ARM 0x080113D8)
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
python3 t90_fw_tool.py patch t90.atk t90_nolie_nologo_fastlcd_fastpd.atk
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
LCD wait at payload offset 0x04B76 (ARM 0x08009B76): movs r0, #100 -> movs r0, #70
LCD wait at payload offset 0x04B7C (ARM 0x08009B7C): movs r0, #100 -> movs r0, #70
LCD wait at payload offset 0x050BC (ARM 0x0800A0BC): movs r0, #200 -> movs r0, #120
  Patched to: LCD waits [70, 70, 120] ms (saves ~140 ms of boot time)
PD pre-wait counter at payload offset 0x0A0D4 (ARM 0x0800F0D4): cmp r0, #100 -> cmp r0, #5
  Patched to: PD pre-wait 5 passes (saves ~1900 ms of blank-screen time)
Ver Info designation at payload offset 0x11814 (ARM 0x08016814): 'T90%s V%1d.%1d.%1dNLF-P'

Patched firmware written to: t90_nolie_nologo_fastlcd_fastpd.atk
  Original size: 104461 bytes
  Output size:   104461 bytes
  Firmware version: 1.1.4
```

An explicit output name is used verbatim — no version or patch suffix is added to it.

Without explicit output:
```bash
python3 t90_fw_tool.py patch t90.atk
```
This writes `t90_v1.1.4_nolie_nologo_fastlcd_fastpd.atk` (auto-inserts the firmware version and the `_nolie_nologo_fastlcd_fastpd` suffix).

The output name always reflects every patch present in the written file — including patches the input already contained. Patching a partially patched file therefore never loses track of earlier patches in the name, and old suffixes are never stacked.

To apply only a subset (comma-separated in one flag; the default run equals `--only nolie,nologo,fastlcd,fastpd` — `earlykey` is opt-in only):

```bash
python3 t90_fw_tool.py patch --only nolie t90.atk                    # -> t90_v1.1.4_nolie.atk
python3 t90_fw_tool.py patch --only nolie,nologo t90.atk             # -> t90_v1.1.4_nolie_nologo.atk
python3 t90_fw_tool.py patch --only fastlcd t90.atk                  # -> t90_v1.1.4_fastlcd.atk
python3 t90_fw_tool.py patch --only earlykey t90.atk                 # -> t90_v1.1.4_earlykey.atk
```

Or skip selected patches with `--skip` (the inverse; cannot be combined with `--only`):

```bash
python3 t90_fw_tool.py patch --skip fastlcd t90.atk                  # -> t90_v1.1.4_nolie_nologo.atk
```

### The "Ver Info" Designation

Menu item 16 shows the model variant and firmware version from the
format string `T90%s  V:%1d.%1d.%1d`. Every patch run also stamps a
one-letter-per-patch designation onto that line: `N` = nolie,
`L` = nologo, `F` = fastlcd, `E` = earlykey, `P` = fastpd, `-` = absent —
e.g. `T90A V1.1.4NLFEP` for a fully patched build, `T90A V1.1.4NLF-P` for
the default run on v1.1.6 (`NLF--` where the counter is absent),
`T90A V1.1.4N----` for nolie only. The
stamp collapses the vendor's double space to one, drops the colon,
and writes the letters into padding bytes inside the existing string
footprint, so no address moves and the file size is unchanged. `info`
reports the stamp as `verinfo:  'NLF-P'` for the default run
(`NLFEP` with `--only nolie,nologo,fastlcd,earlykey,fastpd`); stock firmware
shows `(none)`.

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
