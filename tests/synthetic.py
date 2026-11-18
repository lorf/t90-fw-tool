"""Synthetic .atk firmware builder for tests.

Reconstructs a realistic Alientek T90 firmware image (13-byte FirmInfo
header + XOR-0xFF payload) containing every byte pattern the tool scans
for, laid out the way it appears in the real v1.1.4/v1.1.5/v1.1.6
firmware files.  Layout constants are exposed so tests can assert
against exact offsets.

Payload map (matches the tool's scan behaviour):

    0x0000  vector table (SP in RAM range, Reset in flash range)
    0x0200  version self-check: ldrh r0,[r0,#4]; cmp r0,#<imm>; beq
    0x0400  delay_ms() routine (MS_DELAY_HEAD)
    0x0430  LCD init: two adjacent movs r0,#100; bl delay_ms calls
    0x0460  SLPOUT..DISPON cluster with movs r0,#200; bl delay_ms
    0x04A0  logo animation init with all 8 verified neighbours
    0x04C0  'lie' function (8-halfword signature, BNE at slot 6)
    0x0500  PD pre-wait counter (cmp r0,#100; bge) + task anchor
    0x0600  13 more `movs r0,#imm; bl delay_ms` callers (16 total,
            as in the real firmware - fastlcd counts on there being
            only one 100/100 adjacent pair)
    0x0640  key-scan routine (earlykey anchor + probe)
    0x0800  code region begins (find_firmware_version scans from here)
    0x0820  version self-check (scanned region)
    0x1000  data region with decoys (stray mvn.w bytes, junk)
    0x1040  earlykey cave (48 zero bytes; filled when earlykey=patched)
    0x1100  near-miss 'lie' signature decoy
    0x1180  stray key-scan anchor decoy (bad prologue)
    0x4000  end of payload
"""

import struct

import t90_fw_tool as tool

PAYLOAD_SIZE = 0x4000

# --- header ---------------------------------------------------------------
DEV_TYPE = 0x0208
HW_REV = 10
APP_VER = 0x01
FILE_TYPE = 0xA0
DATA_LEN = 32
HDR_DATE = (26, 3, 4)  # 2026-03-04

# --- vector table ---------------------------------------------------------
INITIAL_SP = 0x20004DB8
RESET_VECTOR = 0x080052CD

# --- version self-check (inside the scanned code region) ------------------
VER_OFFSET = 0x0820  # ldrh halfword offset (>= 0x800)

# --- nolie ---------------------------------------------------------------
NOLIE_SIG_OFFSET = 0x04C0
NOLIE_PATCH_OFFSET = NOLIE_SIG_OFFSET + 10  # 6th halfword of the signature

# --- nologo --------------------------------------------------------------
LOGO_OFFSET = 0x04A0
LOGO_SURROUND_CODE = {
    -8: 0xBB30,   # CBNZ r0, <skip>
    -6: 0x2000,   # MOVS r0, #0
    -4: 0x493B,   # LDR r1, [PC, #imm]
    -2: 0x7008,   # STRB r0, [r1]
    +4: 0xE015,   # B <loop>
    +6: 0x2C00,   # CMP r4, #0
    +8: 0xDB00,   # BLT <redraw>
    +10: 0x2400,  # MOVS r4, #0
}

# --- fastlcd -------------------------------------------------------------
DELAY_OFFSET = 0x0400      # delay_ms() body (MS_DELAY_HEAD)
WAIT_A_OFFSET = 0x0430     # movs r0, #100  (post-reset settle, site A)
WAIT_B_OFFSET = 0x0436     # movs r0, #100  (post-reset settle, site B)
SLPOUT_OFFSET = 0x0460     # movs r0, #0x11
WAIT_C_OFFSET = 0x0466     # movs r0, #200   (SLPOUT -> DISPON, site C)
# The tool requires 'movs r0, #0x29' within 16 bytes of the SLPOUT
# anchor, so the cluster is packed tight (14 bytes total).
DISPON_OFFSET = 0x046C     # movs r0, #0x29

# --- Ver Info screen designation -----------------------------------------
# Format string of menu item 16 "Ver Info" in the real firmware:
#     b'T90%s  V:%1d.%1d.%1d'  (20 chars + NUL, free padding before the
#     next pool word, referenced by exactly one PC-relative ADR).
VER_INFO_OFFSET = 0x1200  # payload offset of the format string
VER_INFO_ADR_DELTA = 0x80  # adr -> string delta, as on real firmware
# Stamped shape: no " V" separator, then the letters (room for 8).
VER_INFO_STOCK = "T90%s%1d.%1d.%1d"
VER_INFO_STAMP_OFFSET = VER_INFO_OFFSET + len(VER_INFO_STOCK.encode())
# Vendor spelling on real firmware (double space + colon).
VER_INFO_VENDOR = "T90%s  V:%1d.%1d.%1d"
VER_INFO_LETTERS = (("nolie", "N"), ("nologo", "L"), ("fastlcd", "F"),
                      ("earlykey", "E"), ("fastpd", "P"),
                      ("fastsettle", "S"))
VER_INFO_STATES = ("stock", "patched")

# --- fastpd (PD pre-wait counter) ----------------------------------------
# v1.1.6 shape: ldr/ldrh/adds/uxth/ldr/strh/cmp #imm/bge/[b]/movs/ldr/
# strh + the movw #0x1388 task anchor; 28 bytes total. v1.1.4/v1.1.5
# ("absent") keep only the anchor, emulating a PD task without the
# counter. Must avoid the earlykey delay-caller field (0x0600+).
PD_OFFSET = 0x0500
PD_BLOCK_LEN = 28


def pd_prewait_bytes(wait=100):
    """PD pre-wait counter block with the given pass threshold."""
    out = bytearray()
    out += struct.pack("<H", 0x4810)   # ldr r0, [pc, #imm]
    out += bytes([0x00, 0x88])         # ldrh r0, [r0]
    out += bytes([0x40, 0x1C])         # adds r0, #1
    out += bytes([0x80, 0xB2])         # uxth r0, r0
    out += struct.pack("<H", 0x490E)   # ldr r1, [pc, #imm]
    out += bytes([0x08, 0x80])         # strh r0, [r1]
    out += struct.pack("<H", 0x2800 | wait)  # cmp r0, #wait
    out += bytes([0x00, 0xDA])         # bge <on>
    out += struct.pack("<H", 0xE003)   # b <past the reset> (miss path)
    out += bytes([0x00, 0x20])         # movs r0, #0
    out += struct.pack("<H", 0x490C)   # ldr r1, [pc, #imm]
    out += bytes([0x08, 0x80])         # strh r0, [r1]
    out += bytes(tool.PD_TASK_ANCHOR)  # movw r0, #0x1388 (task marker)
    assert len(out) == PD_BLOCK_LEN
    return bytes(out)


# --- fastsettle (PD stability thresholds) -------------------------------
# Same counter prefix as the pre-wait, closed by BLE (keep settling).
# Real firmware: cmp r0,#0x1E (31 passes, bit #0x10 path) and
# cmp r0,#0x28 (41 passes, bit #0x08 path); patched halves both.
SETTLE_A_OFFSET = 0x0540
SETTLE_B_OFFSET = 0x0560
SETTLE_BLOCK_LEN = 16


def settle_bytes(wait):
    """PD settle counter block with the given pass threshold."""
    out = bytearray()
    out += struct.pack("<H", 0x4810)   # ldr r0, [pc, #imm]
    out += bytes([0x00, 0x88])         # ldrh r0, [r0]
    out += bytes([0x40, 0x1C])         # adds r0, #1
    out += bytes([0x80, 0xB2])         # uxth r0, r0
    out += struct.pack("<H", 0x490E)   # ldr r1, [pc, #imm]
    out += bytes([0x08, 0x80])         # strh r0, [r1]
    out += struct.pack("<H", 0x2800 | wait)  # cmp r0, #wait
    out += bytes([0x05, 0xDD])         # ble <tail>
    assert len(out) == SETTLE_BLOCK_LEN
    return bytes(out)

# --- earlykey ------------------------------------------------------------
KEYSCAN_OFFSET = 0x0640    # key-scan routine entry (PUSH before anchor)
CAVE_OFF = tool.EARLYKEY_CAVE_ADDR - 0x08005000  # 0x1040
CAVE_LEN = 48              # len(build_earlykey_cave(...))

# delay_ms() callers: (movs_offset, imm). A/B are the fastlcd adjacent
# pair, C sits in the SLPOUT..DISPON cluster; the rest are ordinary
# boot-wait callers. 16 total, matching the real firmware. The BL of
# every caller sits at movs_offset + 2.
EXTRA_CALLERS = (
    (0x600, 20), (0x606, 5), (0x610, 50), (0x616, 30),
    (0x620, 10), (0x626, 15), (0x630, 25), (0x636, 40),
    (0x700, 60), (0x706, 2), (0x710, 35), (0x716, 8),
    (0x720, 7),
)
ALL_DELAY_CALLERS = (
    (WAIT_A_OFFSET, 100),
    (WAIT_B_OFFSET, 100),
    (WAIT_C_OFFSET, 200),
) + EXTRA_CALLERS

# --- decoys (must never be matched) --------------------------------------
DECOY_LOGO_OFFSET = 0x1000  # stray 6F F0 26 04 with wrong neighbours
# (no stray key-scan anchor decoy: find_keyscan refuses on a duplicate
# anchor, so a second copy would poison every payload. Ambiguity is
# tested by mutating a payload inside the test instead.)


def ver_info_stamped(nolie="stock", nologo="stock", fastlcd="stock",
                   earlykey="stock", fastpd="stock", fastsettle="stock"):
    """Ver Info format string with the designation letters for a patch set.

    Returns the full ASCII string (no NUL), e.g. 'T90%s%1d.%1d.%1dNLFEPS'.
    '-' marks a patch that is not present.  Raises KeyError on an
    unknown patch state (guards against builder/tool skew).
    Earlykey accepts 'clean' as an alias for 'stock' (its detector
    vocabulary).
    """
    if earlykey == "clean":
        earlykey = "stock"
    states = {"nolie": nolie, "nologo": nologo, "fastlcd": fastlcd,
              "earlykey": earlykey, "fastpd": fastpd,
              "fastsettle": fastsettle}
    unknown = [s for s in states.values() if s not in VER_INFO_STATES]
    if unknown:
        raise KeyError(f"unknown patch state: {unknown[0]!r}")
    letters = "".join(
        letter if states[patch] == "patched" else "-"
        for patch, letter in VER_INFO_LETTERS
    )
    return VER_INFO_STOCK + letters

# --- Thumb encoders -------------------------------------------------------


def b_bl(pc, target):
    """Encode a 32-bit Thumb BL at absolute address pc jumping to target.

    pc/target are absolute ARM addresses (image base 0x08005000).
    Round-trips with tool._bl_target().
    """
    d = target - (pc + 4)
    assert d % 2 == 0 and -(1 << 24) <= d < (1 << 24), d
    u = d & 0x1FFFFFF
    s = (u >> 24) & 1
    i1 = (u >> 23) & 1
    i2 = (u >> 22) & 1
    imm10 = (u >> 12) & 0x3FF
    imm11 = (u >> 1) & 0x7FF
    j1 = (~(i1 ^ s)) & 1
    j2 = (~(i2 ^ s)) & 1
    h1 = 0xF000 | (s << 10) | imm10
    h2 = 0xC000 | (j1 << 13) | 0x1000 | (j2 << 11) | imm11
    return struct.pack("<HH", h1, h2)


def _bl(pc, off, target_off):
    """BL helper with payload-relative offsets."""
    return b_bl(0x08005000 + pc, 0x08005000 + target_off)


# --- payload pieces -------------------------------------------------------


def version_check_bytes(version_int):
    """ldrh r0, [r0, #4]; cmp r0, #imm8; beq <skip>; <skip> ..."""
    return struct.pack("<HHH", 0x8880, 0x2800 | (version_int & 0xFF), 0xD000)


def nolie_signature_bytes(instruction):
    """The 8-halfword 'lie' function signature with the given slot-6 word."""
    return struct.pack(
        "<8H",
        tool.THUMB_PUSH_R4R5R6LR,   # PUSH {R4, R5, R6, LR}
        tool.THUMB_MOV_R4_R0,        # MOV R4, R0
        tool.THUMB_MOV_R5_R1,        # MOV R5, R1
        tool.THUMB_MOV_R6_R2,        # MOV R6, R2
        tool.THUMB_CMP_R5_R4,        # CMP R5, R4
        instruction,                 # BNE #1 (stock) / NOP (patched)
        tool.THUMB_MOV_R0_R4,        # MOV R0, R4
        tool.THUMB_POP_R4R5R6PC,     # POP {R4, R5, R6, PC}
    )


def logo_anim_bytes(init=None):
    """Logo animation init plus all eight verified neighbours."""
    if init is None:
        init = tool.LOGO_ANIM_ORIG
    words = dict(LOGO_SURROUND_CODE)
    words[0] = struct.unpack("<H", init[:2])[0]
    words[2] = struct.unpack("<H", init[2:])[0]
    # Neighbours span deltas -8..+10 -> 10 halfwords + 2 = 20 bytes.
    out = bytearray(20)
    for delta, hw in words.items():
        struct.pack_into("<H", out, 8 + delta, hw)
    return bytes(out)


def delay_pair_bytes(base, wait_a=100, wait_b=100):
    """Two adjacent `movs r0,#imm; bl delay_ms` sites (BL targets fixed
    to delay_ms from their own addresses). Length: 12 bytes."""
    out = struct.pack("<H", 0x2000 | wait_a)
    out += _bl(base + 2, 0, DELAY_OFFSET)
    out += struct.pack("<H", 0x2000 | wait_b)
    out += _bl(base + 8, 0, DELAY_OFFSET)
    assert len(out) == 12
    return out


def keyscan_bytes():
    """Key-scan routine: PUSH entry, unique anchor, probe, bx lr.

    find_keyscan walks back from the `mov.w r1, #0x8000` anchor to a
    PUSH and then requires `movs r1, #0x10` within the function.
    """
    return (
        struct.pack("<H", 0xB510)   # PUSH {r4, lr} (entry)
        + tool.KEYSCAN_ANCHOR       # mov.w r1, #0x8000 (anchor)
        + struct.pack("<HH", 0x2110, 0x4770)  # movs r1, #0x10; bx lr
    )


def extra_delay_callers_bytes():
    """Emit the 13 extra `movs r0,#imm; bl delay_ms` callers at 0x600+."""
    out = bytearray(0x72A - 0x600)
    for off, imm in EXTRA_CALLERS:
        rel = off - 0x600
        struct.pack_into("<H", out, rel, 0x2000 | imm)
        out[rel + 2:rel + 6] = _bl(off + 2, 0, DELAY_OFFSET)
    return bytes(out)


def lcd_init_bytes(wait_a=100, wait_b=100, wait_c=200):
    """delay_ms caller sites: A/B adjacent pair + SLPOUT..DISPON cluster."""
    out = bytearray()
    # 0x0430: sites A/B, 6 bytes apart (movs offset delta, as in the
    # real firmware)
    out += delay_pair_bytes(WAIT_A_OFFSET, wait_a, wait_b)
    # 0x043C..0x045F: gap up to the SLPOUT cluster
    out += bytes(SLPOUT_OFFSET - 0x043C)
    # 0x0460: SLPOUT cluster
    out += struct.pack("<H", 0x2011)          # movs r0, #0x11
    out += _bl(0x0462, 0, 0x0500)             # bl <lcd_cmd>
    out += struct.pack("<H", 0x2000 | wait_c)  # movs r0, #<wait>
    out += _bl(0x0468, 0, DELAY_OFFSET)       # bl <delay_ms>
    out += struct.pack("<H", 0x2029)          # movs r0, #0x29
    assert len(out) == DISPON_OFFSET + 2 - WAIT_A_OFFSET
    return bytes(out)


def build_payload(version_int=116, nolie="stock", nologo="stock",
                  fastlcd="stock", earlykey="clean", fastpd="stock",
                  fastsettle="stock", verinfo="auto", decoys=True):
    """Build a decrypted firmware payload.

    nolie/nologo/fastlcd: 'stock' or 'patched'.  fastlcd additionally
    accepts 'ambiguous' (a second 100/100 delay pair -> tool refuses).
    earlykey: 'clean' (callers target delay_ms directly) or 'patched'
    (callers redirected to a valid cave, as build_earlykey_cave makes).
    fastpd: 'stock' (pre-wait counter at 100 passes), 'patched' (5
    passes), or 'absent' (task anchor only, emulating v1.1.4/v1.1.5
    which settle the PD link without a pre-wait counter).
    fastsettle: 'stock' (settle thresholds at 31/41 passes) or 'patched'
    (16/21 passes).
    version_int: self-check immediate (114/115/116), or None to omit
    the pattern entirely.
    verinfo: 'auto' (stock string on stock builds, stamped on patched
    ones), 'stock' (always the vendor string), None (no Ver Info
    string at all), or an explicit ASCII string (already-stamped
    input, used for idempotency checks).
    """
    p = bytearray(PAYLOAD_SIZE)

    # Vector table
    struct.pack_into("<II", p, 0, INITIAL_SP, RESET_VECTOR)

    # delay_ms() body
    p[DELAY_OFFSET:DELAY_OFFSET + len(tool.MS_DELAY_HEAD)] = tool.MS_DELAY_HEAD

    # LCD wait sites
    if fastlcd == "ambiguous":
        # A second adjacent 100/100 delay pair -> the tool must refuse.
        p[0x0480:0x0480 + 12] = delay_pair_bytes(0x0480, 100, 100)
        site_c = 200
    else:
        site_c = 120 if fastlcd == "patched" else 200
    p[WAIT_A_OFFSET:DISPON_OFFSET + 2] = lcd_init_bytes(
        wait_c=site_c,
        wait_a=70 if fastlcd == "patched" else 100,
        wait_b=70 if fastlcd == "patched" else 100,
    )

    # Logo animation init (+ neighbours)
    init = tool.LOGO_ANIM_PATCH if nologo == "patched" else tool.LOGO_ANIM_ORIG
    p[LOGO_OFFSET - 8:LOGO_OFFSET + 12] = logo_anim_bytes(init)

    # 'lie' function
    slot6 = tool.THUMB_NOP if nolie == "patched" else 0xD101  # BNE #1
    p[NOLIE_SIG_OFFSET:NOLIE_SIG_OFFSET + 16] = nolie_signature_bytes(slot6)

    # Extra delay_ms callers and the key-scan routine
    p[0x600:0x72A] = extra_delay_callers_bytes()
    p[KEYSCAN_OFFSET:KEYSCAN_OFFSET + 10] = keyscan_bytes()

    # earlykey: redirect every delay_ms caller to the polling cave
    if earlykey == "patched":
        cave = tool.build_earlykey_cave(
            tool.EARLYKEY_CAVE_ADDR,
            0x08005000 + DELAY_OFFSET,
            0x08005000 + KEYSCAN_OFFSET,
        )
        assert len(cave) == CAVE_LEN, len(cave)
        p[CAVE_OFF:CAVE_OFF + CAVE_LEN] = cave
        for off, _imm in ALL_DELAY_CALLERS:
            p[off + 2:off + 6] = b_bl(
                0x08005000 + off + 2, tool.EARLYKEY_CAVE_ADDR
            )
    elif earlykey != "clean":
        raise ValueError(f"earlykey must be 'clean' or 'patched', got {earlykey!r}")

    # PD pre-wait counter (v1.1.6 shape) or task anchor only
    # (v1.1.4/v1.1.5 shape: no counter, nothing to shorten).
    if fastpd == "stock":
        p[PD_OFFSET:PD_OFFSET + PD_BLOCK_LEN] = pd_prewait_bytes(100)
    elif fastpd == "patched":
        p[PD_OFFSET:PD_OFFSET + PD_BLOCK_LEN] = pd_prewait_bytes(
            tool.PD_PREWAIT_NEW)
    elif fastpd == "absent":
        p[PD_OFFSET + PD_BLOCK_LEN - 4:PD_OFFSET + PD_BLOCK_LEN] = \
            bytes(tool.PD_TASK_ANCHOR)
    else:
        raise ValueError(f"fastpd must be 'stock', 'patched' or "
                         f"'absent', got {fastpd!r}")

    # PD settle thresholds (same shape on all versions).
    if fastsettle == "stock":
        p[SETTLE_A_OFFSET:SETTLE_A_OFFSET + SETTLE_BLOCK_LEN] = \
            settle_bytes(tool.PD_SETTLE_ORIG[0])
        p[SETTLE_B_OFFSET:SETTLE_B_OFFSET + SETTLE_BLOCK_LEN] = \
            settle_bytes(tool.PD_SETTLE_ORIG[1])
    elif fastsettle == "patched":
        p[SETTLE_A_OFFSET:SETTLE_A_OFFSET + SETTLE_BLOCK_LEN] = \
            settle_bytes(tool.PD_SETTLE_NEW[0])
        p[SETTLE_B_OFFSET:SETTLE_B_OFFSET + SETTLE_BLOCK_LEN] = \
            settle_bytes(tool.PD_SETTLE_NEW[1])
    else:
        raise ValueError(f"fastsettle must be 'stock' or 'patched', "
                         f"got {fastsettle!r}")

    # Version self-check inside the scanned code region
    if version_int is not None:
        p[VER_OFFSET:VER_OFFSET + 6] = version_check_bytes(version_int)

    # Ver Info format string (vendor spelling or stamped) + its single
    # adr r1 reference (anchored on the adr -> string delta, as on real
    # firmware). Stock builds keep the vendor string verbatim; any patch
    # presence collapses the double space, drops the colon and appends
    # the letters. The stamps land inside the free padding, so the tail
    # pool words and every code address stay byte-identical.
    if verinfo == "auto":
        ek_state = "patched" if earlykey == "patched" else "stock"
        any_patched = "patched" in (nolie, nologo, fastlcd, ek_state,
                                    fastpd, fastsettle)
        body = ver_info_stamped(nolie, nologo, fastlcd, ek_state, fastpd,
                                fastsettle) \
            if any_patched else VER_INFO_VENDOR
    elif verinfo == "stock":
        body = VER_INFO_VENDOR
    elif verinfo is None:
        body = None
    else:
        body = verinfo
    if body is not None:
        raw = body.encode("ascii") + b"\x00"
        assert len(raw) <= 24, f"Ver Info string too long: {body!r}"
        p[VER_INFO_OFFSET:VER_INFO_OFFSET + len(raw)] = raw
        # Nonzero literal-pool word right after the padding, as on real
        # firmware (the finder requires it: string + NUL + <=4 zero
        # bytes + a nonzero word).
        struct.pack_into("<I", p, VER_INFO_OFFSET + 24, 0x20000280)
        string_addr = 0x08005000 + VER_INFO_OFFSET
        adr_arm = (string_addr - VER_INFO_ADR_DELTA - 4) & ~3
        adr_off = adr_arm - 0x08005000  # payload-relative
        # Thumb ADR: target = (PC & ~3) + (imm8 << 2), PC = adr + 4.
        delta = string_addr - ((adr_arm + 4) & ~3)
        assert 0 < delta <= 0x3FC and delta % 4 == 0, hex(delta)
        assert not any(p[adr_off:adr_off + 2]), \
            "Ver Info adr slot clashes with another pattern"
        struct.pack_into("<H", p, adr_off, 0xA100 | (delta >> 2))  # adr r1

    # Decoys in the data region
    if decoys:
        # Stray mvn.w r4, #0x26 bytes whose neighbours are garbage.
        p[DECOY_LOGO_OFFSET:DECOY_LOGO_OFFSET + 4] = tool.LOGO_ANIM_ORIG
        p[DECOY_LOGO_OFFSET - 8:DECOY_LOGO_OFFSET] = bytes(8)
        p[DECOY_LOGO_OFFSET + 4:DECOY_LOGO_OFFSET + 24] = bytes(20)
        # Near-miss 'lie' signature: one MOV differs (MOV R5, R0).
        p[0x1100:0x1110] = nolie_signature_bytes(0xD101)
        p[0x1100 + 4:0x1100 + 6] = struct.pack("<H", 0x4605)  # MOV R5, R0

    return bytes(p)


def build_header(payload_size=PAYLOAD_SIZE, dev_type=DEV_TYPE,
                 hw_rev=HW_REV, app_ver=APP_VER, file_type=FILE_TYPE,
                 data_len=DATA_LEN, date=HDR_DATE, bin_size=None):
    """Build the 13-byte FirmInfo header. bin_size defaults to payload_size."""
    year, month, day = date
    buf = struct.pack(
        "<HBBBBI", dev_type, hw_rev, app_ver, file_type,
        data_len, payload_size if bin_size is None else bin_size,
    )
    buf += struct.pack("<BBB", year, month, day)
    assert len(buf) == 13
    return buf


def build_atk(payload=None, **header_kw):
    """Build a complete .atk file: header + XOR-0xFF(payload)."""
    if payload is None:
        payload = build_payload()
    return build_header(payload_size=len(payload), **header_kw) + tool.xor_decrypt(
        payload
    )