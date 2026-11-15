"""Tests for the LCD init wait scanner (fastlcd patch)."""

import struct

import t90_fw_tool as tool
import synthetic


def test_find_ms_delay():
    payload = synthetic.build_payload()
    assert tool.find_ms_delay(payload) == synthetic.DELAY_OFFSET


def test_find_ms_delay_absent():
    # No SLPOUT..DISPON anchor -> None.
    payload = bytearray(synthetic.build_payload())
    payload[synthetic.SLPOUT_OFFSET] = 0x00  # break 'movs r0, #0x11'
    assert tool.find_ms_delay(bytes(payload)) is None


def test_find_ms_delay_wrong_callee():
    # Anchor present but the delay BL targets something else.
    payload = bytearray(synthetic.build_payload())
    bl = synthetic.b_bl(
        0x08005000 + synthetic.WAIT_C_OFFSET + 2, 0x08005000 + 0x3000
    )
    payload[synthetic.WAIT_C_OFFSET + 2:synthetic.WAIT_C_OFFSET + 6] = bl
    assert tool.find_ms_delay(bytes(payload)) is None


def test_lcd_waits_stock():
    payload = synthetic.build_payload(fastlcd="stock")
    waits = tool.find_lcd_waits(payload, patched=False)
    assert waits == [
        (synthetic.WAIT_A_OFFSET, 100),
        (synthetic.WAIT_B_OFFSET, 100),
        (synthetic.WAIT_C_OFFSET, 200),
    ]


def test_lcd_waits_patched():
    payload = synthetic.build_payload(fastlcd="patched")
    waits = tool.find_lcd_waits(payload, patched=True)
    assert waits == [
        (synthetic.WAIT_A_OFFSET, 70),
        (synthetic.WAIT_B_OFFSET, 70),
        (synthetic.WAIT_C_OFFSET, 120),
    ]


def test_lcd_waits_cross_mode_none():
    payload = synthetic.build_payload(fastlcd="stock")
    assert tool.find_lcd_waits(payload, patched=True) is None
    payload = synthetic.build_payload(fastlcd="patched")
    assert tool.find_lcd_waits(payload, patched=False) is None


def test_lcd_waits_no_delay_at_all():
    assert tool.find_lcd_waits(bytes(0x2000), patched=False) is None


def test_lcd_waits_ambiguous_pair_refused():
    # Two 100/100 pairs -> the tool must refuse (safety).
    payload = synthetic.build_payload(fastlcd="ambiguous")
    assert tool.find_lcd_waits(payload, patched=False) is None


def test_lcd_wait_constants():
    assert tool.LCD_WAIT_ORIG == (100, 100, 200)
    assert tool.LCD_WAIT_PATCH == (70, 70, 120)


def test_patch_sites_are_single_halfwords():
    # All three sites must be `movs r0, #imm` (0x20xx) so a patch
    # writes exactly one halfword each.
    payload = synthetic.build_payload(fastlcd="stock")
    for off, imm in tool.find_lcd_waits(payload, patched=False):
        hw = struct.unpack_from("<H", payload, off)[0]
        assert hw == 0x2000 | imm


def test_bl_target_round_trip():
    payload = bytearray(synthetic.PAYLOAD_SIZE)
    pc = 0x08005000 + 0x1234
    target = 0x08005000 + synthetic.DELAY_OFFSET
    payload[0x1234:0x1238] = synthetic.b_bl(pc, target)
    assert tool._bl_target(bytes(payload), pc) == target


def test_bl_target_not_a_bl():
    payload = bytes(synthetic.PAYLOAD_SIZE)
    assert tool._bl_target(payload, 0x08005000) is None