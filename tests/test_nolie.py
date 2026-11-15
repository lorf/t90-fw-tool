"""Tests for the 'lie' function signature scanner (nolie patch)."""

import struct

import t90_fw_tool as tool
import synthetic


def test_find_stock_signature():
    payload = synthetic.build_payload(nolie="stock")
    off = tool.find_function_location(payload, instruction=None)
    assert off == synthetic.NOLIE_PATCH_OFFSET
    # The halfword found there really is BNE #1.
    hw = struct.unpack_from("<H", payload, off)[0]
    assert hw == 0xD101


def test_find_patched_signature():
    payload = synthetic.build_payload(nolie="patched")
    off = tool.find_function_location(payload, instruction=tool.THUMB_NOP)
    assert off == synthetic.NOLIE_PATCH_OFFSET


def test_stock_not_matched_as_patched():
    payload = synthetic.build_payload(nolie="stock")
    assert (
        tool.find_function_location(payload, instruction=tool.THUMB_NOP)
        is None
    )


def test_patched_not_matched_as_stock():
    payload = synthetic.build_payload(nolie="patched")
    assert tool.find_function_location(payload, instruction=None) is None


def test_near_miss_signature_rejected():
    # The decoy at 0x1100 differs by one MOV and must not match.
    payload = synthetic.build_payload(nolie="stock")
    offs = []
    for instr in (None, tool.THUMB_NOP):
        off = tool.find_function_location(payload, instruction=instr)
        if off is not None:
            offs.append(off)
    assert offs == [synthetic.NOLIE_PATCH_OFFSET]


def test_no_signature_at_all():
    payload = bytes(0x2000)
    assert tool.find_function_location(payload, instruction=None) is None
    assert (
        tool.find_function_location(payload, instruction=tool.THUMB_NOP)
        is None
    )


def test_empty_payload():
    assert tool.find_function_location(b"", instruction=None) is None


def test_wrong_bne_offset_rejected():
    # BNE with a different imm must not match the strict 0xD101 check.
    payload = bytearray(synthetic.build_payload(nolie="stock"))
    struct.pack_into(
        "<H", payload, synthetic.NOLIE_PATCH_OFFSET, 0xD102  # BNE #2
    )
    assert tool.find_function_location(bytes(payload), instruction=None) is None


def test_instruction_constants():
    assert tool.THUMB_NOP == 0xBF00
    assert tool.THUMB_PUSH_R4R5R6LR == 0xB570
    assert tool.THUMB_POP_R4R5R6PC == 0xBD70