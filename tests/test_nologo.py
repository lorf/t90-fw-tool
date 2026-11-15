"""Tests for the boot logo animation scanner (nologo patch)."""

import struct

import t90_fw_tool as tool
import synthetic


def test_find_stock_anim():
    payload = synthetic.build_payload(nologo="stock")
    assert tool.find_logo_anim(payload) == synthetic.LOGO_OFFSET


def test_find_patched_anim():
    payload = synthetic.build_payload(nologo="patched")
    assert tool.find_logo_anim(payload) is None
    assert tool.find_logo_anim_patch(payload) == synthetic.LOGO_OFFSET


def test_stock_has_no_patch():
    payload = synthetic.build_payload(nologo="stock")
    assert tool.find_logo_anim_patch(payload) is None


def test_decoy_bytes_are_skipped():
    # The data-region decoy at 0x1000 has wrong neighbours; the scanner
    # must walk past it and still find the real site (or nothing).
    payload = synthetic.build_payload(nologo="stock")
    raw = bytes(payload)
    assert (
        raw.find(tool.LOGO_ANIM_ORIG, synthetic.DECOY_LOGO_OFFSET)
        == synthetic.DECOY_LOGO_OFFSET
    )
    assert tool.find_logo_anim(payload) == synthetic.LOGO_OFFSET


def test_only_decoy_present_returns_none():
    payload = synthetic.build_payload(nologo="patched")
    # stock anim gone; only the decoy bytes remain -> None
    assert tool.find_logo_anim(payload) is None


def test_verify_logo_anim_all_ok():
    payload = synthetic.build_payload(nologo="stock")
    results = tool.verify_logo_anim(payload, synthetic.LOGO_OFFSET)
    assert results is not None
    assert all(ok for _, _, _, ok in results)
    assert len(results) == len(tool.LOGO_ANIM_SURROUND)


def test_verify_logo_anim_out_of_bounds():
    payload = synthetic.build_payload()
    assert tool.verify_logo_anim(payload, 4) is None  # idx < 8
    assert tool.verify_logo_anim(payload, len(payload) - 4) is None


def test_verify_logo_anim_neighbour_corruption_fails():
    # Corrupt each neighbour in turn; verification must flag it.
    for delta, _, _, desc in tool.LOGO_ANIM_SURROUND:
        payload = bytearray(synthetic.build_payload(nologo="stock"))
        pos = synthetic.LOGO_OFFSET + delta
        struct.pack_into("<H", payload, pos, 0x0000)
        results = tool.verify_logo_anim(bytes(payload), synthetic.LOGO_OFFSET)
        failed = [d for d, _, _, ok in results if not ok]
        assert failed, f"corruption at delta {delta} ({desc}) not detected"


def test_corrupted_neighbour_blocks_find():
    # An orig-bytes candidate whose neighbour is wrong must not be found.
    payload = bytearray(synthetic.build_payload(nologo="stock"))
    pos = synthetic.LOGO_OFFSET + 8  # BLT <redraw>
    struct.pack_into("<H", payload, pos, 0x2400)  # MOVS r4, #0 (wrong op)
    assert tool.find_logo_anim(bytes(payload)) is None


def test_ldr_register_must_be_r1():
    # LDR Rt field wrong (r2 instead of r1) -> candidate rejected.
    payload = bytearray(synthetic.build_payload(nologo="stock"))
    pos = synthetic.LOGO_OFFSET - 4
    struct.pack_into("<H", payload, pos, 0x4A3B)  # LDR r2, [PC, #imm]
    results = tool.verify_logo_anim(bytes(payload), synthetic.LOGO_OFFSET)
    ldr = [r for r in results if "LDR" in r[0]]
    assert ldr and not ldr[0][3]


def test_logo_patch_bytes():
    assert tool.LOGO_ANIM_PATCH == bytes([0x02, 0x24, 0x00, 0xBF])
    assert tool.LOGO_ANIM_ORIG == bytes([0x6F, 0xF0, 0x26, 0x04])


def test_verify_result_format():
    payload = synthetic.build_payload(nologo="stock")
    for desc, expected, actual, ok in tool.verify_logo_anim(
        payload, synthetic.LOGO_OFFSET
    ):
        assert isinstance(desc, str) and desc
        assert expected.startswith("0x")
        assert actual.startswith("0x")
        assert isinstance(ok, bool)