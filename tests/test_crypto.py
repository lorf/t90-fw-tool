"""Tests for xor_decrypt."""

import t90_fw_tool as tool


def test_round_trip():
    data = bytes(range(256)) * 4
    assert tool.xor_decrypt(tool.xor_decrypt(data)) == data


def test_xor_key_is_0xff():
    assert tool.XOR_KEY == 0xFF
    assert tool.xor_decrypt(b"\x00\x01\x7F\x80\xFF") == b"\xFF\xFE\x80\x7F\x00"


def test_empty():
    assert tool.xor_decrypt(b"") == b""


def test_atk_payload_round_trip():
    # Extracted .bin must be decryptable back to the on-disk payload.
    encrypted = bytes([0x12, 0x34, 0xFF, 0x00, 0xAB])
    decrypted = tool.xor_decrypt(encrypted)
    assert tool.xor_decrypt(decrypted) == encrypted