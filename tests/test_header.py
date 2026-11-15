"""Tests for parse_atk_header."""

import struct

import pytest

import t90_fw_tool as tool
import synthetic


def test_valid_header():
    data = synthetic.build_atk()
    header = tool.parse_atk_header(data)
    assert header["dev_type"] == 0x0208
    assert header["hw_rev"] == synthetic.HW_REV
    assert header["app_ver"] == 0x01
    assert header["file_type"] == 0xA0
    assert header["data_len"] == 32
    assert header["bin_size"] == synthetic.PAYLOAD_SIZE
    assert header["date"] == "2026-03-04"


def test_header_fields_match_bytes():
    data = synthetic.build_atk()
    dev_type, hw_rev, app_ver, file_type, data_len, bin_size = (
        struct.unpack_from("<HBBBBI", data, 0)
    )
    year, month, day = struct.unpack_from("<BBB", data, 10)
    header = tool.parse_atk_header(data)
    assert header["dev_type"] == dev_type
    assert header["hw_rev"] == hw_rev
    assert header["app_ver"] == app_ver
    assert header["file_type"] == file_type
    assert header["data_len"] == data_len
    assert header["bin_size"] == bin_size
    assert header["date"] == f"20{year:02d}-{month:02d}-{day:02d}"


def test_too_small_file():
    with pytest.raises(ValueError, match="too small"):
        tool.parse_atk_header(b"\x08\x02" + b"\x00" * 10)  # 12 bytes


def test_empty_file():
    with pytest.raises(ValueError, match="too small"):
        tool.parse_atk_header(b"")


def test_wrong_dev_type():
    data = synthetic.build_atk(dev_type=0x0308)
    with pytest.raises(ValueError, match="0x0308"):
        tool.parse_atk_header(data)


def test_custom_header_fields():
    data = synthetic.build_atk(
        hw_rev=7, app_ver=0x02, file_type=0xB0, data_len=64,
        date=(30, 12, 31),
    )
    header = tool.parse_atk_header(data)
    assert header["hw_rev"] == 7
    assert header["app_ver"] == 0x02
    assert header["file_type"] == 0xB0
    assert header["data_len"] == 64
    assert header["date"] == "2030-12-31"


def test_file_type_names():
    assert tool.FILE_TYPE_NAMES[0xA0] == "Application"
    assert tool.FILE_TYPE_NAMES[0xA1] == "Logo"
    assert tool.FILE_TYPE_NAMES[0xB0] == "Bootloader"


def test_bin_size_mismatch_is_parsed():
    # bin_size lies about the payload length: parsing still succeeds,
    # cmd_info reports the mismatch as a warning (covered in test_cli).
    data = synthetic.build_atk(bin_size=synthetic.PAYLOAD_SIZE // 2)
    header = tool.parse_atk_header(data)
    assert header["bin_size"] == synthetic.PAYLOAD_SIZE // 2
    assert len(data) != 13 + header["bin_size"]