"""Tests for version formatting, filename parsing, and code scanning."""

import pytest

import t90_fw_tool as tool
import synthetic


# --- format_version -------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [(114, "1.1.4"), (115, "1.1.5"), (116, "1.1.6"), (100, "1.0.0"),
     (120, "1.2.0"), (999, "9.9.9")],
)
def test_format_version(value, expected):
    assert tool.format_version(value) == expected


@pytest.mark.parametrize("value", [0, 99, 1000, -5])
def test_format_version_out_of_range_passthrough(value):
    assert tool.format_version(value) == str(value)


# --- parse_version_from_filename -----------------------------------------


@pytest.mark.parametrize(
    "name,expected",
    [
        ("t90_v1.1.4.atk", "1.1.4"),
        ("t90_v1.1.6_nolie_nologo_fastlcd.atk", "1.1.6"),
        ("maximize_t90_v1.1.4.atk", "1.1.4"),
        ("T90-V2.0.3.bin", "2.0.3"),
        ("t90_v1.1.4_nolie_earlykey.atk", "1.1.4"),
        ("/some/path/t90_v1.1.5.atk", "1.1.5"),
    ],
)
def test_parse_version_from_filename(name, expected):
    assert tool.parse_version_from_filename(name) == expected


@pytest.mark.parametrize(
    "name", ["t90.atk", "firmware_v1.atk", "other_v1.1.atk", "readme.md"]
)
def test_parse_version_from_filename_no_match(name):
    assert tool.parse_version_from_filename(name) is None


# --- version_in_filename --------------------------------------------------


def test_version_in_filename_dotted():
    assert tool.version_in_filename("t90_v1.1.4.atk", "1.1.4")
    assert tool.version_in_filename("t90_1.1.4_nolie.atk", "1.1.4")


def test_version_in_filename_absent():
    assert not tool.version_in_filename("t90_nolie.atk", "1.1.4")


def test_version_in_filename_none_version():
    assert not tool.version_in_filename("t90_v1.1.4.atk", None)


def test_version_in_filename_no_partial_digit_match():
    # '1.1.4' must not match inside '11.1.40' (boundary lookaround).
    assert not tool.version_in_filename("t90_v11.1.40.atk", "1.1.4")


# --- make_versioned_filename ----------------------------------------------


def test_make_versioned_filename_inserts():
    assert (
        tool.make_versioned_filename("t90_nolie.atk", "1.1.4")
        == "t90_nolie_v1.1.4.atk"
    )


def test_make_versioned_filename_version_present():
    assert (
        tool.make_versioned_filename("t90_v1.1.4.atk", "1.1.4")
        == "t90_v1.1.4.atk"
    )


def test_make_versioned_filename_unknown_version():
    assert tool.make_versioned_filename("t90.atk", None) == "t90.atk"


def test_make_versioned_filename_no_extension():
    assert (
        tool.make_versioned_filename("t90_nolie", "1.1.6")
        == "t90_nolie_v1.1.6"
    )


def test_make_versioned_filename_from_filename_version():
    # Version known only from the name is not duplicated.
    assert (
        tool.make_versioned_filename("t90_v1.1.6_nolie.atk", "1.1.6")
        == "t90_v1.1.6_nolie.atk"
    )


# --- find_firmware_version ------------------------------------------------


def test_find_version_in_stock_payload():
    payload = synthetic.build_payload(version_int=116)
    checks = tool.find_firmware_version(payload)
    assert checks == [(synthetic.VER_OFFSET, 116)]


@pytest.mark.parametrize("version_int", [114, 115, 116])
def test_find_version_immediates(version_int):
    payload = synthetic.build_payload(version_int=version_int)
    checks = tool.find_firmware_version(payload)
    assert len(checks) == 1
    assert checks[0][1] == version_int


def test_find_version_absent():
    payload = synthetic.build_payload(version_int=None)
    assert tool.find_firmware_version(payload) == []


def test_find_version_outside_scan_window():
    # Below 0x800 the scanner does not look.
    payload = bytearray(synthetic.build_payload(version_int=None))
    payload[0x200:0x206] = synthetic.version_check_bytes(114)
    assert tool.find_firmware_version(bytes(payload)) == []


def test_determine_firmware_version_prefers_code():
    payload = synthetic.build_payload(version_int=115)
    assert (
        tool.determine_firmware_version(payload, "t90_v1.1.4.atk") == "1.1.5"
    )


def test_determine_firmware_version_falls_back_to_filename():
    payload = synthetic.build_payload(version_int=None)
    assert (
        tool.determine_firmware_version(payload, "t90_v1.1.4.atk") == "1.1.4"
    )


def test_determine_firmware_version_unknown_everywhere():
    payload = synthetic.build_payload(version_int=None)
    assert tool.determine_firmware_version(payload, "firmware.atk") is None


def test_multiple_version_matches_warns(capsys):
    payload = bytearray(synthetic.build_payload(version_int=114))
    payload[0x0900:0x0906] = synthetic.version_check_bytes(115)
    version = tool.determine_firmware_version(bytes(payload), "t90.atk")
    captured = capsys.readouterr()
    assert "multiple version check matches" in captured.err
    assert version == "1.1.4"  # lowest of the sorted unique values