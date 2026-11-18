"""Tests for the Ver Info screen designation stamp (menu item 16).

The tool rewrites the stock format string 'T90%s  V:%1d.%1d.%1d' to
'T90%s V%1d.%1d.%1d<letters>' (N=nolie, L=nologo, F=fastlcd,
E=earlykey, P=fastpd, '-'=absent), reusing the padding inside the existing footprint.
"""

import struct

import pytest

import t90_fw_tool as tool
import synthetic
from conftest import FIRMWARE_DIR


def payload_of(atk_bytes):
    return tool.xor_decrypt(atk_bytes[13:])


def read(path):
    with open(path, "rb") as f:
        return f.read()


def diff_offsets(a, b):
    return {i for i in range(min(len(a), len(b))) if a[i] != b[i]}


def stamped_payload(**kw):
    """Stock synthetic payload with the given patch states applied."""
    kw.setdefault("verinfo", "auto")
    return bytearray(synthetic.build_payload(**kw))


# --- finder ---------------------------------------------------------------


def test_find_ver_info_stock_synthetic():
    payload = synthetic.build_payload()
    off = tool.find_ver_info(payload)
    assert off == synthetic.VER_INFO_OFFSET
    assert tool.ver_info_letters(payload, off) is None


def test_find_ver_info_absent():
    payload = synthetic.build_payload(verinfo=None)
    assert tool.find_ver_info(payload) is None
    assert tool.ver_info_letters(payload) is None


def test_find_ver_info_needs_single_adr_reference():
    # A second string of the right shape but without an ADR reference
    # must fail closed (ambiguous -> None), not pick one.
    payload = bytearray(synthetic.build_payload())
    decoy = b"T90%s  V:%1d.%1d.%1d\x00" + bytes(4) + struct.pack("<I", 1)
    at = 0x1400
    payload[at:at + len(decoy)] = decoy
    assert tool.find_ver_info(bytes(payload)) is None


def test_find_ver_info_ignores_wrong_shape():
    # Near-miss strings (extra char before NUL) are not candidates.
    payload = bytearray(synthetic.build_payload())
    at = 0x1400
    payload[at:at + 22] = b"T90%s  V:%1d.%1d.%1dX\x00"
    assert tool.find_ver_info(bytes(payload)) == synthetic.VER_INFO_OFFSET


def test_find_ver_info_dangling_adr_refused():
    # Zeroing the ADR slot removes the only reference -> None.
    payload = bytearray(synthetic.build_payload())
    string_addr = 0x08005000 + synthetic.VER_INFO_OFFSET
    adr_addr = (string_addr - synthetic.VER_INFO_ADR_DELTA - 4) & ~3
    adr_off = adr_addr - 0x08005000
    assert struct.unpack_from("<H", payload, adr_off)[0] & 0xF800 == 0xA000
    struct.pack_into("<H", payload, adr_off, 0xBF00)  # NOP, not ADR
    assert tool.find_ver_info(bytes(payload)) is None


# --- letters / stamping ----------------------------------------------------


@pytest.mark.parametrize(
    "states,expected",
    [
        (("stock", "stock", "stock", "stock", "stock"), "-----"),
        (("patched", "stock", "stock", "stock", "stock"), "N----"),
        (("stock", "patched", "stock", "stock", "stock"), "-L---"),
        (("stock", "stock", "patched", "stock", "stock"), "--F--"),
        (("stock", "stock", "stock", "patched", "stock"), "---E-"),
        (("stock", "stock", "stock", "stock", "patched"), "----P"),
        (("patched", "patched", "stock", "stock", "stock"), "NL---"),
        (("patched", "stock", "patched", "stock", "patched"), "N-F-P"),
        (("stock", "patched", "patched", "stock", "stock"), "-LF--"),
        (("patched", "patched", "patched", "patched", "patched"), "NLFEP"),
        (("patched", "patched", "patched", "stock", "patched"), "NLF-P"),
    ],
)
def test_ver_info_expected_letters(states, expected):
    assert tool.ver_info_expected_letters(*states) == expected


def test_stamp_ver_info_writes_in_place():
    payload = bytearray(synthetic.build_payload())
    off = synthetic.VER_INFO_OFFSET
    stamped = tool.stamp_ver_info(payload, off, "NLFEP")
    assert stamped == "T90%s V%1d.%1d.%1dNLFEP"
    # String start and its ADR reference are untouched; the stamp fits
    # the old footprint (stock 20 chars -> stamped 22 chars + NUL,
    # 23 of 24 allowed).
    assert bytes(payload[off:off + 6]) == b"T90%s "
    assert len(stamped) + 1 <= tool.VER_INFO_MAX_LEN
    assert tool.find_ver_info(bytes(payload)) == off
    assert tool.ver_info_letters(bytes(payload), off) == "NLFEP"
    # The letters sit exactly at the documented stamp offset.
    assert bytes(payload[synthetic.VER_INFO_STAMP_OFFSET:
                         synthetic.VER_INFO_STAMP_OFFSET + 5]) == b"NLFEP"


def test_stamp_ver_info_refuses_nonstock():
    payload = bytearray(synthetic.build_payload())
    tool.stamp_ver_info(payload, synthetic.VER_INFO_OFFSET, "N----")
    with pytest.raises(ValueError, match="already stamped"):
        tool.stamp_ver_info(payload, synthetic.VER_INFO_OFFSET, "NLFEP")


def test_unstamp_restores_vendor_spelling():
    payload = bytearray(synthetic.build_payload(
        nolie="patched", nologo="patched"))
    off = synthetic.VER_INFO_OFFSET
    assert tool.ver_info_letters(bytes(payload), off) == "NL---"
    restored = tool.unstamp_ver_info(payload, off)
    assert restored == synthetic.VER_INFO_VENDOR
    assert bytes(payload[off:off + len(synthetic.VER_INFO_VENDOR) + 1]) == \
        synthetic.VER_INFO_VENDOR.encode() + b"\x00"
    assert tool.ver_info_letters(bytes(payload), off) is None
    assert tool.find_ver_info(bytes(payload)) == off


def test_unstamp_refuses_unstamped():
    payload = bytearray(synthetic.build_payload())
    with pytest.raises(ValueError, match="holds no stamp"):
        tool.unstamp_ver_info(payload, synthetic.VER_INFO_OFFSET)


def test_stamp_unstamp_roundtrip():
    payload = bytearray(synthetic.build_payload())
    before = bytes(payload)
    tool.stamp_ver_info(payload, synthetic.VER_INFO_OFFSET, "N-F--")
    tool.unstamp_ver_info(payload, synthetic.VER_INFO_OFFSET)
    assert bytes(payload) == before


# --- patch integration -----------------------------------------------------


def test_patch_only_nolie_stamps_N_dashes(atk_file, tmp_path, cli):
    path = atk_file()
    code, out, err = cli("patch", "--only", "nolie", path)
    assert code == 0, err
    patched = payload_of(read(tmp_path / "t90_v1.1.6_nolie.atk"))
    assert tool.ver_info_letters(patched) == "N----"


def test_patch_skip_fastlcd_stamps_NL_dash(atk_file, tmp_path, cli):
    path = atk_file()
    code, out, err = cli("patch", "--skip", "fastlcd", path)
    assert code == 0, err
    patched = payload_of(read(tmp_path / "t90_v1.1.6_nolie_nologo_fastpd.atk"))
    assert tool.ver_info_letters(patched) == "NL--P"


def test_patch_all_stamps_NLFP(atk_file, tmp_path, cli):
    path = atk_file()
    code, out, err = cli("patch", path)
    assert code == 0, err
    out_path = tmp_path / "t90_v1.1.6_nolie_nologo_fastlcd_fastpd.atk"
    patched = payload_of(read(out_path))
    assert tool.ver_info_letters(patched) == "NLF-P"
    code, out2, _ = cli("info", str(out_path))
    assert code == 0
    assert "verinfo:  'NLF-P'" in out2


def test_patch_only_earlykey_stamps_E(atk_file, tmp_path, cli):
    path = atk_file()
    code, out, err = cli("patch", "--only", "earlykey", path)
    assert code == 0, err
    patched = payload_of(read(tmp_path / "t90_v1.1.6_earlykey.atk"))
    assert tool.ver_info_letters(patched) == "---E-"


def test_patch_all_with_earlykey_stamps_NLFEP(atk_file, tmp_path, cli):
    path = atk_file()
    code, out, err = cli(
        "patch", "--only", "nolie,nologo,fastlcd,earlykey,fastpd", path)
    assert code == 0, err
    out_path = tmp_path / "t90_v1.1.6_nolie_nologo_fastlcd_earlykey_fastpd.atk"
    assert out_path.exists(), out
    patched = payload_of(read(out_path))
    assert tool.ver_info_letters(patched) == "NLFEP"
    # Stamped string is 23 chars + NUL = 24 bytes in the 24-byte window.
    off = tool.find_ver_info(patched)
    end = patched.index(b"\x00", off)
    assert end - off == 23
    assert end + 1 - off <= tool.VER_INFO_MAX_LEN


def test_patch_is_idempotent_on_stamped_input(atk_file, tmp_path, cli):
    path = atk_file(payload=synthetic.build_payload(
        nolie="patched", nologo="patched", fastlcd="patched",
        fastpd="patched"))
    before = payload_of(read(path))
    assert tool.ver_info_letters(before) == "NLF-P"  # builder stamps it
    code, out, err = cli("patch", path)
    assert code == 0, err
    after = payload_of(
        read(tmp_path / "t90_v1.1.6_nolie_nologo_fastlcd_fastpd.atk"))
    assert after == before
    assert "already stamped" in out


def test_patch_stamp_updates_on_incremental_run(atk_file, tmp_path, cli):
    # A stamp from an earlier subset run is normalized to the new
    # effective set instead of aborting.
    payload = synthetic.build_payload(
        nolie="patched", nologo="patched",
        verinfo="T90%s V%1d.%1d.%1dN----")
    path = atk_file(payload=payload)
    code, out, err = cli("patch", "--only", "nolie", path)
    assert code == 0, err
    assert "updated 'N----' -> 'T90%s V%1d.%1d.%1dNL---'" in out
    patched = payload_of(read(tmp_path / "t90_v1.1.6_nolie_nologo.atk"))
    assert tool.ver_info_letters(patched) == "NL---"


def test_patch_garbage_ver_info_errors(atk_file, cli):
    # A Ver-Info-shaped string with no parseable stamp aborts the run.
    payload = bytearray(synthetic.build_payload())
    off = synthetic.VER_INFO_OFFSET
    payload[off:off + 24] = b"T90%s V%1d.%1d.%1dXX\x00" + bytes(3)
    path = atk_file(payload=bytes(payload))
    code, _, err = cli("patch", "--only", "nolie", path)
    assert code == 1
    assert "Ver Info string pattern not found" in err


def test_patch_missing_ver_info_errors(atk_file, cli):
    path = atk_file(payload=synthetic.build_payload(verinfo=None))
    code, _, err = cli("patch", "--only", "nolie", path)
    assert code == 1
    assert "Ver Info string pattern not found" in err


# --- info integration ------------------------------------------------------


def test_info_stock_shows_no_stamp(atk_file, cli):
    code, out, _ = cli("info", atk_file())
    assert code == 0
    assert "verinfo:  '(none)'" in out


def test_info_unknown_ver_info(atk_file, cli):
    path = atk_file(payload=bytes(synthetic.PAYLOAD_SIZE))
    code, out, _ = cli("info", path)
    assert code == 0
    assert "verinfo:  unknown" in out
