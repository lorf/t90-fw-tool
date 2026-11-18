"""Sanity tests against the real firmware archive.

These tests verify that the synthetic model in synthetic.py matches the
behaviour of the tool on actual .atk files from the archive.

Skipped automatically when the archive directory is missing
(override with T90_FIRMWARE_DIR).
"""

import glob
import os

import pytest

import t90_fw_tool as tool
from conftest import FIRMWARE_DIR

pytestmark = pytest.mark.archive


def _archive_files(pattern="*.atk"):
    return sorted(glob.glob(os.path.join(FIRMWARE_DIR, pattern)))


def _load(path):
    data = open(path, "rb").read()
    return data, tool.xor_decrypt(data[13:])


def atk_names():
    return [os.path.basename(p) for p in _archive_files()]





@pytest.mark.parametrize("name", atk_names() or ["<empty>"])
def test_header_parses(name):
    data, _ = _load(os.path.join(FIRMWARE_DIR, name))
    header = tool.parse_atk_header(data)
    assert header["dev_type"] == 0x0208
    assert len(data) == 13 + header["bin_size"]


@pytest.mark.parametrize("name", atk_names() or ["<empty>"])
def test_version_decoded_from_code_matches_filename(name):
    path = os.path.join(FIRMWARE_DIR, name)
    _, payload = _load(path)
    checks = tool.find_firmware_version(payload)
    assert checks, f"no version self-check found in {name}"
    version_ints = {imm for _, imm in checks}
    assert len(version_ints) == 1
    version = tool.format_version(version_ints.pop())
    assert version == tool.parse_version_from_filename(name)


@pytest.mark.parametrize("name", atk_names() or ["<empty>"])
def test_patch_status_matches_filename(name):
    path = os.path.join(FIRMWARE_DIR, name)
    _, payload = _load(path)

    if "_nolie" in name:
        assert tool.find_function_location(
            payload, instruction=tool.THUMB_NOP
        ) is not None, f"{name}: expected nolie patched"
    else:
        assert tool.find_function_location(
            payload, instruction=None
        ) is not None, f"{name}: expected stock nolie"

    if "_nologo" in name:
        assert tool.find_logo_anim_patch(payload) is not None, name
    else:
        assert tool.find_logo_anim(payload) is not None, name

    if "_fastlcd" in name:
        waits = tool.find_lcd_waits(payload, patched=True)
        assert waits is not None, name
        assert [v for _, v in waits] == list(tool.LCD_WAIT_PATCH)
    else:
        waits = tool.find_lcd_waits(payload, patched=False)
        assert waits is not None, name
        assert [v for _, v in waits] == list(tool.LCD_WAIT_ORIG)

    # fastpd: v1.1.6 stock carries the pre-wait counter, patched files
    # carry the shortened one; v1.1.4/v1.1.5 have no counter (absent).
    pd_state, _ = tool.find_pd_prewait(payload)
    if "_fastpd" in name:
        assert pd_state == "patched", f"{name}: expected fastpd patched"
    elif "_v1.1.6" in name:
        assert pd_state == "stock", f"{name}: expected stock fastpd"
    else:
        assert pd_state == "absent", f"{name}: expected no PD counter"

    # fastsettle: "_fastsettle" in a name means the patch is present -
    # default tune ("patched") or a custom --fastsettle tune ("custom";
    # filenames cannot encode values, the stamp only marks presence).
    st_state, _ = tool.find_pd_settle(payload)
    if "_fastsettle" in name:
        assert st_state in ("patched", "custom"), \
            f"{name}: expected fastsettle patched"
    else:
        assert st_state == "stock", f"{name}: expected stock fastsettle"

    # earlykey: filenames ending in _earlykey carry the patch; the rest
    # (including fastlcd+earlykey combos) must detect through redirects.
    ek, cave_off, _, _ = tool.find_earlykey(payload)
    if "_earlykey" in name:
        assert ek == "patched", f"{name}: expected earlykey patched"
        assert cave_off == tool.EARLYKEY_CAVE_ADDR - 0x08005000, name
    else:
        assert ek == "clean", f"{name}: expected earlykey clean, got {ek}"


@pytest.mark.parametrize("name", atk_names() or ["<empty>"])
def test_info_exits_zero(name):
    import sys

    old = sys.argv
    try:
        sys.argv = ["t90_fw_tool.py", "info",
                    os.path.join(FIRMWARE_DIR, name)]
        assert tool.main() == 0
    finally:
        sys.argv = old


def test_stock_files_are_unpatched():
    stock = [n for n in atk_names() if n.endswith(".atk") and
             n.replace(".atk", "").count("_") == 1]  # t90_vX.Y.Z only
    assert stock, "no stock firmware files in archive"
    for name in stock:
        _, payload = _load(os.path.join(FIRMWARE_DIR, name))
        assert tool.find_function_location(
            payload, instruction=tool.THUMB_NOP
        ) is None, name


def test_archive_files_exist():
    assert atk_names(), f"no .atk files in {FIRMWARE_DIR}"


@pytest.mark.parametrize("name", atk_names() or ["<empty>"])
def test_ver_info_anchor_stable(name):
    # The Ver Info format string sits at a version-dependent offset with
    # exactly one ADR reference.  Files predate stamping (letters None)
    # unless already patched with this tool, in which case the letters
    # must match the patch set in the file name.
    _, payload = _load(os.path.join(FIRMWARE_DIR, name))
    if "_v1.1.4" in name:
        expected_off = 0x10DC8
    elif "_v1.1.5" in name:
        expected_off = 0x10DE0
    else:
        expected_off = 0x11814
    off = tool.find_ver_info(payload)
    assert off == expected_off, name
    letters = tool.ver_info_letters(payload, off)
    expected = "".join(
        letter if f"_{patch}" in name else "-"
        for patch, letter in tool.VER_INFO_LETTERS
    )
    # Legacy stamps (older tool versions) lack the trailing letter(s).
    assert letters in (None, expected, expected[:3], expected[:4],
                       expected[:5]), (name, letters)