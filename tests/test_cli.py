"""End-to-end tests for the CLI: info / extract / patch."""

import argparse
import os
import struct

import pytest

import t90_fw_tool as tool
import synthetic


# --- helpers ---------------------------------------------------------------


def read(path):
    with open(path, "rb") as f:
        return f.read()


def payload_of(atk_bytes):
    return tool.xor_decrypt(atk_bytes[13:])


def payload_diff_offsets(a, b):
    """Payload offsets where two decrypted payloads differ."""
    return [i for i in range(min(len(a), len(b))) if a[i] != b[i]]


# Byte-level diffs vs a stock payload. Nolie: 0xD101 -> 0xBF00 changes
# both bytes. Logo: 6F F0 26 04 -> 02 24 00 BF changes all 4 bytes.
# Fastlcd: movs r0,#imm -> #new changes only the low byte (100->70,
# 200->120 all fit in a byte).
NOLIE_BYTES = {synthetic.NOLIE_PATCH_OFFSET, synthetic.NOLIE_PATCH_OFFSET + 1}
LOGO_BYTES = set(range(synthetic.LOGO_OFFSET, synthetic.LOGO_OFFSET + 4))
FASTLCD_BYTES = {
    synthetic.WAIT_A_OFFSET, synthetic.WAIT_B_OFFSET, synthetic.WAIT_C_OFFSET
}
# Ver Info designation: stock 'T90%s  V:%1d.%1d.%1d' (20 chars) ->
# stamped 'T90%s V%1d.%1d.%1d<letters>' (21 chars). Bytes 0..5 are
# identical, then the collapsed space, dropped colon, shifted tail and
# 3 letters differ (rel 6..20); the relocated NUL lands on old zero
# padding, and the pool word after the window is untouched.
VER_BYTES = set(range(synthetic.VER_INFO_OFFSET + 6,
                      synthetic.VER_INFO_OFFSET + 21))


# --- info ------------------------------------------------------------------


def test_info_stock(atk_file, cli):
    path = atk_file()
    code, out, err = cli("info", path)
    assert code == 0
    assert "version:   1.1.6" in out
    assert "nolie:    not patched" in out
    assert "nologo:   not patched" in out
    assert "fastlcd:  not patched (LCD waits: 100 ms, 100 ms, 200 ms)" in out
    assert "earlykey: not patched" in out
    assert f"0x{synthetic.KEYSCAN_OFFSET:05X}" in out  # key-scan offset shown
    assert "File size matches bin_size + header" in out
    assert "SP address in RAM range" in out
    assert "Reset vector in Flash range" in out


def test_info_patched(atk_file, cli):
    path = atk_file(payload=synthetic.build_payload(
        nolie="patched", nologo="patched", fastlcd="patched"
    ))
    code, out, err = cli("info", path)
    assert code == 0
    assert "nolie:    already patched" in out
    assert "nologo:   already patched" in out
    assert "fastlcd:  already patched (LCD waits: 70 ms, 70 ms, 120 ms)" in out


def test_info_earlykey_patched(atk_file, cli):
    path = atk_file(payload=synthetic.build_payload(earlykey="patched"))
    code, out, err = cli("info", path)
    assert code == 0
    assert "earlykey: already patched" in out
    # Cave ARM address = image base + cave offset.
    assert f"0x{tool.EARLYKEY_CAVE_ADDR:08X}" in out
    # fastlcd state still visible through the redirection.
    assert "fastlcd:  not patched (LCD waits: 100 ms, 100 ms, 200 ms)" in out


def test_info_version_source(atk_file, cli):
    code, out, _ = cli("info", atk_file())
    assert "source:    code self-check immediates" in out
    assert f"0x{synthetic.VER_OFFSET:04X}" in out


def test_info_version_from_filename(atk_file, cli):
    path = atk_file(payload=synthetic.build_payload(version_int=None))
    code, out, _ = cli("info", path)
    assert "version:   1.1.6" in out
    assert "source:    filename" in out


def test_info_version_unknown(atk_file, cli):
    path = atk_file(payload=synthetic.build_payload(version_int=None),
                    name="firmware.atk")
    code, out, _ = cli("info", path)
    assert code == 0
    assert "version:   unknown" in out
    assert "source:    unsure" in out


def test_info_unknown_patterns(atk_file, cli):
    # Payload without any patch signatures -> 'unknown' everywhere.
    path = atk_file(payload=bytes(synthetic.PAYLOAD_SIZE))
    code, out, _ = cli("info", path)
    assert code == 0
    assert "nolie:    unknown" in out
    assert "nologo:   unknown" in out
    assert "fastlcd:  unknown" in out


def test_info_bad_dev_type(atk_file, cli):
    path = atk_file(dev_type=0x0999)
    code, out, err = cli("info", path)
    assert code == 1
    assert "Invalid dev_type" in err


def test_info_size_mismatch_warning(atk_file, cli):
    path = atk_file(bin_size=synthetic.PAYLOAD_SIZE - 16)
    code, out, _ = cli("info", path)
    assert code == 0
    assert "WARNING: File size" in out


def test_info_vector_table_values(atk_file, cli):
    code, out, _ = cli("info", atk_file())
    assert f"0x{synthetic.INITIAL_SP:08X}" in out
    assert f"0x{synthetic.RESET_VECTOR:08X}" in out


# --- extract ---------------------------------------------------------------


def test_extract_explicit_output(atk_file, tmp_path, cli):
    path = atk_file()
    out_file = str(tmp_path / "out.bin")
    code, out, err = cli("extract", path, out_file)
    assert code == 0
    # A user-supplied output name is used verbatim.
    assert os.path.exists(out_file)
    assert read(out_file) == payload_of(read(path))


def test_extract_default_output_is_versioned(atk_file, tmp_path, cli):
    path = atk_file(name="t90.atk")
    code, out, _ = cli("extract", path)
    assert code == 0
    expected = tmp_path / "t90_v1.1.6.bin"
    assert expected.exists()
    assert read(expected) == payload_of(read(path))
    assert "Extracted firmware to" in out
    assert "Firmware version: 1.1.6" in out


def test_extract_does_not_double_version(atk_file, tmp_path, cli):
    atk_file(name="t90_v1.1.6.atk")
    path = str(tmp_path / "t90_v1.1.6.atk")
    code, out, _ = cli("extract", path)
    assert code == 0
    assert (tmp_path / "t90_v1.1.6.bin").exists()


def test_extract_bad_header(atk_file, tmp_path, cli):
    path = atk_file(dev_type=0x0999)
    code, _, err = cli("extract", path)
    assert code == 1
    assert "Invalid dev_type" in err


# --- patch: all patches ----------------------------------------------------


def test_patch_all(atk_file, tmp_path, cli):
    path = atk_file()
    code, out, err = cli("patch", path)
    assert code == 0, err

    out_path = tmp_path / "t90_v1.1.6_nolie_nologo_fastlcd.atk"
    assert out_path.exists(), f"missing {out_path.name}; stdout:\n{out}"
    original = read(path)
    patched = read(out_path)

    # Header untouched, size unchanged.
    assert patched[:13] == original[:13]
    assert len(patched) == len(original)

    # Exactly the intended bytes differ.
    orig_p = payload_of(original)
    new_p = payload_of(patched)
    diffs = set(payload_diff_offsets(orig_p, new_p))
    expected = NOLIE_BYTES | LOGO_BYTES | FASTLCD_BYTES | VER_BYTES
    assert diffs == expected, (sorted(diffs), sorted(expected))

    # Spot-check the written instructions.
    hw = struct.unpack_from("<H", new_p, synthetic.NOLIE_PATCH_OFFSET)[0]
    assert hw == tool.THUMB_NOP
    assert new_p[synthetic.LOGO_OFFSET:synthetic.LOGO_OFFSET + 4] == (
        tool.LOGO_ANIM_PATCH
    )
    for off, imm in zip(
        (synthetic.WAIT_A_OFFSET, synthetic.WAIT_B_OFFSET,
         synthetic.WAIT_C_OFFSET),
        tool.LCD_WAIT_PATCH,
    ):
        hw = struct.unpack_from("<H", new_p, off)[0]
        assert hw == 0x2000 | imm

    # The tool now reports everything as already patched.
    code, out2, _ = cli("info", str(out_path))
    assert "nolie:    already patched" in out2
    assert "nologo:   already patched" in out2
    assert "fastlcd:  already patched" in out2
    assert "version:   1.1.6" in out2
    assert "verinfo:  'NLF'" in out2

    # Patched output is valid XOR of the payload (re-encrypt sanity).
    assert tool.xor_decrypt(patched[13:]) == new_p


def test_patch_keeps_file_size_and_header(atk_file, tmp_path, cli):
    path = atk_file()
    code, out, _ = cli("patch", path)
    out_path = tmp_path / "t90_v1.1.6_nolie_nologo_fastlcd.atk"
    assert read(out_path)[:13] == read(path)[:13]
    assert len(read(out_path)) == len(read(path))


# --- patch: --only / --skip ------------------------------------------------


def test_patch_only_nolie(atk_file, tmp_path, cli):
    path = atk_file()
    code, out, err = cli("patch", "--only", "nolie", path)
    assert code == 0, err
    out_path = tmp_path / "t90_v1.1.6_nolie.atk"
    assert out_path.exists()
    diffs = set(payload_diff_offsets(payload_of(read(path)),
                                     payload_of(read(out_path))))
    assert diffs == NOLIE_BYTES | VER_BYTES


def test_patch_only_comma_list(atk_file, tmp_path, cli):
    path = atk_file()
    code, out, err = cli("patch", "--only", "nolie,fastlcd", path)
    assert code == 0, err
    out_path = tmp_path / "t90_v1.1.6_nolie_fastlcd.atk"
    assert out_path.exists()
    diffs = set(payload_diff_offsets(payload_of(read(path)),
                                     payload_of(read(out_path))))
    assert diffs == NOLIE_BYTES | FASTLCD_BYTES | VER_BYTES


def test_patch_only_fastlcd(atk_file, tmp_path, cli):
    path = atk_file()
    code, out, err = cli("patch", "--only", "fastlcd", path)
    assert code == 0, err
    out_path = tmp_path / "t90_v1.1.6_fastlcd.atk"
    assert out_path.exists()
    diffs = set(payload_diff_offsets(payload_of(read(path)),
                                     payload_of(read(out_path))))
    assert diffs == FASTLCD_BYTES | VER_BYTES


def test_patch_skip_fastlcd(atk_file, tmp_path, cli):
    path = atk_file()
    code, out, err = cli("patch", "--skip", "fastlcd", path)
    assert code == 0, err
    out_path = tmp_path / "t90_v1.1.6_nolie_nologo.atk"
    assert out_path.exists()
    diffs = set(payload_diff_offsets(payload_of(read(path)),
                                     payload_of(read(out_path))))
    assert diffs == NOLIE_BYTES | LOGO_BYTES | VER_BYTES


# --- patch: earlykey -------------------------------------------------------


def earlykey_diff_bytes(orig_p, patched_p):
    """Expected payload-byte diffs when earlykey redirects callers."""
    # Cave region: every nonzero byte of the cave (initially zeros).
    cave = tool.build_earlykey_cave(
        tool.EARLYKEY_CAVE_ADDR,
        0x08005000 + synthetic.DELAY_OFFSET,
        0x08005000 + synthetic.KEYSCAN_OFFSET,
    )
    diffs = {
        synthetic.CAVE_OFF + i for i, b in enumerate(cave) if b != 0
    }
    # Each redirected BL: bytes where cave target encoding differs.
    for off, _imm in synthetic.ALL_DELAY_CALLERS:
        bl = off + 2
        src = 0x08005000 + bl
        before = synthetic.b_bl(src, 0x08005000 + synthetic.DELAY_OFFSET)
        after = tool._bl_encode(src, tool.EARLYKEY_CAVE_ADDR)
        assert len(before) == len(after) == 4
        diffs |= {bl + i for i in range(4) if before[i] != after[i]}
    return diffs


def test_patch_only_earlykey(atk_file, tmp_path, cli):
    path = atk_file()
    code, out, err = cli("patch", "--only", "earlykey", path)
    assert code == 0, err
    out_path = tmp_path / "t90_v1.1.6_earlykey.atk"
    assert out_path.exists(), out
    diffs = set(payload_diff_offsets(payload_of(read(path)),
                                     payload_of(read(out_path))))
    assert diffs == earlykey_diff_bytes(payload_of(read(path)),
                                        payload_of(read(out_path)))
    # The cave landed at the expected offset, others untouched.
    new_p = payload_of(read(out_path))
    assert new_p[synthetic.CAVE_OFF:synthetic.CAVE_OFF + synthetic.CAVE_LEN] != bytes(
        synthetic.CAVE_LEN
    )
    # info sees through the redirect.
    code, info, _ = cli("info", str(out_path))
    assert "earlykey: already patched" in info
    assert "fastlcd:  not patched" in info


def test_default_patch_does_not_apply_earlykey(atk_file, tmp_path, cli):
    path = atk_file()
    code, out, err = cli("patch", path)
    assert code == 0, err
    out_path = tmp_path / "t90_v1.1.6_nolie_nologo_fastlcd.atk"
    assert out_path.exists()  # no _earlykey in the name
    new_p = payload_of(read(out_path))
    assert new_p[synthetic.CAVE_OFF:synthetic.CAVE_OFF + synthetic.CAVE_LEN] == bytes(
        synthetic.CAVE_LEN
    )
    code, info, _ = cli("info", str(out_path))
    assert "earlykey: not patched" in info


def test_skip_fastlcd_does_not_apply_earlykey(atk_file, tmp_path, cli):
    path = atk_file()
    code, out, err = cli("patch", "--skip", "fastlcd", path)
    assert code == 0, err
    out_path = tmp_path / "t90_v1.1.6_nolie_nologo.atk"
    assert out_path.exists()
    new_p = payload_of(read(out_path))
    assert new_p[synthetic.CAVE_OFF:synthetic.CAVE_OFF + synthetic.CAVE_LEN] == bytes(
        synthetic.CAVE_LEN
    )


def test_patch_earlykey_with_fastlcd(atk_file, tmp_path, cli):
    # fastlcd runs before earlykey; both must survive together.
    path = atk_file()
    code, out, err = cli("patch", "--only", "fastlcd,earlykey", path)
    assert code == 0, err
    out_path = tmp_path / "t90_v1.1.6_fastlcd_earlykey.atk"
    assert out_path.exists(), out
    new_p = payload_of(read(out_path))
    for off, imm in zip(
        (synthetic.WAIT_A_OFFSET, synthetic.WAIT_B_OFFSET,
         synthetic.WAIT_C_OFFSET),
        tool.LCD_WAIT_PATCH,
    ):
        hw = struct.unpack_from("<H", new_p, off)[0]
        assert hw == 0x2000 | imm
    code, info, _ = cli("info", str(out_path))
    assert "earlykey: already patched" in info
    assert "fastlcd:  already patched (LCD waits: 70 ms, 70 ms, 120 ms)" in info


def test_patch_earlykey_idempotent(atk_file, tmp_path, cli):
    path = atk_file(payload=synthetic.build_payload(earlykey="patched"),
                    name="t90_v1.1.6_earlykey.atk")
    before = read(path)
    code, out, err = cli("patch", "--only", "earlykey", path)
    assert code == 0, err
    assert "already applied" in out
    out_path = tmp_path / "t90_v1.1.6_earlykey.atk"
    assert read(out_path) == before  # byte-identical re-run


def test_patch_earlykey_on_fastlcd_patched_input(atk_file, tmp_path, cli):
    # Apply earlykey to an input that already has fastlcd: the redirect
    # must not confuse the fastlcd detector.
    path = atk_file(payload=synthetic.build_payload(fastlcd="patched"))
    code, out, err = cli("patch", "--only", "earlykey", path)
    assert code == 0, err
    out_path = tmp_path / "t90_v1.1.6_fastlcd_earlykey.atk"
    assert out_path.exists(), out
    code, info, _ = cli("info", str(out_path))
    assert "earlykey: already patched" in info
    assert "fastlcd:  already patched" in info


def test_patch_earlykey_no_keyscan_errors(atk_file, cli):
    # Key-scan routine missing -> earlykey refuses.
    payload = bytearray(synthetic.build_payload())
    payload[synthetic.KEYSCAN_OFFSET:synthetic.KEYSCAN_OFFSET + 10] = bytes(10)
    path = atk_file(payload=bytes(payload))
    code, _, err = cli("patch", "--only", "earlykey", path)
    assert code == 1
    assert "delay_ms caller pattern not found" in err


def test_patch_earlykey_occupied_cave_errors(atk_file, cli):
    # Cave not empty -> refuse to patch.
    payload = bytearray(synthetic.build_payload())
    payload[synthetic.CAVE_OFF + 4] = 0xFF
    path = atk_file(payload=bytes(payload))
    code, _, err = cli("patch", "--only", "earlykey", path)
    assert code == 1
    assert "cave" in err and "not empty" in err


def test_patch_skip_all_errors(atk_file, cli):
    path = atk_file()
    code, _, err = cli(
        "patch", "--skip", "nolie,nologo,fastlcd", path
    )
    assert code == 1
    assert "no patches selected" in err


def test_patch_only_unknown_name_raises(atk_file, cli):
    path = atk_file()
    with pytest.raises(SystemExit):  # argparse error
        cli("patch", "--only", "bogus", path)


def test_only_and_skip_mutually_exclusive(atk_file, cli):
    path = atk_file()
    with pytest.raises(SystemExit):
        cli("patch", "--only", "nolie", "--skip", "fastlcd", path)


# --- patch: idempotency and partial inputs ---------------------------------


def test_patch_patched_input_is_idempotent(atk_file, tmp_path, cli):
    path = atk_file(payload=synthetic.build_payload(
        nolie="patched", nologo="patched", fastlcd="patched"
    ))
    before = read(path)
    code, out, err = cli("patch", path)
    assert code == 0, err
    out_path = tmp_path / "t90_v1.1.6_nolie_nologo_fastlcd.atk"
    assert out_path.exists()
    after = read(out_path)
    assert after[13:] == before[13:]  # payload unchanged
    assert "already applied" in out or "already" in out


def test_patch_patched_input_no_suffix_stacking(atk_file, tmp_path, cli):
    # Re-running on an output-named file must not grow the name.
    path = atk_file(payload=synthetic.build_payload(
        nolie="patched", nologo="patched", fastlcd="patched"
    ), name="t90_v1.1.6_nolie_nologo_fastlcd.atk")
    code, out, _ = cli("patch", path)
    assert code == 0
    assert (tmp_path / "t90_v1.1.6_nolie_nologo_fastlcd.atk").exists()
    # No doubled suffix file was written.
    assert not (
        tmp_path / "t90_v1.1.6_nolie_nologo_fastlcd_nolie_nologo_fastlcd.atk"
    ).exists()


def test_patch_partial_input_keeps_existing_patch_in_name(
    atk_file, tmp_path, cli
):
    # A file patched by an older tool (no Ver Info stamp yet) gains the
    # remaining patches plus the stamp for the full effective set.
    path = atk_file(payload=synthetic.build_payload(nolie="patched",
                                                    verinfo="stock"))
    code, out, err = cli("patch", path)  # applies nologo + fastlcd
    assert code == 0, err
    out_path = tmp_path / "t90_v1.1.6_nolie_nologo_fastlcd.atk"
    assert out_path.exists(), out
    # Only nologo + fastlcd bytes changed vs the input.
    diffs = set(payload_diff_offsets(payload_of(read(path)),
                                     payload_of(read(out_path))))
    assert diffs == LOGO_BYTES | FASTLCD_BYTES | VER_BYTES


def test_patch_explicit_output(atk_file, tmp_path, cli):
    path = atk_file()
    out_file = str(tmp_path / "custom.atk")
    code, out, err = cli("patch", path, out_file)
    assert code == 0, err
    # A user-supplied output name is used verbatim.
    assert os.path.exists(out_file)
    assert read(out_file)[13:] != read(path)[13:]


def test_patch_bad_header(atk_file, cli):
    path = atk_file(dev_type=0x0999)
    code, _, err = cli("patch", path)
    assert code == 1
    assert "Invalid dev_type" in err


def test_patch_missing_nolie_pattern_errors(atk_file, cli):
    # Payload without the lie function -> patch aborts with exit 1.
    payload = bytearray(synthetic.build_payload())
    payload[synthetic.NOLIE_SIG_OFFSET:synthetic.NOLIE_SIG_OFFSET + 16] = (
        bytes(16)
    )
    path = atk_file(payload=bytes(payload))
    code, _, err = cli("patch", "--only", "nolie", path)
    assert code == 1
    assert "lie" in err


def test_patch_missing_nologo_pattern_errors(atk_file, cli):
    payload = bytearray(synthetic.build_payload(nologo="patched"))
    # remove the patched bytes too so 'already applied' doesn't trigger
    payload[synthetic.LOGO_OFFSET:synthetic.LOGO_OFFSET + 4] = bytes(4)
    path = atk_file(payload=bytes(payload))
    code, _, err = cli("patch", "--only", "nologo", path)
    assert code == 1
    assert "logo animation pattern not found" in err


def test_patch_missing_fastlcd_pattern_errors(atk_file, cli):
    payload = bytes(synthetic.PAYLOAD_SIZE)  # nothing at all
    path = atk_file(payload=payload)
    code, _, err = cli("patch", "--only", "fastlcd", path)
    assert code == 1
    assert "LCD init wait pattern not found" in err


def test_patch_ambiguous_fastlcd_refused(atk_file, cli):
    path = atk_file(payload=synthetic.build_payload(fastlcd="ambiguous"))
    code, _, err = cli("patch", "--only", "fastlcd", path)
    assert code == 1
    assert "LCD init wait pattern not found" in err


# --- misc ------------------------------------------------------------------


def test_parse_only_accepts_valid():
    assert tool._parse_only("nolie") == ["nolie"]
    assert tool._parse_only("nolie, nologo") == ["nolie", "nologo"]
    assert tool._parse_only("nolie,nologo,fastlcd") == ["nolie", "nologo", "fastlcd"]
    assert tool._parse_only("nolie,nologo,fastlcd,earlykey") == list(tool.PATCH_NAMES)


def test_parse_only_rejects_unknown():
    with pytest.raises(argparse.ArgumentTypeError, match="bogus"):
        tool._parse_only("bogus")
    with pytest.raises(argparse.ArgumentTypeError, match="bogus"):
        tool._parse_only("nolie,bogus")
    with pytest.raises(argparse.ArgumentTypeError):
        tool._parse_only("")


def test_patch_names_constant():
    assert tool.PATCH_NAMES == ("nolie", "nologo", "fastlcd", "earlykey")


def test_default_patches_exclude_earlykey():
    # earlykey is experimental/opt-in: never in the default set.
    assert tool.DEFAULT_PATCHES == ("nolie", "nologo", "fastlcd")
    assert "earlykey" not in tool.DEFAULT_PATCHES


def test_main_no_command_prints_help(capsys):
    import sys
    old = sys.argv
    try:
        sys.argv = ["t90_fw_tool.py"]
        assert tool.main() == 1
    finally:
        sys.argv = old
    assert "usage:" in capsys.readouterr().out