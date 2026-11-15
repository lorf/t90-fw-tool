"""Shared fixtures for the t90_fw_tool test suite."""

import os
import sys

import pytest

# Make t90_fw_tool importable (pytest.ini sets pythonpath too; belt and braces).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import t90_fw_tool as tool  # noqa: E402
import synthetic  # noqa: E402

# Archive of real firmware files (optional; tests using it skip if absent).
FIRMWARE_DIR = os.path.expanduser(
    os.environ.get("T90_FIRMWARE_DIR", "~/apps/atflash/firmware")
)


def pytest_collection_modifyitems(config, items):
    """Skip archive tests when the firmware directory is not available."""
    if os.path.isdir(FIRMWARE_DIR):
        return
    skip = pytest.mark.skip(
        reason=f"firmware archive {FIRMWARE_DIR} not present"
    )
    for item in items:
        if "archive" in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def synthetic_atk():
    """A stock synthetic .atk file (bytes)."""
    return synthetic.build_atk()


@pytest.fixture
def atk_file(tmp_path):
    """Write a synthetic .atk to a temp dir; returns its path.

    Usage: atk_file(payload=..., name=..., **header_kw)
    """

    def _make(payload=None, name="t90_v1.1.6.atk", **header_kw):
        data = synthetic.build_atk(payload=payload, **header_kw)
        path = tmp_path / name
        path.write_bytes(data)
        return str(path)

    return _make


def run_cli(monkeypatch, capsys, *argv):
    """Run tool.main() with the given argv; returns (exit_code, stdout, stderr)."""
    monkeypatch.setattr(
        sys, "argv", ["t90_fw_tool.py", *[str(a) for a in argv]]
    )
    code = tool.main()
    captured = capsys.readouterr()
    return code, captured.out, captured.err


@pytest.fixture
def cli(monkeypatch, capsys):
    return lambda *argv: run_cli(monkeypatch, capsys, *argv)