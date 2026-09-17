"""Verify only explicit successful state records skip decompilation."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins"))
import decompile_binary as db


def test_partial_output_is_not_treated_as_complete(tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"binary")
    output = tmp_path / "out"
    partial = output / "sample_decomp"
    partial.mkdir(parents=True)
    (partial / "one_function.c").write_text("partial", encoding="utf-8")

    assert not db.already_processed(binary, output, {}, False, False)


def test_matching_success_state_is_complete(tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"binary")
    state = {
        db.compute_file_hash(binary): {
            "file": str(binary),
            "status": "success",
        },
    }

    assert db.already_processed(binary, tmp_path / "out", state, False, False)


def test_same_content_at_different_path_is_not_same_job(tmp_path):
    first = tmp_path / "a" / "sample.exe"
    second = tmp_path / "b" / "sample.exe"
    first.parent.mkdir()
    second.parent.mkdir()
    first.write_bytes(b"same")
    second.write_bytes(b"same")
    state = {
        db.compute_file_hash(first): {
            "file": str(first),
            "status": "success",
        },
    }

    assert not db.already_processed(second, tmp_path / "out", state, False, False)
