"""Verify same-named binaries receive distinct default output directories."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins"))
import decompile_binary as db


def test_same_named_inputs_have_unique_stable_output_dirs(tmp_path):
    first = tmp_path / "a" / "sample.exe"
    second = tmp_path / "b" / "sample.exe"
    first.parent.mkdir()
    second.parent.mkdir()
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    output = tmp_path / "out"

    mapping = db.assign_output_subdirs([first, second])
    first_dir, _ = db.get_output_paths(
        first, output, None, False, False, None, mapping,
    )
    second_dir, _ = db.get_output_paths(
        second, output, None, False, False, None, mapping,
    )

    assert first_dir != second_dir
    assert first_dir.name.startswith("sample_")
    assert second_dir.name.startswith("sample_")
    assert db.assign_output_subdirs([first, second]) == mapping


def test_unique_input_keeps_original_output_name(tmp_path):
    source = tmp_path / "sample.exe"
    source.write_bytes(b"only")
    output = tmp_path / "out"
    mapping = db.assign_output_subdirs([source])

    per_file_dir, _ = db.get_output_paths(
        source, output, None, False, False, None, mapping,
    )

    assert mapping == {}
    assert per_file_dir == output / "sample_decomp"


def test_quoted_glob_pattern_is_expanded(tmp_path):
    first = tmp_path / "one.o"
    second = tmp_path / "two.o"
    ignored = tmp_path / "three.c"
    first.write_bytes(b"one")
    second.write_bytes(b"two")
    ignored.write_bytes(b"three")

    assert db.gather_input_files([str(tmp_path / "*.o")]) == [
        first.resolve(), second.resolve(),
    ]
