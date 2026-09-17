"""Ensure patch targets cannot escape the selected build directory."""

import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins"))
import patch as patch_mod


def _replace_patch(filename):
    return {
        "op": "replace",
        "file": str(filename),
        "old": "ORIGINAL",
        "new": "MODIFIED",
    }


def test_parent_traversal_is_rejected(tmp_path):
    build = tmp_path / "build"
    build.mkdir()
    outside = tmp_path / "outside.c"
    outside.write_text("ORIGINAL", encoding="utf-8")

    applied, errors = patch_mod.apply_patch_list(build, [_replace_patch("../outside.c")])

    assert applied == 0
    assert any("escapes build directory" in error for error in errors)
    assert outside.read_text(encoding="utf-8") == "ORIGINAL"


def test_absolute_path_is_rejected(tmp_path):
    build = tmp_path / "build"
    build.mkdir()
    outside = tmp_path / "outside.c"
    outside.write_text("ORIGINAL", encoding="utf-8")

    applied, errors = patch_mod.apply_patch_list(build, [_replace_patch(outside)])

    assert applied == 0
    assert any("absolute patch paths" in error for error in errors)
    assert outside.read_text(encoding="utf-8") == "ORIGINAL"


def test_symlink_to_outside_is_rejected(tmp_path):
    build = tmp_path / "build"
    build.mkdir()
    outside = tmp_path / "outside.c"
    outside.write_text("ORIGINAL", encoding="utf-8")
    link = build / "linked.c"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip("symlinks are unavailable: %s" % exc)

    applied, errors = patch_mod.apply_patch_list(build, [_replace_patch("linked.c")])

    assert applied == 0
    assert any("escapes build directory" in error for error in errors)
    assert outside.read_text(encoding="utf-8") == "ORIGINAL"


def test_nested_file_inside_build_is_allowed(tmp_path):
    build = tmp_path / "build"
    nested = build / "src"
    nested.mkdir(parents=True)
    target = nested / "inside.c"
    target.write_text("ORIGINAL", encoding="utf-8")

    applied, errors = patch_mod.apply_patch_list(
        build, [_replace_patch("src/inside.c")],
    )

    assert applied == 1
    assert errors == []
    assert target.read_text(encoding="utf-8") == "MODIFIED"
