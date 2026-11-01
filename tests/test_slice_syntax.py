"""Compile and execute repaired Ghidra slice expressions."""

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins"))
import decompile_helper as dh


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_scalar_and_array_slice_reads_and_writes(tmp_path):
    source = """#include <stdint.h>
#include <string.h>
typedef uint8_t undefined1;
typedef uint32_t undefined4;
typedef uint64_t undefined8;

int main(void)
{
    undefined8 scalar = UINT64_C(0x1122334455667788);
    undefined4 scalar_read = scalar._4_4_;
    undefined4 expected_read;
    memcpy(&expected_read, (char *)&scalar + 4, sizeof(expected_read));
    if (scalar_read != expected_read) return 1;

    undefined8 expected_scalar = scalar;
    undefined4 scalar_write = UINT32_C(0xa1b2c3d4);
    scalar._0_4_ = scalar_write;
    memcpy(&expected_scalar, &scalar_write, sizeof(scalar_write));
    if (memcmp(&scalar, &expected_scalar, sizeof(scalar)) != 0) return 2;

    undefined1 array[12] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    undefined4 array_read = array._4_4_;
    memcpy(&expected_read, array + 4, sizeof(expected_read));
    if (array_read != expected_read) return 3;

    undefined1 expected_array[12];
    memcpy(expected_array, array, sizeof(array));
    undefined4 array_write = UINT32_C(0x10203040);
    array._8_4_ = array_write;
    memcpy(expected_array + 8, &array_write, sizeof(array_write));
    if (memcmp(array, expected_array, sizeof(array)) != 0) return 4;

    return 0;
}
"""
    repaired = dh._repair_slice_syntax(source)
    assert "(char *)&scalar + 4" in repaired
    assert "(char *)&array + 8" in repaired

    src = tmp_path / "slice_test.c"
    executable = tmp_path / "slice_test"
    src.write_text(repaired, encoding="utf-8")
    sanitizer = os.environ.get("SLICE_TEST_SANITIZERS")
    flags = ["-fsanitize=" + sanitizer, "-fno-sanitize-recover=all"] if sanitizer else []
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-O2", "-fno-strict-aliasing", "-Wall", "-Wextra",
         "-Werror", *flags, str(src), "-o", str(executable)],
        capture_output=True, text=True, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
