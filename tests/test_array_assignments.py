"""Compile and execute array assignment repairs to check object boundaries."""

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins"))
import decompile_helper as dh


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.parametrize("declaration", [
    "unsigned char buf[1]", "unsigned char buf[2]", "unsigned char buf[3]",
    "unsigned char buf[4]", "unsigned char buf[5]", "unsigned char buf[7]",
    "unsigned char buf[8]", "unsigned char buf[16]", "unsigned char buf[0x4]",
    "unsigned short buf[2]", "unsigned int buf[1]",
])
@pytest.mark.parametrize("storage", ["local", "global", "parameter"])
def test_bounded_scalar_copy(tmp_path, declaration, storage):
    assignment = "  buf = next_value();\n"
    global_decl = declaration + ";" if storage == "global" else ""
    helper = ""
    if storage == "parameter":
        helper = "void assign(%s)\n{\n%s}\n" % (declaration, assignment)
        assignment = "  assign(buf);\n"
    local_decl = "" if storage == "global" else declaration + ";"
    source = """#include <string.h>
#include <stddef.h>
typedef unsigned long long undefined8;
static inline void ghidra_copy_scalar(void *dst, undefined8 value, size_t size) {
    memcpy(dst, &value, size);
}
static int calls;
static undefined8 next_value(void) {
    calls++;
    return 0x8877665544332211ULL;
}
%s
%s
int main(void)
{
    %s
    unsigned char expected[sizeof(buf)];
    undefined8 value = 0x8877665544332211ULL;
    size_t count = sizeof(buf) < sizeof(value) ? sizeof(buf) : sizeof(value);
    memset(buf, 0xa5, sizeof(buf));
    memset(expected, 0xa5, sizeof(expected));
    memcpy(expected, &value, count);
%s
    return calls != 1 || memcmp(buf, expected, sizeof(buf)) != 0;
}
""" % (global_decl, helper, local_decl, assignment)

    # Global declarations live in a separate header in generated projects.
    repair_input = source.replace(global_decl, "", 1) if global_decl else source
    src = tmp_path / "input.c"
    dst = tmp_path / "output.c"
    src.write_text(repair_input, encoding="utf-8")
    dh.repair_source_file(src, dst, value_used=set(), global_names=set(),
                          global_arrays={"buf"} if storage == "global" else None)
    if global_decl:
        dst.write_text(global_decl + "\n" + dst.read_text(encoding="utf-8"),
                       encoding="utf-8")
    executable = tmp_path / "array_test"
    sanitizer = os.environ.get("ARRAY_TEST_SANITIZERS")
    flags = ["-fsanitize=" + sanitizer, "-fno-sanitize-recover=all"] if sanitizer else []
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", *flags,
         str(dst), "-o", str(executable)],
        capture_output=True, text=True, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
