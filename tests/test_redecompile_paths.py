"""Verify signature re-decompilation preserves duplicate function identity."""

from pathlib import Path
import sys
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins"))
import fix_signatures_llm as fsllm


class _Function:
    def __init__(self, name, address):
        self.name = name
        self.address = address

    def getName(self):
        return self.name

    def getEntryPoint(self):
        return self.address

    def getSignature(self):
        return "int %s(void)" % self.name


class _Decompiler:
    def decompileFunction(self, func, timeout, monitor):
        decompiled = SimpleNamespace(getC=lambda: "int %s(void) { return %s; }\n" % (
            func.getName(), func.getEntryPoint(),
        ))
        return SimpleNamespace(
            decompileCompleted=lambda: True,
            getDecompiledFunction=lambda: decompiled,
        )


def test_duplicate_functions_update_their_address_files(tmp_path):
    funcs = [_Function("helper", "1000"), _Function("helper", "2000")]
    for func in funcs:
        path = tmp_path / ("helper_%s.c" % func.getEntryPoint())
        path.write_text(
            "// Function: helper\n// Address:  %s\nold\n" % func.getEntryPoint(),
            encoding="utf-8",
        )
    manager = SimpleNamespace(getFunctions=lambda forward: funcs)
    program = SimpleNamespace(getFunctionManager=lambda: manager)

    assert fsllm.redecompile_selected(program, funcs, tmp_path, _Decompiler()) == 2
    assert "return 1000" in (tmp_path / "helper_1000.c").read_text(encoding="utf-8")
    assert "return 2000" in (tmp_path / "helper_2000.c").read_text(encoding="utf-8")
    assert not (tmp_path / "helper.c").exists()
