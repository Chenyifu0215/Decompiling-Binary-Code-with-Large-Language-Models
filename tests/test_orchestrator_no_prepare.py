"""Exercise patch scheduling when the repair loop reuses an existing tree."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins"))
import orchestrator as orch


class _SecondRoundProposer:
    def __init__(self):
        self.calls = 0

    def propose(self, errors, build_dir):
        self.calls += 1
        if self.calls > 1:
            return []
        return [{
            "op": "replace",
            "file": "value.c",
            "old": "missing",
            "new": "0",
        }]


def test_no_prepare_applies_historical_patch_only_once(tmp_path, monkeypatch):
    build = tmp_path / "build"
    build.mkdir()
    source = build / "value.c"
    source.write_text("int value = missing;\n", encoding="utf-8")
    patch_file = build / "patches.json"
    patch_file.write_text(json.dumps([{
        "op": "replace",
        "file": "value.c",
        "old": "int value",
        "new": "unsigned int value",
    }]), encoding="utf-8")

    proposer = _SecondRoundProposer()
    states = []

    def fake_compile(build_dir, make_cmd=None):
        text = source.read_text(encoding="utf-8")
        states.append(text)
        if text == "unsigned int value = 0;\n":
            return True, []
        return False, [{
            "file": "value.c",
            "line": 1,
            "col": 1,
            "kind": "error",
            "message": "missing is undeclared",
        }]

    monkeypatch.setattr(orch, "make_proposer", lambda *args, **kwargs: proposer)
    monkeypatch.setattr(orch, "compile_build", fake_compile)
    monkeypatch.setattr(sys, "argv", [
        "orchestrator.py", "unused.bin", "unused_decomp",
        "--no-prepare", "--build-dir", str(build),
        "--patches", str(patch_file), "--max-iter", "3",
    ])

    assert orch.main() == 0
    assert states == [
        "unsigned int value = missing;\n",
        "unsigned int value = 0;\n",
    ]
    assert "unsigned unsigned" not in source.read_text(encoding="utf-8")
