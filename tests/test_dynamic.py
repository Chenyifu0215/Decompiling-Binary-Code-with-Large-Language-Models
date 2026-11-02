"""Meaningful runtime gates using real compiler/sanitizer/process executions."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "plugins"))
sys.path.insert(0, str(ROOT / "scripts"))

from demo_dynamic import prepare
from dynamic.config import load_cases, load_config
from dynamic.controller import run
from dynamic.diagnostics import diagnose
from dynamic.runner import decode, encode, run_case, run_process
from dynamic.validator import accept_candidate
from dynamic.workspace import apply_candidate, digest


@pytest.fixture
def project(tmp_path):
    if sys.platform != "linux" or not shutil.which("gcc"):
        pytest.skip("Linux GCC/ASan backend required")
    path = prepare(tmp_path / "project")
    return path.parent, load_config(path)


def test_real_repair_rejects_regression_and_passes_heldout(project):
    directory, config = project
    original = digest(directory / "source" / "main.c")
    result = run(config, directory / "evaluation.json", progress=lambda _: None)
    assert result["status"] == "TEST_VALIDATED", result
    assert [a["accepted"] for a in result["attempts"]] == [False, True]
    assert "regression" in result["attempts"][0]["reason"]
    assert result["accepted_count"] == 1
    assert digest(directory / "source" / "main.c") == original
    root = Path(result["run_dir"])
    assert not (root / "attempts/0001/source").exists()
    assert (root / "attempts/0001/decision.json").exists()
    assert (root / "report.html").is_file()
    assert "i < n" in (root / "best/source/main.c").read_text()
    assert "heldout_five" not in (root / "attempts/0002/evidence.json").read_text()
    assert result["repair_results"]["invalid_zero"]["normal"]["result"]["exit_code"] == 7
    assert result["baseline_results"]["two"]["instrumented"]["issues"]


def test_heldout_failure_never_triggers_more_proposals(project):
    directory, config = project
    patches = [[{"op": "replace", "file": "main.c", "old": "i <= n", "new": "i < n"},
                {"op": "replace", "file": "main.c", "old": 'printf("%d\\n", values[n - 1]);',
                 "new": 'printf("%d\\n", n == 5 ? 99 : values[n - 1]);'}]]
    (directory / "replay.json").write_text(json.dumps(patches))
    result = run(config, directory / "evaluation.json", progress=lambda _: None)
    assert result["status"] == "PARTIAL"
    assert len(result["attempts"]) == 1
    assert not result["evaluation_results"]["heldout_five"]["passed"]


def test_evaluation_only_and_missing_oracle(project):
    _, config = project
    config["repair"]["proposer"] = "none"
    result = run(copy.deepcopy(config), progress=lambda _: None)
    assert result["status"] == "NO_PROGRESS"
    assert not result["attempts"]
    config["target"]["reference_binary"] = None
    assert run(config, progress=lambda _: None)["status"] == "UNVERIFIED"


def test_candidate_compile_failure_preserves_best(project):
    directory, config = project
    (directory / "replay.json").write_text(json.dumps([[{"op": "replace", "file": "main.c", "old": "i <= n", "new": "@bad"}]]))
    result = run(config, progress=lambda _: None)
    assert result["status"] == "NO_PROGRESS"
    assert result["attempts"][0]["reason"] == "candidate compilation failed"
    assert digest(Path(result["run_dir"]) / "best/source/main.c") == digest(directory / "source/main.c")


def test_static_blocked(project):
    directory, config = project
    (directory / "source/main.c").write_text("this is not C;")
    result = run(config, progress=lambda _: None)
    assert result["status"] == "STATIC_BLOCKED"
    assert not result["attempts"]


def test_nondeterministic_reference_is_unverified(project):
    directory, config = project
    (directory / "random.c").write_text('#include <unistd.h>\n#include <stdio.h>\nint main(void){printf("%d\\n",getpid());}\n')
    subprocess.run(["gcc", str(directory / "random.c"), "-o", str(directory / "reference")], check=True)
    result = run(config, progress=lambda _: None)
    assert result["status"] == "UNVERIFIED"
    assert "nondeterministic" in result["reason"]


def test_llm_call_budget_includes_invalid_responses(project, monkeypatch):
    import llm
    _, config = project
    calls = []

    class FakeLLM:
        def _available(self): return True
        def usage(self): return {}
        def propose_runtime_fix(self, evidence, max_tokens):
            calls.append(evidence)
            raise ValueError("invalid JSON from fake provider")

    monkeypatch.setattr(llm, "LLMProposer", FakeLLM)
    config["repair"].update(proposer="llm", max_llm_calls=1, max_total_tokens=100000)
    result = run(config, progress=lambda _: None)
    assert len(calls) == result["llm_requests"] == 1
    assert result["status"] == "NO_PROGRESS"
    assert "budget" in result["reason"]
    assert result["reserved_tokens"] > 0


def test_token_reservation_prevents_request(project, monkeypatch):
    import llm
    _, config = project
    monkeypatch.setattr(llm.LLMProposer, "_available", lambda self: True)
    monkeypatch.setattr(llm.LLMProposer, "propose_runtime_fix", lambda *a: pytest.fail("must not call provider"))
    config["repair"].update(proposer="llm", max_total_tokens=1)
    result = run(config, progress=lambda _: None)
    assert result["llm_requests"] == 0
    assert "budget" in result["reason"]


@pytest.mark.parametrize("file", ["../main.c", "/tmp/main.c", "C:/main.c", "sub/../../main.c", "Makefile"])
def test_patch_is_transactional_and_source_only(tmp_path, file):
    (tmp_path / "main.c").write_text("int n = 1;")
    patches = [{"op": "replace", "file": "main.c", "old": "1", "new": "2"},
               {"op": "replace", "file": file, "old": "1", "new": "2"}]
    with pytest.raises(ValueError):
        apply_candidate(tmp_path, patches, {"main.c"}, 3)
    assert (tmp_path / "main.c").read_text() == "int n = 1;"


def test_symlink_patch_rejected(tmp_path):
    external = tmp_path / "outside.c"
    external.write_text("int n = 1;")
    root = tmp_path / "root"
    root.mkdir()
    (root / "alias.c").symlink_to(external)
    with pytest.raises(ValueError):
        apply_candidate(root, [{"op": "replace", "file": "alias.c", "old": "1", "new": "2"}], {"alias.c"}, 3)
    assert external.read_text() == "int n = 1;"


def test_gate_rejects_new_failure_even_when_total_decreases():
    def row(issues):
        return {p: {"matches_reference": True, "issues": issues} for p in ("normal", "instrumented")}
    before = {"a": row(["sanitizer:a", "sanitizer:b"]), "b": row([])}
    after = {"a": row([]), "b": row(["timeout"])}
    assert not accept_candidate(before, after)[0]
    assert accept_candidate(before, {"a": row(["sanitizer:a"]), "b": row([])})[0]


@pytest.mark.parametrize("text,expected", [
    ("ERROR: AddressSanitizer: heap-buffer-overflow on address", "sanitizer:heap-buffer-overflow"),
    ("x.c:1: runtime error: signed integer overflow", "sanitizer:undefined-behavior"),
    ("ERROR: LeakSanitizer: detected memory leaks", "sanitizer:detected"),
    ("AddressSanitizer:DEADLYSIGNAL", "sanitizer:deadly-signal"),
])
def test_diagnostic_categories(text, expected):
    assert expected in diagnose({"stderr": encode(text.encode()), "state": "exited", "exit_code": 1})


@pytest.mark.skipif(sys.platform != "linux", reason="POSIX process group runner")
def test_timeout_kills_descendants(tmp_path):
    program = "import subprocess,time; p=subprocess.Popen(['sleep','60']); print(p.pid,flush=True); time.sleep(60)"
    result = run_process([sys.executable, "-c", program], tmp_path, .3, 1024)
    assert result["state"] == "timeout"
    pid = int(decode(result["stdout"]))
    stat = Path("/proc") / str(pid) / "stat"
    assert not stat.exists() or stat.read_text().split()[2] == "Z"


@pytest.mark.skipif(sys.platform != "linux", reason="POSIX runner")
def test_output_cap_and_stdin(tmp_path):
    result = run_process([sys.executable, "-c", "import os; os.write(1,b'x'*10000)"], tmp_path, 2, 100)
    assert result["state"] == "output_limit"
    assert len(decode(result["stdout"])) == 100
    echoed = run_process([sys.executable, "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"], tmp_path, 2, 100000, b"a" * 70000)
    assert decode(echoed["stdout"]) == b"a" * 70000


def test_file_inputs_and_output_hashes(project):
    _, config = project
    case = {"id": "file", "args": ["-c", "from pathlib import Path; Path('out').write_bytes(Path('in').read_bytes())"],
            "stdin": "", "files": {"in": "hello"}, "output_files": ["out", "missing"]}
    result = run_case(sys.executable, case, config)
    assert result["output_files"]["out"]["size"] == 5
    assert result["output_files"]["missing"] is None


def test_config_paths_relative_to_config_and_typos_rejected(project):
    directory, config = project
    assert config["target"]["source_dir"] == str(directory / "source")
    path = directory / "config.yaml"
    path.write_text(path.read_text().replace("max_attempts:", "max_atempts:"))
    with pytest.raises(ValueError, match="unknown"):
        load_config(path)


def test_manifest_escape_and_duplicate_ids_rejected(tmp_path):
    path = tmp_path / "cases.json"
    for cases in ([{"id": "one", "files": {"../escape": "bad"}}], [{"id": "same"}, {"id": "same"}]):
        path.write_text(json.dumps({"schema_version": 1, "cases": cases}))
        with pytest.raises(ValueError): load_cases(path)


def test_windows_delegates_same_cli_to_wsl(monkeypatch):
    import dynamic_repair
    commands = []
    monkeypatch.setattr(dynamic_repair, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(dynamic_repair, "wsl_path", lambda path, distribution: "/mapped/" + Path(path).name)
    monkeypatch.setattr(dynamic_repair.subprocess, "call", lambda cmd: commands.append(cmd) or 0)
    assert dynamic_repair.main(["--config", "demo.yaml", "--evaluation-manifest", "heldout.json", "--wsl-distribution", "Ubuntu", "--wsl-python", "/env/bin/python"]) == 0
    assert commands == [["wsl.exe", "--distribution", "Ubuntu", "--exec", "/env/bin/python", "/mapped/dynamic_repair.py", "--config", "/mapped/demo.yaml", "--evaluation-manifest", "/mapped/heldout.json"]]


def test_runtime_llm_contract(monkeypatch):
    from llm import LLMProposer
    proposer = LLMProposer(api_key="fake-not-used")
    captured = {}
    def chat(system, user, max_tokens=None):
        captured.update(system=system, user=json.loads(user), max_tokens=max_tokens)
        return {"patches": []}
    monkeypatch.setattr(proposer, "_chat_json", chat)
    assert proposer.propose_runtime_fix({"failures": {}}, max_tokens=123) == []
    assert captured["max_tokens"] == 123
    assert "runtime" in captured["system"]
