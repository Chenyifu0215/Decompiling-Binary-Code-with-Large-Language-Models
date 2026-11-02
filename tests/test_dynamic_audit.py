"""Fault-injection regressions found during the V1 review."""
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins"))
from test_dynamic import project
from dynamic.config import load_config, load_cases
from dynamic.controller import run, promote
from dynamic.diagnostics import diagnose
from dynamic.runner import encode


def test_heldout_changed_observations_are_still_duplicate_inputs(project):
    directory, config = project
    (directory / "evaluation.json").write_text(json.dumps({"schema_version": 1, "cases": [
        {"id": "renamed", "args": ["2"], "output_files": ["missing.txt"]}]}))
    result = run(config, directory / "evaluation.json", progress=lambda _: None)
    assert result["status"] == "UNVERIFIED"
    assert "repeat repair inputs" in result["reason"]


def test_promotion_failure_never_marks_patch_accepted(project, monkeypatch):
    import dynamic.controller as controller
    _, config = project
    original = controller.promote
    def fail_candidate(candidate, root):
        if candidate.parent.name == "attempts":
            raise OSError("injected disk failure")
        original(candidate, root)
    monkeypatch.setattr(controller, "promote", fail_candidate)
    result = run(config, progress=lambda _: None)
    assert result["accepted_count"] == 0
    assert all(not row["accepted"] for row in result["attempts"])
    assert "i <= n" in (Path(result["run_dir"]) / "best/source/main.c").read_text()


def test_failed_snapshot_copy_does_not_poison_next_promotion(tmp_path, monkeypatch):
    import dynamic.controller as controller
    root, candidate = tmp_path / "run", tmp_path / "candidate"
    (root / "best").mkdir(parents=True)
    (root / "best/file").write_text("old")
    candidate.mkdir()
    (candidate / "file").write_text("new")
    def partial_copy(src, dst, *args, **kwargs):
        Path(dst).mkdir()
        raise OSError("disk full")
    with monkeypatch.context() as patch:
        patch.setattr(controller.shutil, "copytree", partial_copy)
        with pytest.raises(OSError): promote(candidate, root)
    assert (root / "best/file").read_text() == "old"
    promote(candidate, root)
    assert (root / "best/file").read_text() == "new"


@pytest.mark.parametrize("snippet", ["artifacts:\n  output_dir: null\n", "schema_version: true\n"])
def test_invalid_config_returns_validation_error(project, snippet):
    directory, _ = project
    path = directory / "invalid.yaml"
    path.write_text("schema_version: 1\ntarget:\n  source_dir: ./source\n" + snippet)
    with pytest.raises(ValueError): load_config(path)


@pytest.mark.parametrize("name", [".", "bad\x00name"])
def test_invalid_test_file_names_rejected_before_execution(tmp_path, name):
    path = tmp_path / "cases.json"
    path.write_text(json.dumps({"schema_version": 1, "cases": [{"id": "case", "files": {name: "text"}}]}))
    with pytest.raises(ValueError): load_cases(path)


def test_program_error_text_is_not_a_sanitizer_diagnostic():
    result = {"state": "exited", "exit_code": 7,
              "stderr": encode(b"runtime error: invalid argument; see Sanitizer tutorial\n")}
    assert diagnose(result) == []


@pytest.mark.parametrize("body", [[], {"choices": [None]}, {"choices": [{"message": {"content": [1]}}]}])
def test_malformed_provider_response_is_controlled_error(monkeypatch, body):
    import llm
    from io import BytesIO
    monkeypatch.setattr(llm, "_CACHE_ENABLED", False)
    monkeypatch.setattr(llm.urllib.request, "urlopen", lambda *a, **kw: BytesIO(json.dumps(body).encode()))
    proposer = llm.LLMProposer(api_key="test-only")
    with pytest.raises((ValueError, RuntimeError)):
        proposer.propose_runtime_fix({})


def test_provider_cache_is_separated_by_endpoint_and_budget(monkeypatch):
    import llm
    from io import BytesIO
    cache, requests = {}, []
    monkeypatch.setattr(llm, "_cache_load", cache.get)
    monkeypatch.setattr(llm, "_cache_store", lambda key, value: cache.__setitem__(key, value))
    def reply(request, **kwargs):
        requests.append(request.full_url)
        return BytesIO(json.dumps({"choices": [{"message": {"content": '{"patches": []}'}}]}).encode())
    monkeypatch.setattr(llm.urllib.request, "urlopen", reply)
    first = llm.LLMProposer(api_key="fake", base_url="https://first.invalid")
    second = llm.LLMProposer(api_key="fake", base_url="https://second.invalid")
    first.propose_runtime_fix({}, 100)
    second.propose_runtime_fix({}, 100)
    first.propose_runtime_fix({}, 200)
    first.propose_runtime_fix({}, 100)
    assert len(requests) == 3


def test_result_file_cannot_overwrite_source(project, monkeypatch):
    import dynamic.controller as controller
    import dynamic_repair
    directory, _ = project
    source = directory / "source/main.c"
    original = source.read_bytes()
    monkeypatch.setattr(controller, "run", lambda *a, **kw: pytest.fail("must reject before running"))
    assert dynamic_repair.main(["--config", str(directory / "config.yaml"), "--result-file", str(source)]) == 2
    assert source.read_bytes() == original


def test_deadline_interrupts_stalled_proposer_and_restores_alarm(project, monkeypatch):
    import llm
    import signal
    import time
    _, config = project
    handler = signal.getsignal(signal.SIGALRM)
    config["repair"].update(proposer="llm", max_total_tokens=100000, max_total_seconds=2)
    monkeypatch.setattr(llm.LLMProposer, "_available", lambda self: True)
    def stalled(*args, **kwargs):
        time.sleep(20)
        pytest.fail("total deadline must interrupt the stalled call")
    monkeypatch.setattr(llm.LLMProposer, "propose_runtime_fix", stalled)
    start = time.monotonic()
    result = run(config, progress=lambda _: None)
    assert time.monotonic() - start < 6
    assert "total run time budget" in result["reason"]
    assert result["llm_requests"] == 1
    assert result["attempts"][0]["reason"] == result["reason"]
    assert signal.getsignal(signal.SIGALRM) == handler
    assert signal.getitimer(signal.ITIMER_REAL)[0] == 0


def test_cancelled_proposal_keeps_baseline_and_records_reason(project, monkeypatch):
    import llm
    _, config = project
    config["repair"].update(proposer="llm", max_total_tokens=100000)
    monkeypatch.setattr(llm.LLMProposer, "_available", lambda self: True)
    def cancel(*args, **kwargs): raise KeyboardInterrupt
    monkeypatch.setattr(llm.LLMProposer, "propose_runtime_fix", cancel)
    result = run(config, progress=lambda _: None)
    assert result["status"] == "CANCELLED"
    assert result["accepted_count"] == 0
    assert "cancelled" in result["attempts"][0]["reason"]
    assert (Path(result["run_dir"]) / "best/source/main.c").is_file()


def test_atomic_result_write_preserves_previous_file_on_failure(tmp_path, monkeypatch):
    import dynamic.workspace as workspace
    path = tmp_path / "results.json"
    path.write_text('{"previous": true}')
    def fail(*args): raise OSError("injected rename failure")
    monkeypatch.setattr(workspace.os, "replace", fail)
    with pytest.raises(OSError): workspace.write_json(path, {"next": True})
    assert json.loads(path.read_text()) == {"previous": True}
    assert list(tmp_path.iterdir()) == [path]


def test_failed_commit_rename_restores_previous_best(tmp_path, monkeypatch):
    root, candidate = tmp_path / "run", tmp_path / "candidate"
    (root / "best").mkdir(parents=True)
    (root / "best/file").write_text("old")
    candidate.mkdir()
    (candidate / "file").write_text("new")
    original = Path.rename
    def fail_commit(path, target):
        if path.name.startswith("best-next"):
            raise OSError("injected rename failure")
        return original(path, target)
    monkeypatch.setattr(Path, "rename", fail_commit)
    with pytest.raises(OSError): promote(candidate, root)
    assert (root / "best/file").read_text() == "old"
    assert list(root.iterdir()) == [root / "best"]


def test_cancel_at_commit_boundary_keeps_report_consistent(project, monkeypatch):
    import signal
    import dynamic.controller as controller
    _, config = project
    original = controller.promote
    def cancel_after_promotion(candidate, root):
        original(candidate, root)
        if candidate.parent.name == "attempts":
            signal.raise_signal(signal.SIGINT)
    monkeypatch.setattr(controller, "promote", cancel_after_promotion)
    result = run(config, progress=lambda _: None)
    assert result["status"] == "CANCELLED"
    assert result["accepted_count"] == 1
    assert result["attempts"][-1]["accepted"]
    assert all(row["passed"] for row in result["repair_results"].values())
    assert "i < n" in (Path(result["run_dir"]) / "best/source/main.c").read_text()
