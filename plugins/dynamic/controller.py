"""Runtime repair state machine. Original inputs are never patched in place."""
from datetime import datetime, timezone
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import sys
import threading
import time
import uuid

from .builder import compile_profiles, resolve_build
from .config import load_cases
from .evidence import make_evidence
from .oracle import collect_reference, evaluate
from .report import write_report
from .runner import decode, environment, remaining_timeout, run_process
from .validator import accept_candidate, failures
from .workspace import apply_candidate, digest, snapshot, write_json


@contextmanager
def commit_without_interrupts():
    """Deliver cancellation after source promotion and its counters agree."""
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGALRM})
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def install_deadline(seconds):
    """Bound even a trickling network response; CLI runs on the main thread."""
    if platform.system() != "Linux":
        return lambda: None  # preflight reports unsupported platforms
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("run the dynamic controller in a separate process, not a worker thread")
    if signal.getitimer(signal.ITIMER_REAL)[0]:
        raise RuntimeError("an existing process alarm conflicts with the runtime deadline")
    previous = signal.getsignal(signal.SIGALRM)
    def expired(signum, frame):
        raise TimeoutError("total run time budget exhausted")
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    def restore():
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    return restore


def promote(candidate, root):
    suffix = uuid.uuid4().hex[:8]
    next_best, best, previous = root / ("best-next-" + suffix), root / "best", root / ("best-previous-" + suffix)
    try:
        shutil.copytree(candidate, next_best)
        if best.exists():
            best.rename(previous)
        next_best.rename(best)
    except BaseException:
        if previous.exists() and not best.exists():
            previous.rename(best)
        raise
    finally:
        # Failed staging must not poison later attempts. Cleanup after commit
        # cannot turn a successful version switch into a rejected patch.
        if next_best.exists():
            shutil.rmtree(next_best, ignore_errors=True)
    if previous.exists():
        shutil.rmtree(previous, ignore_errors=True)


def best_builds(root):
    return {profile: {"binary": str(root / "best" / profile / "program")}
            for profile in ("normal", "instrumented")}


def preflight(config, root):
    if platform.system() != "Linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        raise OSError("V1 runtime backend requires Linux x86-64 (including WSL2)")
    compiler = shutil.which(config["build"]["compiler"])
    if not compiler:
        raise OSError("C compiler not found: " + config["build"]["compiler"])
    config["build"]["compiler"] = str(Path(compiler).resolve())
    version = run_process([compiler, "--version"], root, remaining_timeout(config, 10), 65536)
    probe = root / "probe"
    probe.mkdir()
    (probe / "probe.c").write_text("int main(void) { return 0; }\n")
    binary = probe / "probe"
    built = run_process([compiler, "-g", "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
                         str(probe / "probe.c"), "-o", str(binary)], probe, remaining_timeout(config, 30), 65536)
    if built["exit_code"] != 0 or built["state"] != "exited":
        raise OSError("sanitizer compilation unavailable: " + decode(built["stderr"]).decode("utf-8", "replace"))
    runs = [run_process([binary], probe, remaining_timeout(config, 5), 65536, env=environment(config, True)) for _ in range(2)]
    write_json(probe / "checks.json", {"build": built, "runs": runs})
    if any(r["exit_code"] != 0 or r["state"] != "exited" or decode(r["stderr"]) for r in runs):
        raise OSError("ASan/UBSan runtime preflight failed; see probe/checks.json")
    return decode(version["stdout"]).decode("utf-8", "replace")


def run(config, evaluation_manifest=None, progress=print):
    config = copy.deepcopy(config)
    name = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
    root = Path(config["artifacts"]["output_dir"]) / name
    root.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    result = {"schema_version": 1, "project_id": config["project_id"], "run_dir": str(root),
              "status": "UNVERIFIED", "reason": "", "attempts": [], "accepted_count": 0,
              "llm_requests": 0, "reserved_tokens": 0, "repair_results": {}, "evaluation_results": None,
              "validation_scope": "Executed cases only; not a proof of semantic equivalence."}
    write_json(root / "manifest.json", {"config": config})
    progress("动态修复运行目录: " + str(root))
    stage = "environment"
    restore_deadline = lambda: None
    try:
        config["_deadline"] = started + config["repair"]["max_total_seconds"]
        restore_deadline = install_deadline(config["repair"]["max_total_seconds"])
        compiler_version = preflight(config, root)
        stage = "inputs"
        baseline = root / "baseline"
        inventory = snapshot(Path(config["target"]["source_dir"]), baseline / "source")
        resolve_build(config, inventory)
        repair_path = config["tests"]["repair_manifest"]
        reference_path = config["target"]["reference_binary"]
        manifest = {"schema_version": 1, "config": {k: v for k, v in config.items() if not k.startswith("_")},
                    "source_sha256": inventory, "python": sys.version, "platform": platform.platform(),
                    "compiler_version": compiler_version, "tool_sha256": {},
                    "reference_sha256": None, "repair_manifest_sha256": None,
                    "evaluation_manifest_sha256": None,
                    "model": os.environ.get("LLM_MODEL", "deepseek-chat") if config["repair"]["proposer"] == "llm" else None}
        for tool in sorted(Path(__file__).parent.glob("*.py")):
            manifest["tool_sha256"][tool.name] = digest(tool)
        manifest["tool_sha256"]["llm.py"] = digest(Path(__file__).parents[1] / "llm.py")
        if not repair_path or not reference_path:
            result["reason"] = "reference binary and nonempty repair manifest are required"
            write_json(root / "manifest.json", manifest)
            return result
        cases = load_cases(repair_path)
        inputs = root / "inputs"
        inputs.mkdir()
        shutil.copy2(reference_path, inputs / "reference")
        reference = inputs / "reference"
        with reference.open("rb") as stream:
            header = stream.read(20)
        if len(header) < 20 or header[:6] != b"\x7fELF\x02\x01" or int.from_bytes(header[18:20], "little") != 62 or int.from_bytes(header[16:18], "little") not in (2, 3):
            raise ValueError("reference must be a Linux x86-64 executable ELF, not a relocatable object")
        reference.chmod(0o700)
        write_json(inputs / "repair.json", {"schema_version": 1, "cases": cases})
        manifest["reference_sha256"] = digest(reference)
        manifest["repair_manifest_sha256"] = digest(inputs / "repair.json")
        # Hash now, load evaluation contents only after the repair loop has finished.
        if evaluation_manifest:
            manifest["evaluation_manifest_sha256"] = digest(evaluation_manifest)
        write_json(root / "manifest.json", manifest)
        stage = "reference"
        expected, records = collect_reference(reference, cases, config)
        write_json(baseline / "reference.json", records)
        stage = "build"
        builds = compile_profiles(baseline / "source", baseline, config)
        if not all(b["ok"] for b in builds.values()):
            result.update(status="STATIC_BLOCKED", reason="baseline normal or instrumented compilation failed")
            return result
        stage = "repair"
        current = evaluate(builds, cases, expected, config)
        write_json(baseline / "cases.json", current)
        promote(baseline, root)
        result["baseline_results"] = current
        result["repair_results"] = current
        proposer = None
        replay = []
        settings = config["repair"]
        if failures(current) and settings["proposer"] == "llm":
            from llm import LLMProposer
            proposer = LLMProposer()
            if not proposer._available():
                result.update(status="ENVIRONMENT_ERROR", reason="LLM_API_KEY is not configured; baseline evaluation is retained")
                return result
        elif settings["proposer"] == "replay":
            replay = json.loads(Path(settings["replay_file"]).read_text(encoding="utf-8"))
            if not isinstance(replay, list):
                raise ValueError("replay file must be a list of patch lists, one per attempt")
            manifest["replay_sha256"] = digest(settings["replay_file"])
            write_json(inputs / "replay.json", replay)
            write_json(root / "manifest.json", manifest)
        no_progress = 0
        stop = "repair tests already passed" if not failures(current) else "evaluation only"
        for index in range(settings["max_attempts"]):
            if not failures(current) or settings["proposer"] == "none":
                break
            remaining_timeout(config, 1)
            if no_progress >= settings["max_no_progress"]:
                stop = "no-progress budget exhausted"
                break
            if settings["proposer"] == "replay" and index >= len(replay):
                stop = "replay exhausted"
                break
            evidence = make_evidence(root / "best" / "source", inventory, cases, expected, current)
            completion = settings["max_completion_tokens"]
            if proposer:
                from llm import RUNTIME_PROMPT
                # Conservative byte reservation, not an exact tokenizer/billing estimate.
                reservation = len((RUNTIME_PROMPT + json.dumps(evidence, ensure_ascii=False)).encode("utf-8")) + completion + 1024
                if result["llm_requests"] >= settings["max_llm_calls"] or result["reserved_tokens"] + reservation > settings["max_total_tokens"]:
                    stop = "LLM call/token reservation budget exhausted"
                    break
                result["llm_requests"] += 1
                result["reserved_tokens"] += reservation  # Failed requests consume reservation too.
                proposer.timeout = remaining_timeout(config, 120)
            attempt = root / "attempts" / ("%04d" % (index + 1))
            attempt.mkdir(parents=True)
            row = {"attempt": index + 1, "accepted": False, "reason": ""}
            result["attempts"].append(row)
            write_json(attempt / "evidence.json", evidence)
            progress("候选补丁 %d：生成并验证" % (index + 1))
            try:
                patches = proposer.propose_runtime_fix(evidence, completion) if proposer else replay[index]
                write_json(attempt / "patches.json", patches)
                shutil.copytree(root / "best" / "source", attempt / "source")
                diff = apply_candidate(attempt / "source", patches, inventory, settings["max_files_per_patch"])
                (attempt / "patch.diff").write_text(diff, encoding="utf-8")
                proposed_builds = compile_profiles(attempt / "source", attempt, config)
                if not all(b["ok"] for b in proposed_builds.values()):
                    row["reason"] = "candidate compilation failed"
                else:
                    proposed = evaluate(proposed_builds, cases, expected, config)
                    write_json(attempt / "cases.json", proposed)
                    eligible, row["reason"] = accept_candidate(current, proposed)
                    if eligible:
                        with commit_without_interrupts():
                            promote(attempt, root)
                            row["accepted"] = True
                            current = proposed
                            result["repair_results"] = current
                            result["accepted_count"] += 1
                            with (root / "accepted_patches.jsonl").open("a", encoding="utf-8") as stream:
                                stream.write(json.dumps({"attempt": index + 1, "patches": patches}, ensure_ascii=False) + "\n")
            except TimeoutError as exc:
                if not row["accepted"]:
                    row["reason"] = str(exc)
                raise
            except KeyboardInterrupt:
                if not row["accepted"]:
                    row["reason"] = "cancelled before candidate acceptance"
                raise
            except (ValueError, OSError, RuntimeError) as exc:
                row["reason"] = str(exc)
            finally:
                write_json(attempt / "decision.json", row)
                if not row["accepted"] and not config["artifacts"]["keep_rejected_candidates"]:
                    if (attempt / "source").exists():
                        shutil.rmtree(attempt / "source")
                    for profile in ("normal", "instrumented"):
                        (attempt / profile / "program").unlink(missing_ok=True)
                if proposer:
                    result["llm_usage"] = proposer.usage()
            progress(("接受" if row["accepted"] else "拒绝") + "：" + row["reason"])
            no_progress = 0 if row["accepted"] else no_progress + 1
            stop = "attempt budget exhausted"
        if failures(current):
            result.update(status="PARTIAL" if result["accepted_count"] else "NO_PROGRESS", reason=stop)
        else:
            result.update(status="REPAIR_TESTS_PASSED", reason="repair cases passed; independent evaluation not supplied")
        # No more proposals after this point, even if held-out evaluation fails.
        if evaluation_manifest:
            stage = "evaluation"
            if digest(evaluation_manifest) != manifest["evaluation_manifest_sha256"]:
                raise ValueError("evaluation manifest changed during repair")
            heldout = load_cases(evaluation_manifest)
            def input_key(case):
                return json.dumps({k: case[k] for k in ("args", "stdin", "files")}, sort_keys=True)
            repair_inputs = {input_key(c) for c in cases}
            if any(input_key(c) in repair_inputs for c in heldout):
                raise ValueError("independent evaluation must not repeat repair inputs")
            oracle, records = collect_reference(reference, heldout, config)
            write_json(root / "evaluation_reference.json", records)
            write_json(root / "evaluation_manifest.json", {"schema_version": 1, "cases": heldout})
            evaluated = evaluate(best_builds(root), heldout, oracle, config)
            result["evaluation_results"] = evaluated
            if not failures(current) and not failures(evaluated):
                result.update(status="TEST_VALIDATED", reason="repair and independent evaluation cases passed")
            else:
                result.update(status="PARTIAL" if result["accepted_count"] else "NO_PROGRESS", reason="remaining failures on repair or independent evaluation cases")
    except KeyboardInterrupt:
        result.update(status="CANCELLED", reason="cancelled; original source and accepted best snapshot retained")
    except TimeoutError as exc:
        result.update(status="PARTIAL" if result["accepted_count"] else "NO_PROGRESS", reason=str(exc))
    except (ValueError, OSError, RuntimeError) as exc:
        result.update(status="UNVERIFIED" if stage in ("reference", "evaluation") else "ENVIRONMENT_ERROR", reason=str(exc))
    finally:
        restore_deadline()
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        if (root / "best" / "source").exists():
            result["best_source_sha256"] = {p.relative_to(root / "best" / "source").as_posix(): digest(p)
                                            for p in sorted((root / "best" / "source").rglob("*")) if p.is_file()}
            result["best_binary_sha256"] = {profile: digest(root / "best" / profile / "program")
                                            for profile in ("normal", "instrumented")}
        config.pop("_deadline", None)
        write_report(root, result)
        progress("最终状态: %s；报告: %s" % (result["status"], root / "report.html"))
    return result
