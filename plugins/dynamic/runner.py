"""Bounded POSIX subprocess execution; process groups are cleaned on every exit."""
import base64
import hashlib
import os
from pathlib import Path
import selectors
import signal
import subprocess
import tempfile
import time


def encode(data):
    return base64.b64encode(data).decode("ascii")


def decode(data):
    return base64.b64decode(data)


def run_process(argv, cwd, timeout, limit, stdin=b"", env=None):
    start = time.monotonic()
    chunks = {"stdout": bytearray(), "stderr": bytearray()}
    state = "exited"
    proc = subprocess.Popen([str(x) for x in argv], cwd=cwd, env=env,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=True)
    selector = selectors.DefaultSelector()
    sent = 0
    try:
        for stream, name in ((proc.stdout, "stdout"), (proc.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        if stdin:
            os.set_blocking(proc.stdin.fileno(), False)
            selector.register(proc.stdin, selectors.EVENT_WRITE, "stdin")
        else:
            proc.stdin.close()
        while selector.get_map() or proc.poll() is None:
            if time.monotonic() - start >= timeout:
                state = "timeout"
                break
            for key, _ in selector.select(min(.05, max(.001, timeout - (time.monotonic() - start)))):
                if key.data == "stdin":
                    try:
                        sent += os.write(key.fd, stdin[sent:sent + 4096])
                    except BrokenPipeError:
                        sent = len(stdin)
                    if sent == len(stdin):
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    continue
                block = os.read(key.fd, 65536)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                remaining = limit - sum(len(v) for v in chunks.values())
                chunks[key.data].extend(block[:remaining])
                if len(block) > remaining:
                    state = "output_limit"
                    break
            if state != "exited":
                break
    finally:
        # Also clean children that inherited pipes after the direct child exited.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        selector.close()
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            stream.close()
    return {"state": state, "exit_code": proc.returncode,
            "stdout": encode(chunks["stdout"]), "stderr": encode(chunks["stderr"]),
            "elapsed_seconds": round(time.monotonic() - start, 6)}


def environment(config, instrumented=False):
    # Do not pass credentials, loader options or host sanitizer settings to samples.
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "TZ": "UTC"}
    env.update(config["execution"]["environment"])
    if instrumented:
        env["ASAN_OPTIONS"] = "detect_leaks=1:halt_on_error=1:abort_on_error=0:symbolize=1"
        env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    return env


def remaining_timeout(config, requested):
    left = config.get("_deadline", float("inf")) - time.monotonic()
    if left <= 0:
        raise TimeoutError("total run time budget exhausted")
    return min(requested, left)


def run_case(binary, case, config, instrumented=False):
    execution = config["execution"]
    timeout = execution["instrumented_timeout_seconds" if instrumented else "timeout_seconds"]
    limit = execution["max_output_bytes"]
    with tempfile.TemporaryDirectory(prefix="dynamic-case-") as directory:
        root = Path(directory)
        for name, content in case["files"].items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        result = run_process([binary, *case["args"]], root,
                             remaining_timeout(config, timeout), limit,
                             case["stdin"].encode("utf-8"), environment(config, instrumented))
        outputs = {}
        total = 0
        for name in case["output_files"]:
            path = root / name
            if path.is_symlink() or root not in path.resolve().parents:
                result["state"] = "invalid_output_file"
                outputs[name] = None
            elif not path.exists():
                outputs[name] = None
            elif not path.is_file() or path.stat().st_size + total > limit:
                result["state"] = "output_limit"
                outputs[name] = None
            else:
                with path.open("rb") as stream:
                    content = stream.read(limit - total + 1)
                total += len(content)
                if total > limit:
                    result["state"] = "output_limit"
                outputs[name] = {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        result["output_files"] = outputs
        return result
