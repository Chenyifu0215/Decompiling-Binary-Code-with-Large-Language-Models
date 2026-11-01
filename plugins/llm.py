#!/usr/bin/env python3
"""llm.py - Patch proposers for the static-repair loop.

Two implementations, same interface `propose(errors, build_dir) -> list[patches]`:

    FallbackProposer  -- deterministic rule library (no network / no key).
                        The "safety net" that always works, and the baseline
                        for the loop to be tested end-to-end without an LLM.

    LLMProposer       -- calls an OpenAI-compatible chat/completions endpoint
                        (works for OpenAI, DeepSeek, local Ollama/vLLM, ...).
                        Configured via env vars; see `make_proposer`.

The rule library grows over time: every fix that an LLM keeps re-proposing can
be distilled into a FallbackProposer rule so it no longer costs a model call.
"""

import concurrent.futures
import hashlib
import json
import logging
import os
import re
import urllib.request
from pathlib import Path

from patch import load_patches

LOG = logging.getLogger("llm")

# How many chat/completions requests may be in flight at once.  A repair round
# is split by file, so the groups are independent; the patches are still
# applied in order afterwards ("fetch in parallel, apply serially").
try:
    _MAX_PARALLEL = max(1, int(os.environ.get("LLM_CONCURRENCY", "4")))
except ValueError:
    _MAX_PARALLEL = 4
# Splitting a round into N requests repeats the system prompt N times and makes
# the model re-emit its reasoning per group, so it is only worth it when one
# request would be too large (context window) -- measured on a 3.2 KB round:
# 1 call 9-16 s / 1.4 k prompt tokens vs 4 groups 17-52 s / 2.8 k prompt tokens.
# Default split threshold therefore keeps normal rounds as ONE request.
try:
    _SPLIT_MIN_CHARS = max(0, int(os.environ.get("LLM_SPLIT_CHARS", "6000")))
except ValueError:
    _SPLIT_MIN_CHARS = 6000

# Response cache: keyed by sha256(model + system + user).  Replaying the same
# error set costs nothing and yields byte-identical patches (which also makes
# the repair loop reproducible despite the model's own non-determinism).
# Disable with LLM_CACHE=0; relocate with LLM_CACHE_DIR.
_CACHE_ENABLED = os.environ.get("LLM_CACHE", "1").strip().lower() not in (
    "0", "false", "no")
_CACHE_DIR = Path(os.environ.get("LLM_CACHE_DIR")
                  or (Path.home() / ".cache" / "decompile-llm"))


# --------------------------------------------------------------------------- #
# Fallback rule library
# --------------------------------------------------------------------------- #
#
# Each rule: {"match": <regex on the compiler error message>,
#             "patches": [ <patch dicts> ]}
# A patch dict may omit "file"; it is filled in from the error's file field.

DEFAULT_RULES = [
    {
        "name": "slice-syntax",
        "match": r"request for member",
        "patches": [
            {
                "op": "regex",
                "pattern": r"(\b[A-Za-z_]\w*)\._(\d+)_(\d+)_",
                "repl": r"*(undefined\3 *)((char *)\1 + \2)",
                "count": 0,
            },
        ],
    },
    # Add more rules here as new failure modes are catalogued. Each rule that
    # an LLM keeps proposing can be distilled into this library to avoid a
    # model round-trip next time.
]


class FallbackProposer:
    def __init__(self, rules=None):
        self.rules = rules if rules is not None else DEFAULT_RULES

    def propose(self, errors, build_dir):
        patches = []
        seen = set()
        for err in errors:
            msg = err.get("message", "")
            for rule in self.rules:
                if not re.search(rule["match"], msg):
                    continue
                for p in rule["patches"]:
                    p = dict(p)
                    p.setdefault("file", err.get("file"))
                    key = json.dumps(p, sort_keys=True)
                    if key in seen:
                        continue
                    seen.add(key)
                    patches.append(p)
                break
        return patches


# --------------------------------------------------------------------------- #
# LLM proposer (OpenAI-compatible chat/completions)
# --------------------------------------------------------------------------- #

SYSTEM_PROMPT = """You repair decompiled C code so it compiles with gcc.
Given compiler errors and the relevant source snippets, propose the minimal
set of patches that fixes those errors.

Reply ONLY with a JSON object of this exact shape:
{"patches": [
  {"op": "replace", "file": "apply_op.c", "old": "exact old text", "new": "replacement"},
  {"op": "regex", "file": "apply_op.c", "pattern": "regex", "repl": "replacement", "count": 0}
]}

Rules:
- "replace" replaces an exact substring; "regex" uses Python re.subn.
- "old" must be the SHORTEST substring that occurs exactly once in the file
  (usually one line, at most ~200 chars). Never paste a whole block: split it
  into several "replace" patches, or use one short "regex".
- "count" defaults to 0 (replace all); use 1 for a single occurrence.
- Only emit patches for the errors shown. Do not rename functions or refactor.
- If no change is needed, return {"patches": []}.
- Typical Ghidra decompilation errors:
  - "assignment to expression with array type": array assigned like a scalar;
    index it (`buf[0]=x`) or change the declaration to a pointer/scalar.
  - "invalid type argument of unary '*'" with long/undefined8: pointer stored
    as an integer; cast it (`*(char **)x`).
  - "invalid operands to binary &": pointer in a bitwise op; cast to an
    integer (`(unsigned long)x & y`).
  - "unknown type name 'X'": use a known type (byte, uint, ulong, ulonglong,
    char, int, long, short, size_t).
"""


SIGNATURE_PROMPT = """You are a reverse engineer specialized in x86-64 disassembly
and function signature recovery. Given a function's disassembly, decompiled
pseudocode and cross-references (call sites), infer its exact C signature.

x86-64 calling convention: the first 6 integer args are RDI, RSI, RDX, RCX, R8, R9.
The instructions right before each call site show the actual arguments passed
(e.g. "PUSH 0xa; POP RDX" means the 3rd argument is 10, i.e. a numeric base).

Reply ONLY with a JSON object of this exact shape:
{"return_type": "unsigned int", "params": ["char *arg", "char **endptr", "int base"]}

Rules:
- Do NOT use the `const` keyword (Ghidra's parser does not support it).
- Do NOT use glibc/glibc-internal typedef names (e.g. __sighandler_t, sighandler_t,
  __off_t, __pid_t, __time_t). For function-pointer parameters, degrade them to
  `void *` (Ghidra's parser cannot resolve those typedefs or function-pointer types).
- Infer parameter count and types from the register usage and call sites.
- TYPE PROPAGATION: if the function calls library functions whose signatures are
  listed below (under "callee anchors"), propagate their parameter types back:
  e.g. if it calls `strlen(x)` and strlen's signature is `size_t strlen(char *)`,
  then `x` is `char *`; if `x` is itself a parameter, that parameter is `char *`.
  Use this to sharpen your inferred parameter types.
- If you cannot infer, still output your best guess.
"""


TYPE_FIX_PROMPT = """You are a reverse engineer. Given a decompiled function's
pseudocode, assembly, call sites and compiler errors, generate patches that fix
type errors INSIDE the function body (Ghidra decompiled a struct as a byte array,
a pointer as a long integer, etc.).

Reply ONLY with a JSON object of this exact shape:
{"patches": [{"op": "replace", "file": "xxx.c", "old": "exact old text", "new": "replacement"}]}

Rules:
- "replace" replaces an exact substring (must match the pseudocode exactly, including indentation).
- Fix type errors only:
  - "assignment to expression with array type": a variable was declared as an array
    but assigned like a scalar; change the declaration to a pointer/scalar.
  - "invalid type argument of unary '*'": a value is a pointer decompiled as an
    integer; change the declaration to a pointer, or cast at the dereference.
  - "invalid operands to binary &" / "|" / "<<": a pointer used with bitwise ops;
    cast it to an integer, e.g. `(unsigned long)x & y`.
  - "request for member": a struct was decompiled as a byte array; change the
    declaration to a pointer and use indexed/offset access.
- Do NOT rename functions or change signatures.
- If you cannot fix, return {"patches": []}.
"""


_FENCE_RE = re.compile(r"^\s*```[^\n]*\n?(.*?)\n?```\s*$", re.DOTALL)
_QUOTED_IDENT = re.compile(r"'([A-Za-z_][\w$]*)'")


def _strip_code_fence(text):
    m = _FENCE_RE.match(text)
    return m.group(1).strip() if m else text


def _dedupe_errors(errors):
    """Drop exact duplicate diagnostics (make/gcc repeat the same error)."""
    seen, out = set(), []
    for e in errors:
        key = (e.get("file"), e.get("line"), e.get("col"), e.get("message"))
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


def _split_by_file(errors, limit):
    """Split diagnostics into at most `limit` groups, never splitting a file.

    Each group becomes one independent request; patches are merged back in
    order, so two groups can never touch the same file.
    """
    by_file = {}
    for e in errors:
        by_file.setdefault(e.get("file") or "", []).append(e)
    if limit <= 1 or len(by_file) <= 1:
        return [errors] if errors else []
    buckets = [[] for _ in range(min(limit, len(by_file)))]
    for i, (_fname, errs) in enumerate(sorted(by_file.items())):
        buckets[i % len(buckets)].extend(errs)
    return [b for b in buckets if b]


def _merge_patches(patches):
    """Drop byte-identical duplicates coming from different groups."""
    seen, out = set(), []
    for p in patches:
        key = json.dumps(p, sort_keys=True, ensure_ascii=False)
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def _cache_path(key):
    return _CACHE_DIR / key[:2] / (key + ".json")


def _cache_load(key):
    if not _CACHE_ENABLED:
        return None
    try:
        return json.loads(_cache_path(key).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _cache_store(key, data):
    if not _CACHE_ENABLED:
        return
    path = _cache_path(key)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass


class LLMProposer:
    def __init__(self, base_url=None, api_key=None, model=None, timeout=120):
        self.base_url = (
            base_url or os.environ.get("LLM_BASE_URL", "https://api.deepseek.com/v1")
        ).rstrip("/")
        self.api_key = api_key or os.environ.get("LLM_API_KEY", "")
        self.model = model or os.environ.get("LLM_MODEL", "deepseek-chat")
        self.timeout = timeout
        self.stats = {"calls": 0, "cache_hits": 0,
                      "prompt_tokens": 0, "completion_tokens": 0}

    def usage(self):
        """Token / cache counters accumulated by this proposer instance."""
        return dict(self.stats)

    def _available(self):
        return bool(self.api_key)

    def _chat_json(self, system, user):
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }
        budget = os.environ.get("LLM_MAX_TOKENS")
        if budget:
            try:
                payload["max_tokens"] = int(budget)
            except ValueError:
                pass

        key = hashlib.sha256(
            ("%s\x00%s\x00%s" % (self.model, system, user)).encode("utf-8")
        ).hexdigest()
        cached = _cache_load(key)
        if cached is not None:
            self.stats["cache_hits"] += 1
            LOG.info("LLM cache hit (model=%s key=%s)", self.model, key[:12])
            return cached

        req = urllib.request.Request(
            self.base_url + "/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + self.api_key,
            },
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))

        usage = body.get("usage") or {}
        self.stats["calls"] += 1
        self.stats["prompt_tokens"] += int(usage.get("prompt_tokens") or 0)
        self.stats["completion_tokens"] += int(usage.get("completion_tokens") or 0)
        LOG.info(
            "LLM usage: model=%s prompt=%s completion=%s total=%s (input chars=%d)",
            self.model, usage.get("prompt_tokens"),
            usage.get("completion_tokens"), usage.get("total_tokens"),
            len(system) + len(user),
        )

        raw = (body.get("choices") or [{}])[0].get("message", {}).get("content") or ""
        text = _strip_code_fence(raw)
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise RuntimeError("LLM returned non-JSON content: %r" % raw) from e
        _cache_store(key, data)
        return data

    def propose(self, errors, build_dir):
        if not self._available():
            raise RuntimeError(
                "LLMProposer needs LLM_API_KEY (and optionally LLM_BASE_URL / LLM_MODEL). "
                "Use --proposer fallback instead."
            )
        errors = _dedupe_errors(errors)
        context = self._build_context(errors, build_dir)
        groups = _split_by_file(errors, _MAX_PARALLEL)
        if (_MAX_PARALLEL <= 1 or len(groups) <= 1
                or len(context) < _SPLIT_MIN_CHARS):
            return self._validate_patches(self._chat_json(SYSTEM_PROMPT, context))

        LOG.info("LLM propose: %d error(s), %d chars, %d parallel group(s)",
                 len(errors), len(context), len(groups))
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(groups)) as pool:
            futures = [
                pool.submit(self._chat_json, SYSTEM_PROMPT,
                            self._build_context(group, build_dir))
                for group in groups
            ]
            results = [f.result() for f in futures]
        patches = []
        for data in results:
            patches.extend(self._validate_patches(data))
        return _merge_patches(patches)

    @staticmethod
    def _validate_patches(data):
        patches = data.get("patches", [])
        if not isinstance(patches, list):
            raise RuntimeError("LLM returned malformed patches: %r" % data)
        return patches

    def infer_signature(self, func_name, current_sig, c_code, asm, xrefs, callee_ctx=None):
        """Infer a function signature from evidence; return (ret, params) or None.

        callee_ctx: 可选文本，列出本函数调用的已知签名函数（用于类型传播）。
        """
        if not self._available():
            return None
        parts = [
            "函数名: %s" % func_name,
            "当前 Ghidra 推断签名: %s" % current_sig,
            "",
            "伪代码:",
            c_code,
            "",
            "汇编:",
            asm,
            "",
            "调用点(交叉引用):",
            xrefs,
        ]
        if callee_ctx:
            parts += [
                "",
                "本函数调用的已知签名函数(可据此做类型传播):",
                callee_ctx,
            ]
        prompt = "\n".join(parts)
        try:
            data = self._chat_json(SIGNATURE_PROMPT, prompt)
        except Exception:
            return None
        ret = str(data.get("return_type", "")).strip()
        params = data.get("params")
        if not ret or not isinstance(params, list):
            return None
        params = [str(p).strip() for p in params if str(p).strip()]
        return ret, params

    def infer_type_fixes(self, func_name, c_code, asm, xrefs, errors):
        """从证据推断函数体内部类型修复补丁；返回 patches 列表或 None。"""
        if not self._available():
            return None
        err_lines = "\n".join("  %s:%s: %s" % (e.get("file"), e.get("line"), e.get("message"))
                              for e in errors)
        prompt = (
            "函数名: %s\n\n伪代码:\n%s\n\n汇编:\n%s\n\n调用点:\n%s\n\n编译错误:\n%s"
        ) % (func_name, c_code, asm, xrefs, err_lines)
        try:
            data = self._chat_json(TYPE_FIX_PROMPT, prompt)
        except Exception:
            return None
        patches = data.get("patches", [])
        if not isinstance(patches, list) or not patches:
            return None
        return patches

    _WINDOW = 5        # context lines around the outermost error lines
    _MAX_WINDOW = 40   # hard cap of code lines per file
    _HEADER_LINES = 8  # for diagnostics without a line number (link errors)

    def _symbol_line(self, lines, errs):
        """First line mentioning a quoted identifier from a line-less diagnostic
        (e.g. `undefined reference to '__printf_chk_00101130'`).  Returns 0 when
        nothing matches."""
        for e in errs:
            m = _QUOTED_IDENT.search(e.get("message", ""))
            if not m:
                continue
            name = m.group(1)
            for i, line in enumerate(lines):
                if name in line:
                    return i + 1
        return 0

    def _build_context(self, errors, build_dir):
        """One error list + ONE code window PER FILE.

        The previous version appended a 60-line window for *every* error, so a
        file with N errors was repeated N times (O(errors x 60) tokens, and
        prompts overflowed on error-heavy binaries).  The window now spans all
        error lines of a file at once and is capped, so the cost is O(files)
        instead of O(errors).
        """
        errors = _dedupe_errors(errors)
        # `make -j` emits diagnostics in a non-deterministic order; sort them so
        # that the prompt (and therefore the cache key) is stable across runs.
        errors.sort(key=lambda e: (e.get("file") or "", e.get("line") or 0,
                                   e.get("col") or 0, e.get("message") or ""))
        by_file = {}
        for err in errors:
            by_file.setdefault(err.get("file") or "", []).append(err)

        parts = ["Compiler errors:"]
        for fname, errs in by_file.items():
            for e in errs:
                parts.append("  %s:%s:%s %s: %s" % (
                    fname or "?", e.get("line", 0), e.get("col", 0),
                    e.get("kind", "error"), e.get("message", "")))

        for fname, errs in by_file.items():
            if not fname:
                continue
            path = Path(build_dir) / fname
            if not path.is_file():
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            marks = sorted({e.get("line") or 0 for e in errs} - {0})
            if marks:
                lo = max(1, marks[0] - self._WINDOW)
                hi = min(len(lines), marks[-1] + self._WINDOW)
            else:
                # 链接错误没有行号：定位被引用的符号所在行，只给 ±2 行
                at = self._symbol_line(lines, errs)
                if at:
                    lo, hi = max(1, at - 2), min(len(lines), at + 2)
                else:
                    lo, hi = 1, min(len(lines), self._HEADER_LINES)
            note = ""
            if marks and hi - lo + 1 > self._MAX_WINDOW:
                hi = lo + self._MAX_WINDOW - 1
                note = ", truncated"
            parts.append("\n===== %s (lines %d-%d%s) =====" % (fname, lo, hi, note))
            for i in range(lo - 1, hi):
                marker = ">>" if (i + 1) in marks else "  "
                parts.append("%s %4d | %s" % (marker, i + 1, lines[i]))

        return "\n".join(parts)


def make_proposer(name, **kwargs):
    if name == "fallback":
        rules = kwargs.get("rules")
        rf = kwargs.get("rules_file")
        if isinstance(rf, str):
            if not Path(rf).is_file():
                raise FileNotFoundError("fallback rules file not found: %s" % rf)
            rules = load_patches(rf)
        return FallbackProposer(rules=rules)
    if name == "llm":
        return LLMProposer(
            base_url=kwargs.get("base_url"),
            api_key=kwargs.get("api_key"),
            model=kwargs.get("model"),
        )
    raise ValueError("unknown proposer: %r (use 'fallback' or 'llm')" % name)
