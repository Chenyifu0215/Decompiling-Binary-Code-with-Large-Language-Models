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

import json
import os
import re
import urllib.request
from pathlib import Path

from patch import load_patches


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
Given a list of compiler errors and the relevant source files, propose the
minimal set of patches that fixes those errors.

Reply ONLY with a JSON object of this exact shape:
{"patches": [
  {"op": "replace", "file": "apply_op.c", "old": "exact old text", "new": "replacement"},
  {"op": "regex", "file": "apply_op.c", "pattern": "regex", "repl": "replacement", "count": 0}
]}

Rules:
- "replace" replaces an exact substring; "regex" uses Python re.subn.
- "count" defaults to 0 (replace all); use 1 for a single occurrence.
- Only emit patches for the errors shown. Do not rename functions or refactor.
- If no change is needed, return {"patches": []}.
- Common Ghidra decompilation errors and how to fix them:
  - "assignment to expression with array type": a variable was decompiled as a
    byte array but assigned like a scalar. Either index the array (`buf[0]=x`)
    or change the declaration to a pointer/scalar.
  - "invalid type argument of unary '*'" with "long int"/"undefined8": the value
    is a pointer decompiled as an integer. Cast it to a pointer type before
    dereferencing, e.g. `*(char **)x` instead of `*x`.
  - "invalid operands to binary &" with "unsigned char *": the value is a pointer
    used with bitwise &; cast it to an integer, e.g. `(unsigned long)x & y`.
  - "unknown type name 'X'": replace X with a known type (byte, uint, ulong,
    ulonglong, char, int, long, short, size_t, ...).
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


def _strip_code_fence(text):
    m = _FENCE_RE.match(text)
    return m.group(1).strip() if m else text


class LLMProposer:
    def __init__(self, base_url=None, api_key=None, model=None, timeout=120):
        self.base_url = (
            base_url or os.environ.get("LLM_BASE_URL", "https://api.deepseek.com/v1")
        ).rstrip("/")
        self.api_key = api_key or os.environ.get("LLM_API_KEY", "")
        self.model = model or os.environ.get("LLM_MODEL", "deepseek-chat")
        self.timeout = timeout

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
        raw = (body.get("choices") or [{}])[0].get("message", {}).get("content") or ""
        text = _strip_code_fence(raw)
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise RuntimeError("LLM returned non-JSON content: %r" % raw) from e

    def propose(self, errors, build_dir):
        if not self._available():
            raise RuntimeError(
                "LLMProposer needs LLM_API_KEY (and optionally LLM_BASE_URL / LLM_MODEL). "
                "Use --proposer fallback instead."
            )
        context = self._build_context(errors, build_dir)
        data = self._chat_json(SYSTEM_PROMPT, context)
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
        if not ret or not isinstance(params, list) or not params:
            return None
        params = [str(p).strip() for p in params if str(p).strip()]
        if not params:
            return None
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

    def _build_context(self, errors, build_dir):
        files = {}
        for err in errors:
            fname = err.get("file")
            if not fname or fname in files:
                continue
            path = Path(build_dir) / fname
            if path.is_file():
                files[fname] = path.read_text(encoding="utf-8", errors="replace").splitlines()

        parts = ["Compiler errors:"]
        for err in errors:
            parts.append("  %(file)s:%(line)s:%(col)s %(kind)s: %(message)s" % err)

        # 对每个报错，给报错行附近的前后 30 行上下文（>> 标记报错行）
        for err in errors:
            fname = err.get("file")
            lines = files.get(fname)
            if not lines:
                continue
            ln = err.get("line", 0)
            start = max(0, ln - 30)
            end = min(len(lines), ln + 30)
            parts.append("\n===== %s (lines %d-%d) =====" % (fname, start + 1, end))
            for i in range(start, end):
                marker = ">>" if i == ln - 1 else "  "
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
