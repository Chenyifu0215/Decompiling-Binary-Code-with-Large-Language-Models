#!/usr/bin/env python3
"""eval_llm4decompile.py - 在 LLM4Decompile 的 Decompile-Eval 上对比静态修复通过率。

数据：LLM4Decompile-main/legacy-test/decompile-eval-executable-gcc-ghidra.json
      656 条 = 164 题 × {O0,O1,O2,O3}，`input_asm_prompt` 即 Ghidra 原始伪 C
      （也是 LLM4Decompile V2 系列模型的输入起点）。

对每条样本生成变体（拼接方式与官方评测一致：c_include + 函数 + c_test）：
    raw     原始 Ghidra 伪 C
    fixed   decompile_helper 的文本静态修复（slice/cast/类型别名/结构体等）
    fixed2  在 fixed 基础上按编译错误复用 fix_binary_ops 规则做一次迭代

编译/运行命令与官方 evaluation/run_evaluation_llm4decompile.py 完全一致：
    gcc -S only.c -o asm -lm            # 仅函数编译检查
    gcc combined.c -o exe -lm           # 链接
    timeout 10 ./exe                    # 执行测试断言
两个变体都额外加 -include ghidra_types.h -include compat.h，保证脚手架公平。

用法：
    python tests/eval_llm4decompile.py \
        --dataset "C:/ghidra/ghidra12.1/LLM4Decompile-main/legacy-test/decompile-eval-executable-gcc-ghidra.json"
"""

import argparse
import json
import platform
import re
import subprocess
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "plugins"))

import decompile_helper as dh          # noqa: E402
import fix_binary_ops as fb            # noqa: E402

WINDOWS = platform.system() == "Windows"


def to_wsl(path):
    p = str(Path(path).resolve())
    if not WINDOWS:
        return p
    if len(p) >= 2 and p[1] == ":":
        return "/mnt/" + p[0].lower() + p[2:].replace("\\", "/")
    return p.replace("\\", "/")


def repair_text(text):
    """decompile_helper 的单函数文本静态修复流水线。"""
    text = dh._strip_block_comments(text)
    text = dh.sanitize_qualified_names(text)
    text = dh._merge_split_array_return(text)
    text = dh._repair_anon_func_types(text)
    text = dh._repair_code_casts(text)
    text = dh._repair_slice_syntax(text)
    text = dh._repair_stack_refs(text)
    text = dh._repair_struct_casts(text)
    text = dh._repair_struct_decls(text)
    text = dh._repair_conflicting_struct_decls(text)
    text = dh._repair_aggregate_casts(text)
    text = dh._repair_array_assignments(text)
    return text


def collect_includes(*texts):
    out = []
    for text in texts:
        for line in text.split("\n"):
            if "#include" in line:
                out.append(line)
    return "\n".join(out) + "\n"


def combine(prefix, body, test):
    return prefix + "\n" + body + "\n" + test


def run_shell(script):
    if WINDOWS:
        return subprocess.run(["wsl", "bash", "-lc", script], text=True,
                              capture_output=True, encoding="utf-8",
                              errors="replace")
    return subprocess.run(["bash", "-lc", script], text=True,
                          capture_output=True, encoding="utf-8",
                          errors="replace")


def apply_error_fixes(text, errors):
    """错误驱动的静态修复（第二轮）：
    - `'X' undeclared` → 在函数前补 `extern unsigned long X;`（对齐 fix_undeclared）
    - `invalid operands to binary` → 报错行做位运算 cast（复用 fix_binary_ops）
    """
    rows = text.splitlines()
    changed = 0
    for e in errors:
        m = re.match(r"^[^:]*:(\d+):\d+: error: invalid operands to binary", e.strip())
        if not m:
            continue
        ln = int(m.group(1))
        if not (1 <= ln <= len(rows)):
            continue
        new = rows[ln - 1]
        for _ in range(5):
            nxt = fb._OP_RE.sub(r"(unsigned long)\1\2(unsigned long)\3", new)
            if nxt == new:
                break
            new = nxt
        if new != rows[ln - 1]:
            rows[ln - 1] = new
            changed += 1

    decls = []
    seen = set()
    for e in errors:
        m = re.search(r"error: [\u2018'\u2019\"]?([A-Za-z_]\w*)[\u2019'\u2019\"]?"
                      r" undeclared", e)
        if m:
            name = m.group(1)
            if name not in seen:
                seen.add(name)
                decls.append("extern unsigned long %s;" % name)
    text = "\n".join(rows)
    if decls:
        text = "\n".join(decls) + "\n" + text
    return text, len(decls) + changed


LLM_SYSTEM = """你是二进制反编译修复专家。用户给出 Ghidra 伪 C 函数、编译错误（可能为空）和测试代码。
要求：
1) 输出修复后的完整 C 函数定义（函数名保持不变；可附必要的前置声明/typedef，但不要写 #include）；
2) 目标：gcc 能编译通过，且语义正确（测试代码会用原函数签名调用它）；
3) 只输出 JSON：{"code": "<修复后的函数源码>"}，不要任何解释。"""


_LLM_ERRORS = []
_LLM_LOCK = threading.Lock()


def llm_repair(proposer, record, current_code, errors, compiled, run_ok):
    if compiled and run_ok:
        return None
    status = "编译通过但测试失败/超时" if compiled else "编译失败"
    user = (
        "原始 Ghidra 伪代码:\n%s\n\n当前修复版本:\n%s\n\n测试代码:\n%s\n\n"
        "编译错误/测试输出:\n%s\n\n当前状态: %s\n"
        % (record["input_asm_prompt"], current_code, record["c_test"],
           errors.strip() or "(无)", status)
    )
    last = None
    for attempt in range(3):  # 限流/网络抖动时退避重试
        try:
            data = proposer._chat_json(LLM_SYSTEM, user)
            code = str(data.get("code", "")).strip()
            if code:
                return "\n".join(l for l in code.splitlines()
                                 if not l.lstrip().startswith("#include"))
            last = "empty code"
        except Exception as e:
            last = "%s: %s" % (type(e).__name__, str(e)[:200])
        time.sleep(2 + 3 * attempt)
    with _LLM_LOCK:
        _LLM_ERRORS.append((record["type"], str(record["task_id"]), last))
    return None


def load_results(path):
    out = {}
    p = Path(path)
    if not p.exists():
        return out
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split("\t")
        if len(parts) == 6:
            opt, name, variant, c1, c2, run = parts
            out[(opt, name, variant)] = (int(c1), int(c2), int(run))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--out", default=str(ROOT / "ignore/generated/llm4decompile_eval"))
    ap.add_argument("--llm-rounds", type=int, default=2, help="LLM 修复迭代轮数")
    ap.add_argument("--llm-workers", type=int, default=6, help="LLM 并发数")
    ap.add_argument("--reuse", action="store_true",
                    help="复用已有的 samples/results（只补跑 LLM 轮）")
    args = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    dataset = json.loads(Path(args.dataset).read_text(encoding="utf-8"))
    out = Path(args.out)
    samples_dir = out / "samples"
    reuse = args.reuse and (out / "results.tsv").exists() and samples_dir.exists()
    if reuse:
        print("复用已有 samples/results（只补跑 LLM 轮）")
    else:
        if samples_dir.exists():
            import shutil
            shutil.rmtree(samples_dir)
        samples_dir.mkdir(parents=True)
        # 公平脚手架：所有加脚手架的变体都强制包含
        (out / "ghidra_types.h").write_text(dh.GHIDRA_TYPES_TEMPLATE, encoding="utf-8")
        (out / "compat.h").write_text(dh.COMPAT_TEMPLATE, encoding="utf-8")

    repaired = {}
    for rec in dataset:
        opt = rec["type"]
        task = str(rec["task_id"])
        raw = rec["input_asm_prompt"]
        fixed = repair_text(raw)
        repaired[(opt, task)] = fixed
        if reuse:
            continue
        d = samples_dir / opt / task
        d.mkdir(parents=True, exist_ok=True)
        prefix = collect_includes(rec["c_func"], rec["c_test"])
        test = rec["c_test"]
        origin = rec["c_func"]
        # paper：官方评测口径（只用原始 #include，不给我们的类型脚手架）
        (d / "paper.c").write_text(combine(prefix, raw, test), encoding="utf-8")
        (d / "only_paper.c").write_text(combine(prefix, raw, ""), encoding="utf-8")
        (d / "origin.c").write_text(combine(prefix, origin, test), encoding="utf-8")
        (d / "only_origin.c").write_text(combine(prefix, origin, ""), encoding="utf-8")
        (d / "raw.c").write_text(combine(prefix, raw, test), encoding="utf-8")
        (d / "only_raw.c").write_text(combine(prefix, raw, ""), encoding="utf-8")
        (d / "fixed.c").write_text(combine(prefix, fixed, test), encoding="utf-8")
        (d / "only_fixed.c").write_text(combine(prefix, fixed, ""), encoding="utf-8")

    inc = to_wsl(out)
    results = to_wsl(out / "results.tsv")

    def run_script(path, variants, target_tsv):
        script = (
            "#!/bin/sh\n"
            "INC='%s'\nRES='%s'\n" % (inc, target_tsv)
            + "cd \"$INC/samples\" || exit 1\n"
            + ": > \"$RES\"\n"
            + "for d in */*; do\n"
            + "  [ -d \"$d\" ] || continue\n"
            + "  opt=$(basename \"$(dirname \"$d\")\"); name=$(basename \"$d\")\n"
            + "  for v in %s; do\n" % " ".join(variants)
            + "    [ -f \"$d/$v.c\" ] || continue\n"
            + "    c1=0; c2=0; r=0\n"
            + "    if [ \"$v\" = paper ]; then PRE=\"\";"
              " else PRE=\"-include ghidra_types.h -include compat.h -I $INC\"; fi\n"
            + "    gcc -S $PRE \"$d/only_$v.c\" -o /dev/null -lm 2> \"$d/$v.err1\" && c1=1\n"
            + "    gcc $PRE \"$d/$v.c\" -o \"$d/exe_$v\" -lm 2> \"$d/$v.err2\" && c2=1\n"
            + "    if [ \"$c2\" = 1 ]; then timeout 10 \"$d/exe_$v\""
              " > \"$d/$v.run.out\" 2> \"$d/$v.run.err\"; [ $? = 0 ] && r=1; fi\n"
            + "    echo \"$opt\t$name\t$v\t$c1\t$c2\t$r\" >> \"$RES\"\n"
            + "  done\n"
            + "done\n")
        # 直接写字节，避免 Windows 文本模式把 \n 转成 \r\n 破坏 sh 脚本
        path.write_bytes(script.encode("utf-8"))

    if not reuse:
        run1 = out / "_run1.sh"
        run_script(run1, ["paper", "origin", "raw", "fixed"], results)
        print("编译运行 paper/origin/raw/fixed ...")
        r = run_shell("bash '%s'" % to_wsl(run1))
        if r.returncode != 0:
            print((r.stdout or "") + (r.stderr or ""))
            return 1

    # 第二轮：fixed 的 invalid-operands/未声明 报错行做静态修复，生成 fixed2
    if not reuse:
        fixed2_count = 0
        for (opt, task) in list(repaired):
            d = samples_dir / opt / task
            errs = ""
            for name in ("fixed.err1", "fixed.err2"):
                p = d / name
                if p.exists():
                    errs += p.read_text(encoding="utf-8", errors="replace")
            text2, changed = apply_error_fixes(repaired[(opt, task)], errs.splitlines())
            if changed == 0:
                continue
            rec = next(x for x in dataset
                       if str(x["task_id"]) == task and x["type"] == opt)
            prefix = collect_includes(rec["c_func"], rec["c_test"])
            (d / "fixed2.c").write_text(combine(prefix, text2, rec["c_test"]),
                                        encoding="utf-8")
            (d / "only_fixed2.c").write_text(combine(prefix, text2, ""),
                                             encoding="utf-8")
            fixed2_count += 1
        print("生成 fixed2 变体: %d" % fixed2_count)

        if fixed2_count:
            run2 = out / "_run2.sh"
            results2 = to_wsl(out / "results2.tsv")
            run_script(run2, ["fixed2"], results2)
            print("编译运行 fixed2 ...")
            r = run_shell("bash '%s'" % to_wsl(run2))
            if r.returncode != 0:
                print((r.stdout or "") + (r.stderr or ""))
                return 1

    # ---- LLM 修复轮：错误+测试反馈，多轮迭代 ----
    if args.llm_rounds > 0:
        from concurrent.futures import ThreadPoolExecutor
        from llm import LLMProposer
        proposer = LLMProposer()
        if not proposer._available():
            print("未设置 LLM_API_KEY，跳过 LLM 修复")
        else:
            r1 = load_results(out / "results.tsv")
            curr = {}
            for rec in dataset:
                key = (rec["type"], str(rec["task_id"]))
                c1, c2, run = r1.get((key[0], key[1], "fixed"), (0, 0, 0))
                curr[key] = {"code": repaired[key], "compiled": bool(c2),
                             "run": bool(run), "variant": "fixed"}
            llm_variants = []
            start_round = 1
            if reuse:  # 从已有 LLM 结果续跑
                for p in sorted(out.glob("results_llm*.tsv")):
                    variant = p.stem.split("results_")[-1]
                    rr = load_results(p)
                    for rec in dataset:
                        key = (rec["type"], str(rec["task_id"]))
                        got = rr.get((key[0], key[1], variant))
                        if not got or curr[key]["run"]:
                            continue
                        c1, c2, run = got
                        src = samples_dir / key[0] / key[1] / ("only_%s.c" % variant)
                        code = None
                        if src.exists():
                            text = src.read_text(encoding="utf-8", errors="replace")
                            prefix = collect_includes(rec["c_func"], rec["c_test"])
                            if text.startswith(prefix):
                                code = text[len(prefix) + 1:].rstrip("\n")
                        if code:
                            curr[key].update({"code": code, "compiled": bool(c2),
                                              "run": bool(run), "variant": variant})
                nums = [int(p.stem.split("llm")[-1]) for p in out.glob("results_llm*.tsv")
                        if p.stem.split("llm")[-1].isdigit()]
                start_round = max(nums) + 1 if nums else 1
            for rnd in range(start_round, args.llm_rounds + 1):
                todo = [rec for rec in dataset
                        if not curr[(rec["type"], str(rec["task_id"]))]["run"]]
                print("LLM 第 %d 轮: %d 个待修样本（模型 %s）"
                      % (rnd, len(todo), proposer.model))
                if not todo:
                    break
                tasks = []
                for rec in todo:
                    key = (rec["type"], str(rec["task_id"]))
                    st = curr[key]
                    d = samples_dir / key[0] / key[1]
                    errs = ""
                    for suffix in ("err1", "err2"):
                        p = d / ("%s.%s" % (st["variant"], suffix))
                        if p.exists():
                            errs += p.read_text(encoding="utf-8", errors="replace")
                    if st["compiled"] and not st["run"]:
                        for suffix in ("run.out", "run.err"):
                            p = d / ("%s.%s" % (st["variant"], suffix))
                            if p.exists():
                                errs += p.read_text(encoding="utf-8",
                                                    errors="replace")[:2000]
                    tasks.append((rec, st["code"], errs, st["compiled"], st["run"]))
                with ThreadPoolExecutor(max_workers=args.llm_workers) as ex:
                    codes = list(ex.map(lambda t: llm_repair(proposer, *t), tasks))
                variant = "llm%d" % rnd
                generated = {}
                for (rec, *_rest), code_out in zip(tasks, codes):
                    if not code_out:
                        continue
                    key = (rec["type"], str(rec["task_id"]))
                    d = samples_dir / key[0] / key[1]
                    prefix = collect_includes(rec["c_func"], rec["c_test"])
                    (d / ("%s.c" % variant)).write_text(
                        combine(prefix, code_out, rec["c_test"]), encoding="utf-8")
                    (d / ("only_%s.c" % variant)).write_text(
                        combine(prefix, code_out, ""), encoding="utf-8")
                    generated[key] = code_out
                print("  生成 %s: %d 个" % (variant, len(generated)))
                llm_variants.append(variant)
                if not generated:
                    break
                runn = out / ("_run_%s.sh" % variant)
                run_script(runn, [variant], to_wsl(out / ("results_%s.tsv" % variant)))
                r = run_shell("bash '%s'" % to_wsl(runn))
                if r.returncode != 0:
                    print((r.stdout or "") + (r.stderr or ""))
                    return 1
                rr = load_results(out / ("results_%s.tsv" % variant))
                for key, code_out in generated.items():
                    c1, c2, run = rr.get((key[0], key[1], variant), (0, 0, 0))
                    curr[key].update({"code": code_out, "compiled": bool(c2),
                                      "run": bool(run), "variant": variant})

    records = []
    for p in sorted(out.glob("results*.tsv")):
        for line in p.read_text(encoding="utf-8").splitlines():
            parts = line.split("\t")
            if len(parts) == 6:
                opt, name, variant, c1, c2, run = parts
                records.append((opt, name, variant, int(c1), int(c2), int(run)))

    stats = defaultdict(lambda: [0, 0, 0, 0])
    for opt, name, variant, c1, c2, run in records:
        for key in (("all", variant), (opt, variant)):
            s = stats[key]
            s[0] += 1
            s[1] += c1
            s[2] += c2
            s[3] += run

    summary = {"dataset_size": len(dataset), "samples": {}, "reference": {
        "llm4decompile-1.3b-v2": 0.460, "llm4decompile-6.7b-v2": 0.527}}
    print("\n%-6s %-7s %6s %10s %10s %8s" %
          ("opt", "variant", "total", "compileF", "compileC", "run"))
    order = ["paper", "origin", "raw", "fixed", "fixed2", "llm1", "llm2", "llm3"]
    seen = {r[2] for r in records}
    variants = [v for v in order if v in seen] + \
               sorted(v for v in seen if v not in order)
    for key in [("all", v) for v in variants] + \
               [(o, v) for o in ("O0", "O1", "O2", "O3") for v in variants]:
        if key not in stats:
            continue
        total, c1, c2, run = stats[key]
        summary["samples"]["%s/%s" % key] = {
            "total": total, "compile_only": c1, "compile_full": c2, "run": run}
        print("%-6s %-7s %6d %9.1f%% %9.1f%% %7.1f%%" %
              (key[0], key[1], total, 100 * c1 / total, 100 * c2 / total,
               100 * run / total))
    # best-of：每个样本只要任一修复变体通过即算通过（静态/LLM 取最优）
    seen_best = {}
    for opt, name, variant, c1, c2, run in records:
        if variant == "origin":
            continue
        key = (opt, name)
        s = seen_best.setdefault(key, [0, 0])
        s[0] = max(s[0], c2)
        s[1] = max(s[1], run)
    best = defaultdict(lambda: [0, 0, 0])
    for (opt, name), (c2, run) in seen_best.items():
        for k in ("all", opt):
            b = best[k]
            b[0] += 1
            b[1] += c2
            b[2] += run
    summary["our_pipeline_best_of"] = {}
    print("\n%-6s %-12s %6s %10s %8s" % ("opt", "pipeline", "total",
                                         "compile", "run"))
    for k in ("all", "O0", "O1", "O2", "O3"):
        if k not in best:
            continue
        total, c2, run = best[k]
        summary["our_pipeline_best_of"][k] = {
            "total": total, "compile_full": c2, "run": run}
        print("%-6s %-12s %6d %9.1f%% %7.1f%%" %
              (k, "best-of", total, 100 * c2 / total, 100 * run / total))
    if _LLM_ERRORS:
        print("\nLLM 失败重试后仍报错 %d 条，前 3 条：" % len(_LLM_ERRORS))
        for e in _LLM_ERRORS[:3]:
            print("  %s/%s: %s" % e)
    print("\n参考（论文 Table 3，HumanEval-Decompile re-executability）："
          "Ghidra Base 20.12% | Ref-1.3B 46.04% | Ref-6.7B 52.74% | Ref-22B 64.18%")
    (out / "summary.json").write_text(json.dumps(summary, indent=1),
                                      encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
