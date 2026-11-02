"""Standalone, escaped HTML and machine-readable result files."""
import html
import json

from .workspace import write_json


def write_report(root, result):
    write_json(root / "results.json", result)
    payload = html.escape(json.dumps(result, ensure_ascii=False, indent=2))
    def escape(value):
        return html.escape(str(value))

    rows = []
    for label, key in (("修复前", "baseline_results"), ("修复后", "repair_results"), ("独立评估", "evaluation_results")):
        cases = result.get(key) or {}
        for cid, row in cases.items():
            issues = [p + ": " + ", ".join(row[p]["issues"]) for p in ("normal", "instrumented") if row[p]["issues"]]
            if any(not row[p]["matches_reference"] for p in ("normal", "instrumented")):
                issues.append("与参考行为不一致")
            rows.append("<tr>" + "".join("<td>" + escape(v) + "</td>" for v in
                                        (label, cid, "通过" if row["passed"] else "未通过", "; ".join(issues))) + "</tr>")
    attempts = []
    for row in result["attempts"]:
        attempts.append('<li><a href="attempts/%04d/decision.json">候选 %d</a>：%s — %s</li>' %
                        (row["attempt"], row["attempt"], "接受" if row["accepted"] else "拒绝", escape(row["reason"])))
    content = """<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>动态修复报告</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 24px;color:#172433}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f8;padding:20px}a{color:#165abc}
table{border-collapse:collapse;width:100%;margin:24px 0}th,td{text-align:left;border-bottom:1px solid #ddd;padding:12px}
strong{background:#e8eef9;padding:5px 12px;border-radius:6px}td:last-child{overflow-wrap:anywhere}li{margin:12px 0}</style>
<h1>动态修复报告</h1><p>状态：<strong>STATUS</strong></p>
<p>REASON</p>
<p>测试通过仅说明已执行的用例通过，不构成程序语义等价证明。</p>
<p><a href="results.json">完整 JSON</a> · <a href="manifest.json">运行清单</a> · <a href="best/">最佳工程</a></p>
<table><thead><tr><th>阶段</th><th>用例</th><th>结果</th><th>问题</th></tr></thead><tbody>ROWS</tbody></table>
<h2>补丁决策</h2><ol>ATTEMPTS</ol>
<details><summary>完整结果（stdout/stderr 使用 base64 保存原始字节）</summary><pre>PAYLOAD</pre></details></html>"""
    # Replace template markers before inserting user-controlled content.
    import string
    for marker in ("STATUS", "REASON", "ROWS", "ATTEMPTS", "PAYLOAD"):
        content = content.replace(marker, "${" + marker + "}")
    content = string.Template(content).substitute(STATUS=escape(result["status"]), REASON=escape(result["reason"]),
                                                  ROWS="".join(rows), ATTEMPTS="".join(attempts), PAYLOAD=payload)
    (root / "report.html").write_text(content, encoding="utf-8")
