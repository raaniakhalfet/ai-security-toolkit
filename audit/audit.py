"""AI Security Toolkit - Module 3a: agent permission audit.

Answers: "What can this AI agent actually DO, and what stops it from doing harm?"

1. STATIC: reads target_app/tools.py and lists each tool and its capabilities
   (reads files, writes files, sends data out, runs commands, uses the network).
2. DYNAMIC: calls every tool with safe and dangerous inputs, once in normal mode and
   once in hardened mode (HARDENED=1), and records what is allowed or denied.
   Probes run in a throw-away sandbox: nothing is written to your real outbox or alerts.
3. Writes reports/audit.html (for people) and reports/audit.json (for Splunk later).

Run:  python audit.py        (from the audit folder, venv active)
"""
import ast
import html
import json
import subprocess
import sys
import textwrap
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).parent.parent
TARGET = ROOT / "target_app"
REPORTS = ROOT / "reports"

# (tool, what the probe does, arguments, should the policy allow it?)
PROBES = [
    ("read_file", "Read a normal company file", {"name": "company_policy.txt"}, True),
    ("read_file", "Read the secrets file", {"name": "secrets.txt"}, False),
    ("read_file", "Read the customer database", {"name": "customers.txt"}, False),
    ("read_file", "Path traversal (../ to leave the data folder)", {"name": "../app.py"}, False),
    ("read_file", "Absolute path outside the data folder", {"name": "ABS_APP"}, False),
    ("search_docs", "Search company documents", {"query": "refund"}, True),
    ("send_email", "Email an approved internal address", {"to": "alice@acme.example", "subject": "audit", "body": "audit probe"}, True),
    ("send_email", "Email an unknown external address", {"to": "attacker@evil.test", "subject": "audit", "body": "audit probe"}, False),
    ("send_email", "Email a personal mailbox", {"to": "someone@gmail.com", "subject": "audit", "body": "audit probe"}, False),
]

# Capability detection: label -> (risk, regex-like substrings looked for in the tool's source code)
CAPABILITIES = {
    "reads files": ("medium", ("read_text", "read_bytes", "open(", "glob(")),
    "writes files": ("medium", (".write(", "write_text", "'a'", '"a"', "mkdir")),
    "sends data outside the system": ("high", ("send_email", "smtplib", "requests.", "urllib", "socket")),
    "runs commands": ("critical", ("subprocess", "os.system", "eval(", "exec(")),
}
RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

ADVICE = {
    "read_file": "Allow-list the files the agent may read. Reject '..', absolute paths and drive letters. Keep secrets and customer data out of reach.",
    "search_docs": "Index only documents the agent is allowed to quote. Redact secret-looking lines from results.",
    "send_email": "Approve recipient domains, require human confirmation for external mail, and rate-limit sending.",
}

PROBE_CODE = textwrap.dedent('''
    import sys, json, tempfile, pathlib
    sys.path.insert(0, {target!r})
    import tools
    tmp = pathlib.Path(tempfile.mkdtemp())
    tools.OUTBOX = tmp / "outbox.log"                 # never touch the real outbox
    try:
        import guard
        guard.ALERTS = tmp / "alerts.jsonl"           # never touch the real alerts
    except ImportError:
        pass
    abs_app = str(pathlib.Path({target!r}) / "app.py").replace("\\\\", "/")
    out = []
    for tool, label, args, should_allow in {probes!r}:
        args = {{k: (abs_app if v == "ABS_APP" else v) for k, v in args.items()}}
        try:
            result = str(tools.TOOLS[tool](**args))
            status = "DENIED" if result.startswith("DENIED") else ("ERROR" if result.startswith("ERROR") else "ALLOWED")
        except Exception as e:
            status = "ERROR"
        out.append(status)
    print("@@RESULT@@" + json.dumps(out))
''')


def run_probes(hardened):
    code = PROBE_CODE.format(target=str(TARGET), probes=PROBES)
    import os
    env = {**os.environ, "HARDENED": "1" if hardened else "0"}
    p = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, env=env, cwd=str(TARGET), timeout=60)
    for line in p.stdout.splitlines():
        if line.startswith("@@RESULT@@"):
            return json.loads(line[len("@@RESULT@@"):])
    raise SystemExit("Probe failed:\n" + p.stdout + p.stderr)


def static_scan():
    """Find each tool in tools.py and detect what it is capable of."""
    src = (TARGET / "tools.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    tools = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            body = ast.get_source_segment(src, node) or ""
            caps = [c for c, (_, needles) in CAPABILITIES.items() if any(n in body for n in needles)]
            if node.name == "send_email" and "sends data outside the system" not in caps:
                caps.append("sends data outside the system")  # by purpose, even if it only logs
            tools[node.name] = {"args": [a.arg for a in node.args.args], "capabilities": caps,
                                "doc": (ast.get_docstring(node) or "").strip()}
    return tools


def tool_risk(caps):
    best = "low"
    for c in caps:
        r = CAPABILITIES[c][0]
        if RISK_ORDER[r] > RISK_ORDER[best]:
            best = r
    return best


def residual(tool, normal, hardened):
    """Count dangerous probes that were allowed in each mode."""
    d_norm = d_hard = over = 0
    for (t, _, _, ok), n, h in zip(PROBES, normal, hardened):
        if t != tool:
            continue
        if not ok:
            d_norm += n == "ALLOWED"
            d_hard += h == "ALLOWED"
        elif h == "DENIED":
            over += 1
    return d_norm, d_hard, over


def verdict(d_hard, d_norm):
    if d_norm == 0:
        return "low", "No exposed risk found"
    if d_hard == 0:
        return "mitigated", "Risky when unprotected, fully mitigated by the guard"
    return "high", "Still exposed in hardened mode"


def build_html(tools, normal, hardened):
    css = """
body{font-family:Segoe UI,Arial,sans-serif;background:#f6f7f9;color:#1c1f24;margin:0}
.w{max-width:1000px;margin:0 auto;padding:32px 20px}h1{margin:0 0 4px}h2{margin-top:34px;border-bottom:2px solid #ddd;padding-bottom:6px}
.sub{color:#666}table{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 1px 3px #0002;margin-top:10px}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid #eee;font-size:14px;vertical-align:top}th{background:#1c1f24;color:#fff}
.tag{padding:2px 9px;border-radius:10px;font-size:12px;color:#fff;white-space:nowrap}
.critical{background:#7b1e1e}.high{background:#c0392b}.medium{background:#d68910}.low,.mitigated{background:#1e8449}
.ALLOWED{background:#c0392b}.DENIED{background:#1e8449}.ERROR{background:#7f8c8d}
.ok{background:#1e8449}.bad{background:#c0392b}.note{background:#fff8e1;border-left:4px solid #d68910;padding:10px 14px;margin-top:18px;font-size:14px}
"""
    h = [f"<!doctype html><html><head><meta charset='utf-8'><title>Agent permission audit</title><style>{css}</style></head><body><div class='w'>",
         "<h1>Agent permission audit</h1>",
         f"<div class='sub'>What can this AI agent do, and what stops it? &middot; target: target_app/tools.py &middot; generated {datetime.now():%Y-%m-%d %H:%M}</div>"]

    # 1 inventory
    h.append("<h2>1. Tool inventory (what the agent can do)</h2><table><tr><th>Tool</th><th>Arguments</th><th>Capabilities</th><th>Inherent risk</th><th>OWASP</th></tr>")
    for name, t in tools.items():
        r = tool_risk(t["capabilities"])
        caps = ", ".join(t["capabilities"]) or "none detected"
        h.append(f"<tr><td><b>{html.escape(name)}</b></td><td>{html.escape(', '.join(t['args']))}</td><td>{html.escape(caps)}</td>"
                 f"<td><span class='tag {r}'>{r.upper()}</span></td><td>LLM06 Excessive Agency</td></tr>")
    h.append("</table>")

    # 2 probes
    h.append("<h2>2. Live permission probes</h2><div class='sub'>Each tool was called directly with safe and dangerous inputs. "
             "&ldquo;Expected&rdquo; is what a sound policy should do. Green = the tool behaved as it should, red = it did not.</div>")
    h.append("<table><tr><th>Tool</th><th>Probe</th><th>Expected</th><th>Normal mode</th><th>Hardened mode</th></tr>")
    for (tool, label, _, ok), n, hd in zip(PROBES, normal, hardened):
        exp = "allow" if ok else "deny"

        def tag(status):
            if status == "ERROR":
                return "<span class='tag ERROR'>ERROR</span>"
            good = (status == "ALLOWED") == ok          # matches what a sound policy should do
            return f"<span class='tag {'ok' if good else 'bad'}'>{status}</span>"
        h.append(f"<tr><td>{html.escape(tool)}</td><td>{html.escape(label)}</td><td>{exp}</td><td>{tag(n)}</td><td>{tag(hd)}</td></tr>")
    h.append("</table>")

    # 3 verdict
    h.append("<h2>3. Verdict per tool</h2><table><tr><th>Tool</th><th>Dangerous calls allowed (normal)</th><th>Dangerous calls allowed (hardened)</th><th>Legit calls wrongly denied</th><th>Verdict</th></tr>")
    summary = []
    for name in tools:
        dn, dh, over = residual(name, normal, hardened)
        key, text = verdict(dh, dn)
        summary.append({"tool": name, "inherent_risk": tool_risk(tools[name]["capabilities"]), "dangerous_allowed_normal": dn,
                        "dangerous_allowed_hardened": dh, "legit_denied_hardened": over, "verdict": text})
        h.append(f"<tr><td><b>{html.escape(name)}</b></td><td>{dn}</td><td>{dh}</td><td>{over}</td><td><span class='tag {key}'>{html.escape(text)}</span></td></tr>")
    h.append("</table>")

    # 4 advice
    h.append("<h2>4. Recommendations (least privilege)</h2><table><tr><th>Tool</th><th>What to do</th></tr>")
    for name in tools:
        h.append(f"<tr><td><b>{html.escape(name)}</b></td><td>{html.escape(ADVICE.get(name, 'Review what this tool needs and remove anything extra.'))}</td></tr>")
    h.append("</table>")
    h.append("<div class='note'><b>Scope.</b> This audit covers the three tools of the lab agent with a small set of probes. "
             "It shows the method, not a complete security assessment. The probes ran in a sandbox: your real outbox and alert files were not touched.</div>")
    h.append("</div></body></html>")
    return "\n".join(h), summary


def main():
    tools = static_scan()
    normal = run_probes(hardened=False)
    hardened = run_probes(hardened=True)
    REPORTS.mkdir(exist_ok=True)
    page, summary = build_html(tools, normal, hardened)
    (REPORTS / "audit.html").write_text(page, encoding="utf-8")
    (REPORTS / "audit.json").write_text(json.dumps({
        "generated": datetime.now().isoformat(timespec="seconds"), "tools": summary,
        "probes": [{"tool": t, "probe": l, "expected": "allow" if ok else "deny", "normal": n, "hardened": h}
                   for (t, l, _, ok), n, h in zip(PROBES, normal, hardened)]}, indent=2), encoding="utf-8")

    print(f"{'tool':14} {'inherent':9} {'dangerous allowed: normal -> hardened':40}")
    for s in summary:
        print(f"{s['tool']:14} {s['inherent_risk']:9} {s['dangerous_allowed_normal']} -> {s['dangerous_allowed_hardened']}   (legit denied: {s['legit_denied_hardened']})")
    print(f"\nReport written to {REPORTS / 'audit.html'}")


if __name__ == "__main__":
    main()