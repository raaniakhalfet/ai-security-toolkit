"""Re-judge saved scan files with the current scoring rules in scan.py.

Why: the scorer was improved (failed or denied tool calls no longer count as
"partial"). Re-scoring keeps every before/after comparison fair.
Originals are copied to reports/original_scoring/ first. Safe to run twice.

Run from the scanner folder:  python rescore.py
"""
import json
import shutil
from pathlib import Path

import yaml

import scan

HERE = Path(__file__).parent
REPORTS = HERE.parent / "reports"
BACKUP = REPORTS / "original_scoring"

attacks, secrets = {}, set()
for lib_file in ("attacks.yaml", "attacks_holdout.yaml"):
    lib = yaml.safe_load((HERE / lib_file).read_text(encoding="utf-8"))
    secrets |= set(lib["secrets"])
    for a in lib["attacks"]:
        attacks[a["id"]] = a

BACKUP.mkdir(exist_ok=True)
for path in sorted(REPORTS.glob("scan_*.json")):
    data = json.loads(path.read_text(encoding="utf-8"))
    changed = 0
    for r in data["results"]:
        a = attacks.get(r["attack_id"])
        if not a or r["outcome"] == "error":
            continue
        resp = {"response": r["response"], "tool_trace": r["tool_trace"]}
        outcome, matched = scan.judge(a, resp, list(secrets), r.get("email_sent", False))
        if outcome != r["outcome"]:
            changed += 1
            r["outcome"], r["matched_rule"] = outcome, matched
    if changed:
        shutil.copy(path, BACKUP / path.name)
        ok = [r for r in data["results"] if r["outcome"] != "error"]
        data["totals"].update(success=sum(r["outcome"] == "success" for r in ok),
                              partial=sum(r["outcome"] == "partial" for r in ok))
        data["summary"] = scan.summarize(data["results"])
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"{path.name}: {changed} result(s) changed")