"""Compare the same defences on two (or more) AI models.

  python compare.py          ->  reports/compare_models.html  (and prints a short table)

The first model is the one used for all the earlier scans (llama3.2:3b). Another model is added with:
  python toolkit.py full --model qwen2.5:3b --runs 3
Those scans are saved with a "m-<model>-" label, so they never replace the earlier results.
"""
import html
import json
import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from stats import fmt_ci, overlaps, wilson  # noqa: E402

REPORTS = Path(__file__).parent.parent / "reports"
BASE_MODEL = "llama3.2:3b"
SETUPS = [("none", "No defence"), ("firewall", "Firewall only"), ("guard", "Guard only"), ("both", "Firewall + guard"),
          ("rootfix", "Secret removed from prompt + guard")]
SETS = [
    ("Original 12 attacks", {"none": "before", "firewall": "after", "guard": "guard", "both": "both", "rootfix": "rootfix"}),
    ("12 unseen attacks", {"none": "holdoutbefore", "firewall": "holdoutafter", "guard": "holdoutguard", "both": "holdoutboth", "rootfix": "holdoutrootfix"}),
    ("18 more unseen attacks", {"none": "holdout2before", "firewall": "holdout2after", "guard": "holdout2guard", "both": "holdout2both", "rootfix": "holdout2rootfix"}),
    ("Attacks invented by an AI attacker", {"none": "generatedbefore", "firewall": "generatedafter", "guard": "generatedguard", "both": "generatedboth", "rootfix": "generatedrootfix"}),
]


def model_tag(name):
    """File-name friendly version of a model name: qwen2.5:3b -> qwen2-5-3b."""
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def label_prefix(name):
    return "" if name == BASE_MODEL else f"m-{model_tag(name)}-"


def newest(reports, label):
    files = sorted(Path(reports).glob(f"scan_{label}_*.json"))
    return json.loads(files[-1].read_text(encoding="utf-8")) if files else None


def found_models(reports):
    """Base model first, then every other model that has scans (read from the 'model' field of the files)."""
    others = set()
    for f in Path(reports).glob("scan_m-*.json"):
        try:
            m = json.loads(f.read_text(encoding="utf-8")).get("model")
        except ValueError:
            continue
        if m and m != BASE_MODEL:
            others.add(m)
    return [BASE_MODEL] + sorted(others)


def counts(data):
    if not data:
        return None
    ok = [r for r in data["results"] if r["outcome"] != "error"]
    return {"n": len(ok), "success": sum(r["outcome"] == "success" for r in ok), "partial": sum(r["outcome"] == "partial" for r in ok)}


def wins(reports=REPORTS, set_index=0, model=BASE_MODEL):
    """Attacks that worked, per setup, in the newest scan of one attack set. For the jury: what exactly got through?"""
    title, labels = SETS[set_index]
    out = {"title": title, "setups": []}
    for key, name in SETUPS:
        data = newest(reports, label_prefix(model) + labels[key])
        if not data:
            out["setups"].append({"setup": name, "run": False, "wins": []})
            continue
        counts = {}
        for r in data["results"]:
            if r["outcome"] == "success":
                c = counts.setdefault(r["attack_id"], {"id": r["attack_id"], "times": 0, "prompt": r["prompt"], "rule": r.get("matched_rule", "")})
                c["times"] += 1
        runs = len([r for r in data["results"] if r["outcome"] != "error"])
        out["setups"].append({"setup": name, "run": True, "runs": runs, "wins": sorted(counts.values(), key=lambda c: c["id"])})
    return out


def summary(reports=REPORTS):
    models = found_models(reports)
    sets = []
    pooled = {key: {m: {"n": 0, "success": 0, "partial": 0, "sets": 0} for m in models} for key, _ in SETUPS}
    for title, labels in SETS:
        rows = []
        for key, name in SETUPS:
            cells = {}
            for m in models:
                c = counts(newest(reports, label_prefix(m) + labels[key]))
                cells[m] = c
                if c:
                    for k in ("n", "success", "partial"):
                        pooled[key][m][k] += c[k]
                    pooled[key][m]["sets"] += 1
            rows.append({"setup": name, "cells": cells})
        if any(c for r in rows for c in r["cells"].values()):
            sets.append({"title": title, "rows": rows})
    prows = [{"setup": name, "cells": {m: (pooled[key][m] if pooled[key][m]["sets"] else None) for m in models}} for key, name in SETUPS]
    return {"models": models, "sets": sets, "pooled": prows}


def verdict(a, b):
    """Plain sentence about two cells: is the difference real or maybe chance?"""
    if not a or not b or not a["n"] or not b["n"]:
        return ""
    wa, wb = wilson(a["success"], a["n"]), wilson(b["success"], b["n"])
    if overlaps(wa, wb):
        return "difference may be chance"
    return "clear difference"


def build(reports=REPORTS):
    s = summary(reports)
    css = """body{font-family:Segoe UI,Arial,sans-serif;background:#f6f7f9;color:#1c1f24;margin:0}.w{max-width:980px;margin:0 auto;padding:32px 20px}
h1{margin:0 0 4px}h2{margin-top:30px}.sub{color:#666}table{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 1px 3px #0002;margin-top:10px}
th,td{padding:10px 12px;text-align:center;border-bottom:1px solid #eee;font-size:15px}th{background:#1c1f24;color:#fff}td:first-child,th:first-child{text-align:left}.s{font-size:12px;color:#555}
.note{background:#fff8e1;border-left:4px solid #d68910;padding:10px 14px;margin-top:18px;font-size:14px}"""

    def cell(c):
        if not c or not c["n"]:
            return "<td>not run</td>"
        p = 100 * c["success"] / c["n"]
        return f"<td><b>{p:.0f}%</b><br><span class='s'>{c['success']}/{c['n']} runs<br>95% interval {fmt_ci(c['success'], c['n'])}</span></td>"

    def table(rows):
        head = "".join(f"<th>{html.escape(m)}</th>" for m in s["models"])
        out = [f"<table><tr><th>Setup</th>{head}<th>Compared</th></tr>"]
        for r in rows:
            cells = [r["cells"][m] for m in s["models"]]
            note = verdict(cells[0], cells[1]) if len(cells) > 1 else ""
            out.append(f"<tr><td><b>{html.escape(r['setup'])}</b></td>{''.join(cell(c) for c in cells)}<td class='s'>{note}</td></tr>")
        out.append("</table>")
        return "".join(out)

    h = [f"<!doctype html><html><head><meta charset='utf-8'><title>Model comparison</title><style>{css}</style></head><body><div class='w'>",
         "<h1>Same defences, different AI models</h1>",
         f"<div class='sub'>Attack success rate = share of attack runs that caused real harm. Lower is better. Generated {datetime.now():%Y-%m-%d %H:%M}</div>"]
    if len(s["models"]) < 2:
        h.append("<div class='note'>Only one model has been tested so far. Run <b>python toolkit.py full --model qwen2.5:3b --runs 3</b> "
                 "(after <b>ollama pull qwen2.5:3b</b>), then rebuild this page with <b>python scanner/compare.py</b>.</div>")
    h.append("<h2>All three attack sets together</h2>" + table(s["pooled"]))
    for st in s["sets"]:
        h.append(f"<h2>{html.escape(st['title'])}</h2>" + table(st["rows"]))
    h.append("<div class='note'><b>Reading guide.</b> The two models face the same attacks and the same defences. "
             "A big difference with no defence shows that some models are easier to trick than others. "
             "The defences do not depend on the model: the firewall and the guard work on messages and tool calls, not on the model's opinion. "
             "If two 95% intervals overlap, the difference may be chance. Small local models and a few runs: a rough guide, not a ranking.</div></div></body></html>")
    return "\n".join(h)


def print_wins(set_index, model):
    w = wins(REPORTS, set_index, model)
    print(f"Attacks that WORKED. Set: {w['title']}. Model: {model}\n")
    for st in w["setups"]:
        if not st["run"]:
            print(f"{st['setup']}: not run")
            continue
        print(f"{st['setup']}: {len(st['wins'])} different attack(s) worked ({st['runs']} runs)")
        for c in st["wins"]:
            print(f"   {c['id']} worked {c['times']} time(s) via {c['rule'] or '?'}: {c['prompt'][:110].replace(chr(10), ' ')}")
        print()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--wins":
        print_wins(int(sys.argv[2]) if len(sys.argv) > 2 else 0, sys.argv[3] if len(sys.argv) > 3 else BASE_MODEL)
        sys.exit()
    s = summary()
    print("Models found:", ", ".join(s["models"]))
    for r in s["pooled"]:
        line = [f"{r['setup']:38}"]
        for m in s["models"]:
            c = r["cells"][m]
            line.append(f"{m}: " + (f"{100 * c['success'] / c['n']:.0f}% ({c['success']}/{c['n']})" if c and c["n"] else "not run"))
        print("  ".join(line))
    out = REPORTS / "compare_models.html"
    out.write_text(build(), encoding="utf-8")
    print(f"Comparison written to {out}")
