"""Defence-in-depth matrix: 4 setups side by side, for both attack sets.

  python matrix.py      ->  reports/matrix.html

Uses the newest scan for each label. Missing scans show as "not run".
"""
import html
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from stats import fmt_ci  # noqa: E402

REPORTS = Path(__file__).parent.parent / "reports"

SETUPS = [("none", "No defence"), ("firewall", "Firewall only"), ("guard", "Guard only"), ("both", "Firewall + guard"),
          ("rootfix", "Secret removed from prompt + guard")]
SETS = [
    ("Original 12 attacks (the firewall was built knowing these)", {"none": "before", "firewall": "after", "guard": "guard", "both": "both", "rootfix": "rootfix"}),
    ("12 unseen attacks (hold-out set 1)", {"none": "holdoutbefore", "firewall": "holdoutafter", "guard": "holdoutguard", "both": "holdoutboth", "rootfix": "holdoutrootfix"}),
    ("18 more unseen attacks (hold-out set 2: base64, Arabic, fiction, look-alike domains, new poisoned files)", {"none": "holdout2before", "firewall": "holdout2after", "guard": "holdout2guard", "both": "holdout2both", "rootfix": "holdout2rootfix"}),
]


def newest(label):
    files = sorted(REPORTS.glob(f"scan_{label}_*.json"))
    return json.loads(files[-1].read_text(encoding="utf-8")) if files else None


def stats(results):
    ok = [r for r in results if r["outcome"] != "error"]
    n = len(ok)
    s = sum(r["outcome"] == "success" for r in ok)
    p = sum(r["outcome"] == "partial" for r in ok)
    return n, s, p


def color(pct):
    # white (0%) -> red (100%)
    a = min(pct, 100) / 100
    return f"rgba(192,57,43,{0.08 + 0.7 * a:.2f})" if pct > 0 else "rgba(30,132,73,0.15)"


def cell(s, p, n):
    if n == 0:
        return "<td>-</td>"
    pct = 100 * s / n
    return (f"<td style='background:{color(pct)}'><b>{pct:.0f}%</b><br><span class='s'>{s}/{n}"
            + (f" (+{p} partial)" if p else "") + f"<br>95% interval {fmt_ci(s, n)}</span></td>")


def build():
    css = """
body{font-family:Segoe UI,Arial,sans-serif;background:#f6f7f9;color:#1c1f24;margin:0}
.w{max-width:980px;margin:0 auto;padding:32px 20px}h1{margin:0 0 4px}h2{margin-top:34px}
.sub{color:#666}table{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 1px 3px #0002;margin-top:10px}
th,td{padding:10px 12px;text-align:center;border-bottom:1px solid #eee;font-size:15px}th{background:#1c1f24;color:#fff}
td:first-child,th:first-child{text-align:left}.s{font-size:12px;color:#555}
.note{background:#fff8e1;border-left:4px solid #d68910;padding:10px 14px;margin-top:18px;font-size:14px}
"""
    h = [f"<!doctype html><html><head><meta charset='utf-8'><title>Defence matrix</title><style>{css}</style></head><body><div class='w'>",
         "<h1>Defence-in-depth matrix</h1>",
         f"<div class='sub'>Attack success rate = share of attack runs that caused real harm. Lower is better. Generated {datetime.now():%Y-%m-%d %H:%M}</div>"]
    for title, labels in SETS:
        data = {k: newest(v) for k, v in labels.items()}
        h.append(f"<h2>{html.escape(title)}</h2>")
        h.append("<table><tr><th>Setup</th><th>Attack success</th><th>Success or partial</th></tr>")
        for key, name in SETUPS:
            d = data[key]
            if not d:
                h.append(f"<tr><td>{name}</td><td colspan=2>not run</td></tr>")
                continue
            n, s, p = stats(d["results"])
            h.append(f"<tr><td><b>{name}</b></td>{cell(s, 0, n)}{cell(s + p, 0, n)}</tr>")
        h.append("</table>")
        cats = sorted({r["category"] for d in data.values() if d for r in d["results"]})
        h.append("<table><tr><th>Category (success rate)</th>" + "".join(f"<th>{n}</th>" for _, n in SETUPS) + "</tr>")
        for c in cats:
            h.append(f"<tr><td>{html.escape(c)}</td>")
            for key, _ in SETUPS:
                d = data[key]
                rs = [r for r in d["results"] if r["category"] == c] if d else []
                n, s, p = stats(rs)
                h.append(cell(s, p, n))
            h.append("</tr>")
        h.append("</table>")
    h.append("<div class='note'><b>Reading guide.</b> The firewall filters messages and replies; the guard limits what the agent's tools may do. "
             "Each one alone leaves a gap, and together they cover each other. <b>95% interval</b> = the range the true rate probably lies in "
             "(Wilson score). With few runs it is wide: 0 out of 36 only shows the true rate is probably below about 10%, not that it is zero. "
             "If two intervals overlap, the difference may be chance. Results come from a small local model, so use them as a rough guide.</div></div></body></html>")
    return "\n".join(h)


if __name__ == "__main__":
    out = REPORTS / "matrix.html"
    out.write_text(build(), encoding="utf-8")
    print(f"Matrix written to {out}")