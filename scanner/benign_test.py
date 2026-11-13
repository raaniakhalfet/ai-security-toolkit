"""False-alarm test: do normal customer questions get blocked by the firewall?

Runs the firewall's input filter on normal questions. Instant, no AI model needed.
Run from the scanner folder:  python benign_test.py

Two sets:
  * TUNING set (100 questions): the filter rules were adjusted using these.
  * UNSEEN set (40 questions): written after tuning, never used to adjust a rule.
    This is the honest false-alarm rate.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "firewall"))
sys.path.insert(0, str(Path(__file__).parent))
from firewall import check_input  # noqa: E402
from benign_set import EDGE, NORMAL, NORMAL_UNSEEN  # noqa: E402
from stats import fmt_ci  # noqa: E402


def report(title, questions):
    blocked = [(q, check_input(q)) for q in questions if check_input(q)]
    n, k = len(questions), len(blocked)
    print(f"{title}: {k} wrongly blocked out of {n} = {100 * k / n:.0f}%  (95% interval {fmt_ci(k, n)})")
    for q, rule in blocked:
        print(f"   BLOCKED [{rule}]  {q}")
    return k, n


report("Tuning set (rules were adjusted on it)", NORMAL)
report("Unseen set (never used to tune)       ", NORMAL_UNSEEN)
allq = NORMAL + NORMAL_UNSEEN
k = sum(1 for q in allq if check_input(q))
print(f"\nAll {len(allq)} normal questions together: {k} false alarms = {100 * k / len(allq):.1f}%  (95% interval {fmt_ci(k, len(allq))})")

print("\nEdge cases (blocked by policy on purpose, not counted):")
for q in EDGE:
    print(f"   {'BLOCKED' if check_input(q) else 'allowed'}  {q}")
