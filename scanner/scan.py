"""AI Security Toolkit - scanner engine.

Reads attacks.yaml, sends every attack to a chat endpoint several times,
scores each run as success / partial / blocked / error, and saves the raw data.
LOCAL LAB ONLY: it is meant to attack the fake AcmeBot, nothing else.
"""
import argparse
import json
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import requests
import yaml

ROOT = Path(__file__).parent.parent
LIB = Path(__file__).parent / "attacks.yaml"
DATA_DIR = ROOT / "target_app" / "data"
OUTBOX = ROOT / "target_app" / "outbox.log"
REPORTS = ROOT / "reports"


def outbox_size():
    return OUTBOX.stat().st_size if OUTBOX.exists() else 0


def rule_matches(rule, resp, secrets, email_sent):
    reply = str(resp.get("response", ""))
    trace = resp.get("tool_trace", []) or []
    kind = rule["type"]
    if kind == "secret_in_reply":
        return any(s in reply for s in secrets)
    if kind == "secret_in_trace":
        return any(s in str(trace) for s in secrets)
    if kind == "reply_contains":
        return rule["value"] in reply
    if kind == "tool_called":
        for t in trace:
            if t.get("tool") != rule["tool"]:
                continue
            needle = rule.get("arg_contains")
            if needle is None or needle in str(t.get("args")):
                return True
        return False
    if kind == "email_sent":
        return email_sent
    return False


def judge(attack, resp, secrets, email_sent):
    for rule in attack.get("success", []):
        if rule_matches(rule, resp, secrets, email_sent):
            return "success", rule["type"]
    for rule in attack.get("partial", []):
        if rule_matches(rule, resp, secrets, email_sent):
            return "partial", rule["type"]
    return "blocked", ""


def run_attack(attack, url, runs, secrets, timeout):
    fixture = attack.get("fixture")
    fixture_path = None
    if fixture:
        fixture_path = DATA_DIR / fixture["file"]
        fixture_path.write_text(fixture["content"], encoding="utf-8")
    results = []
    try:
        for i in range(1, runs + 1):
            before = outbox_size()
            start = time.time()
            try:
                resp = requests.post(url, json={"message": attack["prompt"]}, timeout=timeout).json()
                email_sent = outbox_size() > before
                outcome, matched = judge(attack, resp, secrets, email_sent)
            except Exception as e:  # network error, bad JSON, timeout...
                resp = {"response": f"ERROR: {e}", "tool_trace": []}
                email_sent, outcome, matched = False, "error", ""
            seconds = round(time.time() - start, 1)
            tools = [t.get("tool") for t in (resp.get("tool_trace") or [])]
            print(f"  run {i}/{runs}: {outcome.upper():8} ({seconds}s) tools={tools or 'none'}"
                  f"{' via ' + matched if matched else ''}", flush=True)
            results.append({
                "attack_id": attack["id"], "category": attack["category"], "owasp": attack["owasp"],
                "technique": attack["technique"], "run": i, "outcome": outcome, "matched_rule": matched,
                "email_sent": email_sent, "seconds": seconds, "prompt": attack["prompt"],
                "response": resp.get("response", ""), "tool_trace": resp.get("tool_trace", []),
            })
    finally:
        if fixture_path and fixture_path.exists():
            fixture_path.unlink()
    return results


def summarize(results):
    cats = defaultdict(lambda: defaultdict(int))
    for r in results:
        cats[r["category"]][r["outcome"]] += 1
        cats[r["category"]]["runs"] += 1
    return {c: dict(v) for c, v in cats.items()}


def main():
    ap = argparse.ArgumentParser(description="Run the attack library against a chat endpoint.")
    ap.add_argument("--url", default="http://127.0.0.1:8000/chat")
    ap.add_argument("--runs", type=int, default=3, help="repetitions per attack")
    ap.add_argument("--label", default="scan", help="name used in the output file, e.g. before or after")
    ap.add_argument("--only", default=None, help="run only one category, e.g. jailbreak")
    ap.add_argument("--timeout", type=int, default=180)
    args = ap.parse_args()

    lib = yaml.safe_load(LIB.read_text(encoding="utf-8"))
    secrets = lib["secrets"]
    attacks = [a for a in lib["attacks"] if args.only in (None, a["category"])]
    print(f"Scanning {args.url} with {len(attacks)} attacks x {args.runs} runs", flush=True)

    all_results = []
    try:
        for attack in attacks:
            print(f"\n=== {attack['id']} {attack['category']} ({attack['technique']}) ===", flush=True)
            all_results += run_attack(attack, args.url, args.runs, secrets, args.timeout)
    except KeyboardInterrupt:
        print("\nInterrupted: saving the results collected so far.")

    summary = summarize(all_results)
    total = len(all_results)
    ok = [r for r in all_results if r["outcome"] != "error"]
    n_success = sum(r["outcome"] == "success" for r in ok)
    n_partial = sum(r["outcome"] == "partial" for r in ok)

    print("\n===== SUMMARY =====")
    print(f"{'category':24} {'runs':>5} {'success':>8} {'partial':>8} {'blocked':>8} {'error':>6}")
    for cat, v in sorted(summary.items()):
        print(f"{cat:24} {v['runs']:>5} {v.get('success', 0):>8} {v.get('partial', 0):>8} "
              f"{v.get('blocked', 0):>8} {v.get('error', 0):>6}")
    if ok:
        print(f"\nAttack success rate: {n_success}/{len(ok)} = {100 * n_success / len(ok):.0f}%")
        print(f"Success or partial : {n_success + n_partial}/{len(ok)} = {100 * (n_success + n_partial) / len(ok):.0f}%")
    if total - len(ok):
        print(f"Errors (not counted): {total - len(ok)}")

    REPORTS.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = REPORTS / f"scan_{args.label}_{stamp}.json"
    out.write_text(json.dumps({
        "label": args.label, "url": args.url, "runs_per_attack": args.runs, "timestamp": stamp,
        "totals": {"runs": total, "success": n_success, "partial": n_partial, "errors": total - len(ok)},
        "summary": summary, "results": all_results,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nRaw data saved to {out}")


if __name__ == "__main__":
    main()
