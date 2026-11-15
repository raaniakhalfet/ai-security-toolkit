"""AI Security Toolkit: one command for everything.

  python toolkit.py up                     start agent + firewall + Control Center (one terminal, Ctrl+C stops all)
  python toolkit.py up --hardened          same, with the guard on
  python toolkit.py up --approval          guard + a human must approve every email (Approvals tab)
  python toolkit.py up --autoblock         firewall cuts off a source after 5 attacks in 60 seconds (5 minutes)
  python toolkit.py kill on|off|status     emergency stop: switch the agent and the firewall off / on
  python toolkit.py scan --runs 5          attack the running agent (see --help for options)
  python toolkit.py audit                  permission audit
  python toolkit.py report                 rebuild all HTML reports from saved scans
  python toolkit.py check                  false-alarm test + automatic tests (no AI model needed)
  python toolkit.py full --runs 5          run EVERY scan (5 setups x 3 attack sets), then build the reports
  python toolkit.py full --runs 3 --configs none,both --sets holdout2     only part of it
  python toolkit.py full --model qwen2.5:3b --runs 3    same scans on a second AI model (ollama pull it first)
  python toolkit.py compare                the same defences on each model, side by side (reports/compare_models.html)

LOCAL LAB ONLY. Servers bind to 127.0.0.1 and only fake data is used.
"""
import argparse
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).parent
PY = sys.executable
LOGS = ROOT / "logs"
sys.path.insert(0, str(ROOT / "scanner"))
from compare import BASE_MODEL, label_prefix  # noqa: E402

# setup name -> (agent environment, goes through the firewall?)
CONFIGS = {
    "none": ({}, False),
    "firewall": ({}, True),
    "guard": ({"HARDENED": "1"}, False),
    "both": ({"HARDENED": "1"}, True),
    "rootfix": ({"HARDENED": "1", "SECURE_PROMPT": "1"}, False),
}
# attack set name -> (library file or None, label prefix)
SETS = {
    "original": (None, ""),
    "holdout": ("attacks_holdout.yaml", "holdout"),
    "holdout2": ("attacks_holdout2.yaml", "holdout2"),
}
# the label word each setup uses in scan file names (matrix.py looks for these)
LABEL = {"none": "before", "firewall": "after", "guard": "guard", "both": "both", "rootfix": "rootfix"}


def port_open(port):
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def wait_port(port, name, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        if port_open(port):
            return
        time.sleep(0.3)
    sys.exit(f"{name} did not start on port {port}. See the logs folder.")


def need_free(*ports):
    busy = [p for p in ports if port_open(p)]
    if busy:
        sys.exit(f"Port(s) {busy} already in use. Close the other terminals running the servers first, then try again.")


def spawn(name, cwd, module, port, env_extra=None):
    LOGS.mkdir(exist_ok=True)
    log = open(LOGS / f"{name}.log", "w", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k not in ("HARDENED", "SECURE_PROMPT", "REQUIRE_APPROVAL", "AUTOBLOCK", "MODEL")}
    env.update(env_extra or {})
    proc = subprocess.Popen([PY, "-m", "uvicorn", module, "--host", "127.0.0.1", "--port", str(port)],
                            cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
    wait_port(port, name)
    return proc


def stop(procs):
    for p in procs:
        p.terminate()
    for p in procs:
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()


def check_model(name):
    """Stop early with a clear message if Ollama is off or the model is not downloaded."""
    try:
        tags = requests.get("http://127.0.0.1:11434/api/tags", timeout=3).json().get("models", [])
    except Exception:
        sys.exit("Ollama does not answer on port 11434. Start Ollama first, then try again.")
    have = {m.get("name", "") for m in tags} | {m.get("name", "").removesuffix(":latest") for m in tags}
    if name not in have:
        sys.exit(f"The model {name} is not installed. Download it first:  ollama pull {name}")


# ------------------------------------------------------------------ commands
def cmd_up(a):
    need_free(8000, 8001, 8002)
    env = {}
    if a.model:
        check_model(a.model)
        env["MODEL"] = a.model
    if a.hardened or a.approval or a.secure_prompt:
        env["HARDENED"] = "1"
    if a.approval:
        env["REQUIRE_APPROVAL"] = "1"
    if a.secure_prompt:
        env["SECURE_PROMPT"] = "1"
    if a.autoblock:
        print("Automatic blocking is ON: 5 attack events in 60 seconds from one source = blocked for 5 minutes.")
    mode = ", ".join(f"{k}={v}" for k, v in env.items()) or "vulnerable (no guard)"
    fw_env = {"AUTOBLOCK": "1"} if a.autoblock else {}
    procs = [spawn("agent", ROOT / "target_app", "app:app", 8000, env),
             spawn("firewall", ROOT / "firewall", "firewall:app", 8001, fw_env),
             spawn("dashboard", ROOT / "dashboard", "dashboard:app", 8002)]
    print(f"Agent mode: {mode}\n"
          "  agent          http://127.0.0.1:8000/docs\n"
          "  firewall       http://127.0.0.1:8001/docs\n"
          "  Control Center http://127.0.0.1:8002\n"
          "Logs are in the logs folder. Press Ctrl+C to stop everything.")
    try:
        while all(p.poll() is None for p in procs):
            time.sleep(1)
        print("A server stopped unexpectedly. See the logs folder.")
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        stop(procs)


def cmd_kill(a):
    sys.path.insert(0, str(ROOT / "target_app"))
    import killswitch
    if a.state == "status":
        s = killswitch.status()
        print("Emergency stop is", "ON since " + s["since"] if s["active"] else "off")
        return
    killswitch.set_active(a.state == "on", "set from the command line")
    print("Emergency stop is now", a.state.upper(), "- the agent and the firewall",
          "refuse every request." if a.state == "on" else "work normally again.")


def run(args, cwd):
    return subprocess.run([PY, *args], cwd=cwd).returncode


def cmd_scan(a):
    args = ["scan.py", "--runs", str(a.runs), "--label", a.label, "--url", a.url]
    if a.library:
        args += ["--library", a.library]
    if a.only:
        args += ["--only", a.only]
    sys.exit(run(args, ROOT / "scanner"))


def cmd_audit(a):
    sys.exit(run(["audit.py"], ROOT / "audit"))


def cmd_report(a):
    scanner = ROOT / "scanner"
    run(["rescore.py"], scanner)
    run(["report.py", "--after"], scanner)
    run(["report.py", "--after", "--prefix", "holdout"], scanner)
    run(["matrix.py"], scanner)
    run(["compare.py"], scanner)


def cmd_compare(a):
    sys.exit(run(["compare.py"], ROOT / "scanner"))


def cmd_check(a):
    code = run(["benign_test.py"], ROOT / "scanner")
    code |= subprocess.run([PY, "-m", "pytest", "-q", "-p", "no:tmpdir", "tests"], cwd=ROOT).returncode
    sys.exit(code)


def cmd_full(a):
    configs = [c.strip() for c in a.configs.split(",")]
    sets = [s.strip() for s in a.sets.split(",")]
    for c in configs:
        if c not in CONFIGS:
            sys.exit(f"Unknown setup {c}. Choose from: {', '.join(CONFIGS)}")
    for s in sets:
        if s not in SETS:
            sys.exit(f"Unknown attack set {s}. Choose from: {', '.join(SETS)}")
    need_free(8000, 8001)
    model = a.model or BASE_MODEL
    if a.model and a.model != BASE_MODEL:
        check_model(a.model)
        print(f"Model for this run: {a.model} (results are saved apart, the earlier scans are not touched)")
    start = time.time()
    for c in configs:
        env, via_firewall = CONFIGS[c]
        env = {**env, **({"MODEL": a.model} if a.model and a.model != BASE_MODEL else {})}
        print(f"\n######## setup: {c}  (agent env {env or 'none'}, firewall {'on' if via_firewall else 'off'}) ########", flush=True)
        procs = [spawn("agent", ROOT / "target_app", "app:app", 8000, env)]
        if via_firewall:
            procs.append(spawn("firewall", ROOT / "firewall", "firewall:app", 8001))
        url = "http://127.0.0.1:8001/chat" if via_firewall else "http://127.0.0.1:8000/chat"
        try:
            for s in sets:
                library, prefix = SETS[s]
                label = f"{label_prefix(model)}{prefix}{LABEL[c]}"
                args = ["scan.py", "--runs", str(a.runs), "--label", label, "--url", url, "--model", model]
                if library:
                    args += ["--library", library]
                print(f"\n---- scan {label} ----", flush=True)
                run(args, ROOT / "scanner")
        finally:
            stop(procs)
    print(f"\nAll scans done in {(time.time() - start) / 60:.0f} minutes. Building the reports...")
    cmd_report(a)


def main():
    ap = argparse.ArgumentParser(description="AI Security Toolkit (local lab only)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("up", help="start agent, firewall and Control Center")
    p.add_argument("--hardened", action="store_true", help="turn the guard on")
    p.add_argument("--approval", action="store_true", help="guard + human approval for emails")
    p.add_argument("--autoblock", action="store_true", help="firewall blocks a source after 5 attacks in 60 s")
    p.add_argument("--model", default="", help="AI model for the agent, e.g. qwen2.5:3b (default llama3.2:3b)")
    p.add_argument("--secure-prompt", action="store_true", help="remove the secret from the system prompt")
    p.set_defaults(fn=cmd_up)

    p = sub.add_parser("scan", help="attack the running agent")
    p.add_argument("--runs", type=int, default=5)
    p.add_argument("--label", default="scan")
    p.add_argument("--url", default="http://127.0.0.1:8000/chat")
    p.add_argument("--library", default=None, help="attacks_holdout.yaml or attacks_holdout2.yaml")
    p.add_argument("--only", default=None, help="only one category, e.g. jailbreak")
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("kill", help="emergency stop: on, off or status")
    p.add_argument("state", choices=["on", "off", "status"])
    p.set_defaults(fn=cmd_kill)

    sub.add_parser("audit", help="permission audit").set_defaults(fn=cmd_audit)
    sub.add_parser("report", help="rebuild HTML reports from saved scans").set_defaults(fn=cmd_report)
    sub.add_parser("check", help="false-alarm test and automatic tests").set_defaults(fn=cmd_check)

    p = sub.add_parser("full", help="run all scans for all setups, then the reports")
    p.add_argument("--runs", type=int, default=5)
    p.add_argument("--configs", default=",".join(CONFIGS))
    p.add_argument("--sets", default=",".join(SETS))
    p.add_argument("--model", default="", help="run everything on this AI model, e.g. qwen2.5:3b")
    p.set_defaults(fn=cmd_full)

    sub.add_parser("compare", help="same defences on each AI model, side by side").set_defaults(fn=cmd_compare)

    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
