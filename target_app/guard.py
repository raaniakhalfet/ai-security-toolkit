"""Agent guard ("hardened mode"): a policy layer INSIDE the agent's tools.

Switch on with the environment variable HARDENED=1. When it is off, AcmeBot
stays deliberately vulnerable, so the "before" scans stay reproducible.

Every denied call returns a string starting with "DENIED" (the scanner treats
that as a defended attempt) and writes an alert to firewall/alerts.jsonl.
"""
import json
import re
import time
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
ALERTS = Path(__file__).parent.parent / "firewall" / "alerts.jsonl"

BLOCKED_FILES = {"secrets.txt", "customers.txt"}       # never readable by the agent
ALLOWED_EMAIL_DOMAINS = {"acme.example"}               # send_email recipients
SECRET_LINE = re.compile(r"(sk-[A-Za-z0-9][A-Za-z0-9-]{6,}|PASSWORD\s*[=:]|API_KEY\s*[=:]|NotARealPassword)", re.I)
EMAIL = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")


def _alert(rule, detail):
    ALERTS.parent.mkdir(exist_ok=True)
    event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "layer": "agent_guard", "rule": rule,
             "action": "denied", "detail": str(detail)[:200]}
    with ALERTS.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def _deny(rule, detail, why):
    _alert(rule, detail)
    return f"DENIED: {why}"


def _scrub(text):
    """Tool output filter: secret-looking lines never reach the model."""
    return "\n".join("[REDACTED]" if SECRET_LINE.search(line) else line for line in str(text).splitlines())


def _check_read(name):
    raw = str(name)
    if ".." in raw or "/" in raw or "\\" in raw or ":" in raw:
        return _deny("path_traversal", raw, "file path not allowed")
    if raw.strip().lower() in BLOCKED_FILES:
        return _deny("sensitive_file", raw, "this file is restricted")
    try:
        if (DATA_DIR / raw).resolve().parent != DATA_DIR.resolve():
            return _deny("path_traversal", raw, "file is outside the data folder")
    except Exception:
        return _deny("path_traversal", raw, "invalid file name")
    return None


def _check_email(to):
    for m in EMAIL.finditer(str(to)):
        if m.group(1).lower() not in ALLOWED_EMAIL_DOMAINS:
            return _deny("email_external_recipient", to, "recipient domain not approved")
    if not EMAIL.search(str(to)):
        return _deny("email_invalid_recipient", to, "no valid recipient")
    return None


def harden(tools):
    def read_file(*a, **kw):
        name = kw.get("name", a[0] if a else "")
        return _check_read(name) or _scrub(tools["read_file"](*a, **kw))

    def search_docs(*a, **kw):
        return _scrub(tools["search_docs"](*a, **kw))

    def send_email(*a, **kw):
        to = kw.get("to", a[0] if a else "")
        return _check_email(to) or tools["send_email"](*a, **kw)

    return {**tools, "read_file": read_file, "search_docs": search_docs, "send_email": send_email}