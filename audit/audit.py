"""AI Security Toolkit - Module 2: the firewall (port 8001).

Sits between the user and AcmeBot (port 8000):

    user -> [ INPUT FILTER ] -> AcmeBot -> [ OUTPUT FILTER + TOOL AUDIT ] -> user

Every blocked or redacted event is written to firewall/alerts.jsonl
(Module 3 will send these alerts to Splunk).
LOCAL LAB ONLY. Fake data only.
"""
import json
import os
import re
import time
from pathlib import Path

import requests
from fastapi import FastAPI
from pydantic import BaseModel

BACKEND_URL = os.environ.get("BACKEND_URL", "http://127.0.0.1:8000/chat")
ALERTS = Path(__file__).parent / "alerts.jsonl"
BLOCK_MESSAGE = "Sorry, I can't help with that request."

# ---------------------------------------------------------------- policy
# 1) Input rules: (rule name, regex). Case-insensitive.
INPUT_RULES = [
    ("prompt_leak", r"(repeat|print|show|reveal|display|output|tell me|give me)\b.{0,40}\b(your|the)\b.{0,20}\b(instructions|system prompt|initial prompt|rules|configuration)"),
    ("prompt_leak", r"\bsystem prompt\b"),
    ("prompt_leak", r"word for word"),
    ("override", r"(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|your)\b.{0,30}\b(instructions|rules|prompt|guidelines)"),
    ("jailbreak", r"\b(debug|developer|admin|maintenance|god|sudo|dan)\s+mode\b"),
    ("jailbreak", r"(pretend|act|behave|roleplay|role-play|imagine)\b.{0,30}\b(you are|you're|as|to be)\b"),
    ("jailbreak", r"\b(admin|api|secret|master)\s*(key|token|password)\b"),
    ("sensitive_file", r"\b(secrets?|credentials?|passwords?)\.(txt|json|env|yaml|yml)\b|\.env\b|id_rsa|\bsecrets? file\b|\b(read|open|cat|show|print)\b.{0,15}\bsecrets?\b"),
    ("path_traversal", r"\.\./|\.\.\\|(^|\s)\.\.(\s|$)|%2e%2e|\bapp\.py\b|\btools\.py\b|/etc/|c:\\\\"),
    ("bulk_data", r"\b(all|every)\b.{0,20}\b(customers?|clients?|users?)\b.{0,40}\b(data|records?|emails?|list|file|details)\b"),
    ("bulk_data", r"\bcustomers?\.txt\b"),
]

# 2) Email policy: the bot may only email these domains.
ALLOWED_EMAIL_DOMAINS = {"acme.example"}
EMAIL_INTENT = re.compile(r"\b(send|email|e-mail|mail|forward|write to)\b", re.I)
EMAIL_ADDR = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")

# 3) Output rules: anything that looks like a secret is redacted.
OUTPUT_PATTERNS = [
    ("api_key", r"sk-[A-Za-z0-9][A-Za-z0-9-]{6,}"),
    ("password", r"(DB_PASSWORD|PASSWORD|API_KEY|INTERNAL_API_KEY)\s*[=:]\s*\S+"),
    ("password", r"NotARealPassword!?"),
    ("system_prompt", r"You are AcmeBot,? the internal assistant[^\n]*"),
]
SENSITIVE_FILES = ("secrets.txt",)


# ---------------------------------------------------------------- logic
def log_alert(layer, rule, action, detail):
    event = {"ai_source": "ai-security-toolkit", "ai_ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
             "ai_layer": layer, "ai_rule": rule, "ai_action": action, "ai_detail": str(detail)[:200]}
    with ALERTS.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def check_input(message):
    """Return (rule, reason) if the message must be blocked, else None."""
    for name, pattern in INPUT_RULES:
        if re.search(pattern, message, re.I):
            return name
    if EMAIL_INTENT.search(message):
        for m in EMAIL_ADDR.finditer(message):
            if m.group(1).lower() not in ALLOWED_EMAIL_DOMAINS:
                return "email_external_recipient"
    return None


def redact(text):
    hits = []
    for name, pattern in OUTPUT_PATTERNS:
        if re.search(pattern, text, re.I):
            hits.append(name)
            text = re.sub(pattern, "[REDACTED]", text, flags=re.I)
    return text, hits


def audit_trace(trace):
    """Detective control: flag dangerous tool calls that already happened."""
    findings = []
    for t in trace or []:
        args = str(t.get("args", ""))
        if t.get("tool") == "read_file" and (".." in args or any(s in args for s in SENSITIVE_FILES)):
            findings.append(("tool_read_sensitive_file", args))
        if t.get("tool") == "send_email":
            for m in EMAIL_ADDR.finditer(args):
                if m.group(1).lower() not in ALLOWED_EMAIL_DOMAINS:
                    findings.append(("tool_email_external", args))
    return findings


# ---------------------------------------------------------------- server
app = FastAPI(title="AI Security Toolkit Firewall")


class Chat(BaseModel):
    message: str


@app.post("/chat")
def chat(body: Chat):
    # Layer 1: input filter
    rule = check_input(body.message)
    if rule:
        log_alert("input", rule, "blocked", body.message)
        return {"response": BLOCK_MESSAGE, "tool_trace": [], "firewall": {"action": "blocked", "rule": rule}}

    # Forward to the real agent
    try:
        data = requests.post(BACKEND_URL, json={"message": body.message}, timeout=300).json()
    except Exception as e:
        log_alert("proxy", "backend_error", "error", e)
        return {"response": "Service unavailable.", "tool_trace": [], "firewall": {"action": "error"}}

    # Layer 2: tool-call audit (alerts; the tool has already run)
    for rule, detail in audit_trace(data.get("tool_trace")):
        log_alert("tool", rule, "alert", detail)

    # Layer 3: output filter
    clean, hits = redact(str(data.get("response", "")))
    action = "passed"
    if hits:
        action = "redacted"
        for h in hits:
            log_alert("output", h, "redacted", data.get("response", ""))
        clean = clean if clean.strip() != "[REDACTED]" else BLOCK_MESSAGE
    data["response"] = clean
    data["firewall"] = {"action": action, "rules": hits}
    return data


@app.get("/health")
def health():
    return {"status": "ok", "backend": BACKEND_URL}