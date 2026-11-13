"""Human approval queue for risky tool calls (used by the guard).

When approval is required, the tool does NOT run. A request is stored here with status
"pending". A person approves or denies it (Control Center "Approvals" tab, or
`python approve.py`). Only an approved email is really written to the outbox.
LOCAL LAB ONLY. Nothing is ever sent: the outbox is a log file.
"""
import json
import threading
import time
from datetime import datetime
from pathlib import Path

FILE = Path(__file__).parent / "approvals.json"
OUTBOX = Path(__file__).parent / "outbox.log"
_LOCK = threading.Lock()


def _load():
    if not FILE.exists():
        return []
    try:
        return json.loads(FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def _save(items):
    FILE.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")


def add(tool, args):
    """Queue a request and return its id (a short number)."""
    with _LOCK:
        items = _load()
        rid = (max((i["id"] for i in items), default=0)) + 1
        items.append({"id": rid, "ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "tool": tool,
                      "args": args, "status": "pending", "decided_at": None})
        _save(items)
    return rid


def all_requests():
    with _LOCK:
        return _load()


def decide(rid, approve):
    """Approve or deny request `rid`. Returns the updated request, or None if not found/not pending."""
    with _LOCK:
        items = _load()
        for item in items:
            if item["id"] == rid and item["status"] == "pending":
                item["status"] = "approved" if approve else "denied"
                item["decided_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                if approve and item["tool"] == "send_email":
                    a = item["args"]
                    with OUTBOX.open("a") as f:
                        f.write(f"[{datetime.now().isoformat()}] TO={a.get('to')} SUBJECT={a.get('subject')} (approved by a human, request #{rid})\n"
                                f"{a.get('body')}\n---\n")
                _save(items)
                return item
    return None
