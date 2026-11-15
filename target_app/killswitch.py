"""Emergency stop (kill switch). One small file shared by the agent, the firewall and the Control Center.

When it is ON, the agent and the firewall refuse every request until someone switches it OFF.
Switch it from the Control Center (red button), or with:  python toolkit.py kill on / off
LOCAL LAB ONLY.
"""
import json
import time
from pathlib import Path

STATE = Path(__file__).parent / "killswitch.json"


def status():
    try:
        data = json.loads(STATE.read_text(encoding="utf-8"))
        return {"active": bool(data.get("active")), "since": data.get("since", ""), "reason": data.get("reason", "")}
    except Exception:
        return {"active": False, "since": "", "reason": ""}


def is_active():
    return status()["active"]


def set_active(active, reason=""):
    data = {"active": bool(active), "since": time.strftime("%Y-%m-%dT%H:%M:%S"), "reason": str(reason)[:200]}
    STATE.write_text(json.dumps(data), encoding="utf-8")
    return data
