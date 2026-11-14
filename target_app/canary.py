"""Canary tokens: traps that trigger a CRITICAL alert the moment a planted fake secret is touched.

Shared by the agent's tools and by the firewall. The list lives in canaries.yaml.
"""
import json
import re
import time
from pathlib import Path

import yaml

ALERTS = Path(__file__).parent.parent / "firewall" / "alerts.jsonl"
TOKEN = re.compile(r"CANARY-[0-9A-F]{8}")


def _load():
    try:
        data = yaml.safe_load((Path(__file__).parent / "canaries.yaml").read_text(encoding="utf-8")) or {}
        planted = {str(c["token"]): str(c.get("planted_in", "?")) for c in data.get("canaries", []) if "token" in c}
        honey = {str(h).lower() for h in data.get("honeyfiles", [])}
        return planted, honey
    except Exception:
        return {}, set()


PLANTED, HONEYFILES = _load()


def tokens_in(text):
    """Planted canary tokens found in a text, as (token, file it was planted in)."""
    return [(t, PLANTED.get(t, "?")) for t in dict.fromkeys(TOKEN.findall(str(text))) if t in PLANTED]


def alert(rule, detail, layer="canary"):
    ALERTS.parent.mkdir(exist_ok=True)
    event = {"ai_source": "ai-security-toolkit", "ai_ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
             "ai_layer": layer, "ai_rule": rule, "ai_action": "alert", "ai_detail": str(detail)[:200]}
    with ALERTS.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")
