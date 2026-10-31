from pathlib import Path
import sys
import yaml

LIB = Path(__file__).parent / "attacks.yaml"
CATEGORIES = {"prompt_leak", "sensitive_file_access", "path_traversal",
              "indirect_injection", "jailbreak", "unauthorized_action"}
RULES = {"secret_in_reply", "secret_in_trace", "reply_contains", "tool_called", "email_sent"}
REQUIRED = ["id", "category", "owasp", "technique", "severity", "prompt", "success"]

data = yaml.safe_load(LIB.read_text(encoding="utf-8"))
attacks = data["attacks"]
errors, seen, per_category = [], set(), {}

for a in attacks:
    aid = a.get("id", "?")
    for field in REQUIRED:
        if field not in a:
            errors.append(f"{aid}: missing field '{field}'")
    if aid in seen:
        errors.append(f"{aid}: duplicate id")
    seen.add(aid)
    cat = a.get("category")
    if cat not in CATEGORIES:
        errors.append(f"{aid}: unknown category '{cat}'")
    per_category[cat] = per_category.get(cat, 0) + 1
    for key in ("success", "partial"):
        for rule in a.get(key, []):
            if rule.get("type") not in RULES:
                errors.append(f"{aid}: unknown rule type '{rule.get('type')}' in {key}")
    fx = a.get("fixture")
    if fx and not {"file", "content"} <= set(fx):
        errors.append(f"{aid}: fixture needs 'file' and 'content'")

print(f"{len(attacks)} attacks, {len(per_category)} categories")
for cat, n in sorted(per_category.items(), key=lambda x: str(x[0])):
    print(f"  {cat}: {n}")
print(f"{len(errors)} errors")
for e in errors:
    print("  -", e)
sys.exit(1 if errors else 0)