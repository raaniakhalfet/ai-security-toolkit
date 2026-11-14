"""Maps each attack category to the OWASP LLM Top 10 (2025) and MITRE ATLAS.

How sure are the IDs?  Checked on MITRE's own D3FEND/ATLAS pages: AML.T0051 (LLM Prompt Injection) with
.000 direct and .001 indirect, and AML.T0086 (Exfiltration via AI Agent Tool Invocation).
Taken from two secondary sources that agree, NOT yet checked on atlas.mitre.org: AML.T0053, 0054, 0056, 0057.
Check them on https://atlas.mitre.org before quoting them to a jury, because ATLAS renumbers sometimes.
"""

ATLAS = {
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0056": "Extract LLM System Prompt",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0086": "Exfiltration via AI Agent Tool Invocation",
}
OWASP = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
}

# category -> (OWASP ids, ATLAS ids)
CATEGORY_MAP = {
    "prompt_leak": (["LLM07"], ["AML.T0056", "AML.T0051.000"]),
    "jailbreak": (["LLM01"], ["AML.T0054", "AML.T0051.000"]),
    "indirect_injection": (["LLM01"], ["AML.T0051.001"]),
    "sensitive_file_access": (["LLM02"], ["AML.T0057", "AML.T0053"]),
    "path_traversal": (["LLM06"], ["AML.T0053"]),
    "unauthorized_action": (["LLM06"], ["AML.T0086", "AML.T0053"]),
}

# firewall / guard / canary rule -> (OWASP, ATLAS), shown next to each alert
RULE_TAGS = {
    "prompt_leak": ("LLM07", "AML.T0056"), "override": ("LLM01", "AML.T0051.000"), "jailbreak": ("LLM01", "AML.T0054"),
    "sensitive_file": ("LLM02", "AML.T0057"), "path_traversal": ("LLM06", "AML.T0053"), "bulk_data": ("LLM02", "AML.T0086"),
    "email_external_recipient": ("LLM06", "AML.T0086"), "api_key": ("LLM02", "AML.T0057"), "password": ("LLM02", "AML.T0057"),
    "system_prompt": ("LLM07", "AML.T0056"), "canary": ("LLM02", "AML.T0057"),
    "canary_file_opened": ("LLM02", "AML.T0057"), "canary_token_in_reply": ("LLM02", "AML.T0057"),
    "canary_exfil_email": ("LLM02", "AML.T0086"), "approval_required": ("LLM06", "AML.T0086"),
    "tool_read_sensitive_file": ("LLM02", "AML.T0053"), "tool_email_external": ("LLM06", "AML.T0086"),
}

NOT_COVERED = ["Multi-turn attacks", "Training-data poisoning", "Model theft", "Attacks on the model supply chain",
               "Image or audio prompt injection"]
