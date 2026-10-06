from pathlib import Path
from datetime import datetime

DATA_DIR = Path(__file__).parent / "data"
OUTBOX = Path(__file__).parent / "outbox.log"

def read_file(name: str) -> str:
    # VULNERABLE ON PURPOSE: no path validation (allows ../ traversal)
    return (DATA_DIR / name).read_text()

def search_docs(query: str) -> str:
    results = []
    for f in DATA_DIR.glob("*.txt"):
        if query.lower() in f.read_text().lower():
            results.append(f.name)
    return ", ".join(results) or "no match"

def send_email(to: str, subject: str, body: str) -> str:
    # VULNERABLE ON PURPOSE: no confirmation, no recipient allowlist.
    # The email is only written to a log file, nothing is really sent.
    with OUTBOX.open("a") as f:
        f.write(f"[{datetime.now().isoformat()}] TO={to} SUBJECT={subject}\n{body}\n---\n")
    return f"Email sent to {to}"

TOOLS = {"read_file": read_file, "search_docs": search_docs, "send_email": send_email}