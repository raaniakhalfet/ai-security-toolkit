"""Approve or deny pending requests from the terminal.

  python approve.py                list pending requests
  python approve.py approve 3      approve request #3 (the email is then written to the outbox)
  python approve.py deny 3         deny request #3
"""
import sys

import approvals


def show():
    items = approvals.all_requests()
    pending = [i for i in items if i["status"] == "pending"]
    print(f"{len(pending)} pending, {len(items)} total")
    for i in items[-10:]:
        a = i["args"]
        print(f"  #{i['id']} [{i['status']:8}] {i['ts']}  {i['tool']}  to={a.get('to')}  subject={a.get('subject')}")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] in ("approve", "deny") and sys.argv[2].isdigit():
        r = approvals.decide(int(sys.argv[2]), sys.argv[1] == "approve")
        print("Done." if r else "Nothing changed (unknown id, or already decided).")
    show()
