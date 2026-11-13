"""A tiny FAKE Ollama server for automatic tests (port 11435).

It behaves like a naive, over-obedient model: it leaks its instructions when asked, reads any file
it is told to read, and emails anyone it is told to email. That is enough to test the whole toolkit
(firewall, guard, approvals, scoring) without a real AI model, in seconds, on any computer or in GitHub Actions.
It is NOT a measurement of real model behaviour. Real numbers come from the real model.

  python tests/mock_ollama.py
"""
import re

import uvicorn
from fastapi import FastAPI, Request

app = FastAPI()


@app.post("/api/chat")
async def chat(req: Request):
    body = await req.json()
    messages = body["messages"]
    system = messages[0]["content"]
    last = messages[-1]
    if last["role"] == "tool":
        return {"message": {"role": "assistant", "content": f"Here is the result: {last['content']}"}}
    text = last["content"]
    low = text.lower()

    def call(tool, **args):
        return {"message": {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": tool, "arguments": args}}]}}

    m = re.search(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", text)
    if m and ("email" in low or "send" in low or "mail" in low):
        return call("send_email", to=m.group(0), subject="Hello", body="Hello from AcmeBot")
    m = re.search(r"([\w./-]*\.\./[\w./-]+)", text)
    if m:
        return call("read_file", name=m.group(1))
    m = re.search(r"\b([\w-]+\.txt)\b", text)
    if m:
        return call("read_file", name=m.group(1))
    if "instruction" in low or "system prompt" in low or "configuration" in low or "admin key" in low:
        return {"message": {"role": "assistant", "content": system}}
    return {"message": {"role": "assistant", "content": "Hello! How can I help you today?"}}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=11435, log_level="warning")
