# AI Security Toolkit - one small image for all three programs (agent, firewall, Control Center).
# LOCAL LAB ONLY. Fake data only. The compose file publishes ports on 127.0.0.1 only.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

# The project folder itself is mounted at /app by docker-compose.yml, so the three programs share
# the same alerts, kill switch and approvals files, exactly like on your computer.
COPY . .
