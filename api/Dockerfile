FROM python:3.13-slim
WORKDIR /app
COPY api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY api/app.py api/core.py api/accounts.py api/monitor.py api/receipts.py api/rls.py api/mcp_server.py api/support.py api/audit.py api/alerts.py api/taxonomy.py api/posture.py api/watchdog.py api/interest.py ./
COPY db/schema.sql ./
RUN useradd -r app && chown -R app /app
USER app
EXPOSE 8000
# --proxy-headers only sets the scheme/host behind Azure's ingress. Rate limits never use request.client: core.client_ip reads
# the rightmost X-Forwarded-For entry, the one the ingress appends.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
