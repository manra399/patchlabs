#!/usr/bin/env bash
# Local stack for the signed-in app's end-to-end test (tools/e2e.mjs): postgres:17, a GitHub + webhook stub and the API
# (built from api/Dockerfile) on a private Docker network, the API on localhost:8001, and the built site on localhost:9137.
#   tools/e2e/stack.sh up      # build the site and the API image, start everything
#   tools/e2e/stack.sh down    # stop and remove everything it started
# Magic links and other emails land in .shots/e2e-outbox/outbox.jsonl. Test tokens only: never real data.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NET=pl-e2e; SITE_PORT="${SITE_PORT:-9137}"; OUT="$ROOT/.shots/e2e-outbox"

down() {
  docker rm -f pl-e2e-api pl-e2e-stub pl-e2e-db >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  pkill -f "tools/e2e/serve.py $SITE_PORT" 2>/dev/null || true
}

up() {
  down
  mkdir -p "$OUT" && chmod 777 "$OUT" && rm -f "$OUT/outbox.jsonl"
  python3 "$ROOT/tools/build.py" >/dev/null
  DOCKER_CLI_HINTS=false docker build -q -f "$ROOT/api/Dockerfile" -t patchlabs-api:e2e "$ROOT" >/dev/null 2>&1
  docker network create "$NET" >/dev/null
  docker run -d --name pl-e2e-db --network "$NET" -e POSTGRES_PASSWORD=e2e -e POSTGRES_DB=patchlabs postgres:17 >/dev/null
  docker run -d --name pl-e2e-stub --network "$NET" -p 127.0.0.1:9298:8080 -v "$ROOT/tools/e2e/stub.py:/stub.py:ro" python:3.13-slim python -u /stub.py >/dev/null
  for _ in $(seq 1 60); do docker exec pl-e2e-db pg_isready -U postgres -d patchlabs -h 127.0.0.1 >/dev/null 2>&1 && break; sleep 1; done
  docker run -d --name pl-e2e-api --network "$NET" --user root -p 8001:8000 \
    -v "$ROOT/tools/e2e/e2e_main.py:/app/e2e_main.py:ro" -v "$OUT:/outbox" \
    -e DATABASE_URL=postgresql://postgres:e2e@pl-e2e-db:5432/patchlabs -e WORKER_TOKEN=e2e-worker-token -e ADMIN_TOKEN=e2e-admin-token \
    -e SITE_URL="http://localhost:$SITE_PORT" -e CORS_ORIGINS="http://localhost:$SITE_PORT,http://127.0.0.1:$SITE_PORT" \
    -e GITHUB_API=http://pl-e2e-stub:8080/gh -e RAW_GITHUB=http://pl-e2e-stub:8080/raw -e EMAIL_OUTBOX=/outbox/outbox.jsonl \
    -e AUTH_PER_IP_PER_HOUR=100000 -e FOUNDER_EMAIL=founder@example.test \
    -e RECEIPT_PRIVATE_KEY="$(python3 -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())')" \
    patchlabs-api:e2e uvicorn e2e_main:app --host 0.0.0.0 --port 8000 >/dev/null
  for _ in $(seq 1 30); do curl -sf localhost:8001/health >/dev/null && break; sleep 1; done
  curl -sf localhost:8001/health >/dev/null || { docker logs pl-e2e-api | tail -20; exit 1; }
  nohup python3 "$ROOT/tools/e2e/serve.py" "$SITE_PORT" "$ROOT/docs" >/dev/null 2>&1 &
  for _ in $(seq 1 20); do curl -sf "localhost:$SITE_PORT/" >/dev/null && break; sleep 0.25; done
  echo "API http://localhost:8001 · site http://localhost:$SITE_PORT · stub http://localhost:9298 · outbox $OUT/outbox.jsonl"
}

case "${1:-up}" in up) up ;; down) down ;; *) echo "usage: $0 up|down"; exit 2 ;; esac
