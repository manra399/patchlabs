#!/usr/bin/env bash
# Runs the API test suite in Docker from scratch: a throwaway postgres:17 plus a python:3.13-slim runner on a private
# network. Everything is removed afterwards. Extra arguments go to pytest, e.g. tools/test-api.sh -k webhook -x
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ID="patchlabs-test-$$"
cleanup() { docker rm -f "$ID-db" >/dev/null 2>&1 || true; docker network rm "$ID" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

docker network create "$ID" >/dev/null
docker run -d --name "$ID-db" --network "$ID" -e POSTGRES_PASSWORD=test -e POSTGRES_DB=patchlabs postgres:17 >/dev/null
for _ in $(seq 1 60); do
  docker exec "$ID-db" pg_isready -U postgres -d patchlabs -h 127.0.0.1 >/dev/null 2>&1 && break
  sleep 1
done

docker run --rm --network "$ID" -v "$ROOT:/src:ro" -w /src \
  -e DATABASE_URL="postgresql://postgres:test@$ID-db:5432/patchlabs" -e PYTHONDONTWRITEBYTECODE=1 -e PIP_ROOT_USER_ACTION=ignore \
  python:3.13-slim sh -c 'pip install -q --disable-pip-version-check -r api/requirements-dev.txt && python -m pytest -p no:cacheprovider api/tests "$@"' sh "$@"
