# PatchLabs

Leak checks and tested fixes for AI-built apps: https://patchlabs.dev

| Part | Where | Runs on |
|---|---|---|
| `docs/` | Website: landing page, check status and report page, privacy | GitHub Pages (patchlabs.dev) |
| `api/` | FastAPI: checks, accounts, workspaces, monitored apps, receipts, free RLS tool, MCP (see API below) | Azure Container Apps (api.patchlabs.dev) |
| `db/schema.sql` | Postgres schema, idempotent and additive; applied by the API on start | Azure Database for PostgreSQL, database `patchlabs` |
| `worker/` | Takes verified checks, runs the lab pipeline (Docker + Claude Code), posts reports; deletes run folders older than 30 days | Manraj's Mac, kept alive by launchd |

## Flow
1. Visitor enters a GitHub repo and email on patchlabs.dev → `POST /checks`.
2. They prove the repo is theirs by committing `patchlabs-verify.txt` with a one-time code → `POST /checks/{id}/verify`.
3. The worker claims the check (`POST /worker/claim`), rebuilds the database from the repo's migrations in a lab, finds personal data the wrong people can read, has the fix agent write a fix (Haiku first, escalating to Sonnet then Opus only if the lab proof fails), and posts the report (`POST /worker/checks/{id}/result`).
4. The check page shows the report, the proof table and the fix, and offers the fix as a download. An email goes out at each step once SMTP is configured.

## API
Contract: `SPEC.md`. JSON everywhere; errors are `{"detail": "..."}`. Signed-in calls send `Authorization: Bearer <session>`,
CI calls send `X-API-Key: pl_live_...`, worker and admin calls send their bearer tokens.

| Module | Endpoints |
|---|---|
| `app.py` | `GET /health`, `POST /checks`, `GET /checks/{id}`, `POST /checks/{id}/verify`, `POST /worker/heartbeat\|claim` (claim also runs the scheduler), `POST /worker/checks/{id}/result`, `GET /admin/checks` |
| `accounts.py` | `POST /workspaces/{wid}/webhook/rotate-secret`, `POST /auth/start\|finish\|logout`, `POST /invites/accept`, `GET\|PATCH\|DELETE /me`, `GET /me/export`, `GET /me/checks`, `GET\|PATCH /workspaces/{wid}`, `POST /workspaces/{wid}/webhook/test`, `POST /workspaces/{wid}/invites`, `DELETE /workspaces/{wid}/invites/{id}`, `PATCH\|DELETE /workspaces/{wid}/members/{uid}`, `GET\|POST /workspaces/{wid}/api-keys`, `DELETE /workspaces/{wid}/api-keys/{kid}`, `POST /workspaces/{wid}/upgrade-request`, `GET /admin/workspaces`, `PATCH /admin/workspaces/{wid}`, `GET /admin/upgrade-requests` |
| `monitor.py` | `GET\|POST /workspaces/{wid}/apps`, `GET\|PATCH\|DELETE /apps/{aid}`, `POST /apps/{aid}/verify`, `POST /apps/{aid}/checks`, `GET /badge/{aid}.svg`, `GET /public/apps/{aid}`, `GET /stats`, `POST /v1/apps/{aid}/checks`, `GET /v1/checks/{cid}` |
| `receipts.py` | `POST /checks/{id}/decision`, `POST /checks/{id}/answers`, `GET /checks/{id}/decisions` (members), `GET /receipts/{id}`, `GET /.well-known/patchlabs-receipt-key` |
| `rls.py` | `POST /tools/rls-check` |
| `mcp_server.py` | `POST /mcp` (tools: `rls_check`, `start_check`, `get_check`, `list_apps`, `run_check`) |

Env: `DATABASE_URL`, `WORKER_TOKEN`, `ADMIN_TOKEN`, `SITE_URL`, `CORS_ORIGINS`, `SMTP_*`, `RECEIPT_PRIVATE_KEY` (required: base64
of a 32-byte Ed25519 seed, `python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"`; the API refuses to
start without it unless `PATCHLABS_DEV=1`), optional `GITHUB_TOKEN`, `FOUNDER_EMAIL`. Test hooks: `EMAIL_OUTBOX`, `GITHUB_API`,
`RAW_GITHUB`. Security rules (rate limits, verification, masking): see "Security rules" in `SPEC.md`.

Webhooks are signed: `X-PatchLabs-Signature: v1=<hex HMAC-SHA256 of "<timestamp>.<raw body>">` with the workspace's
`whsec_` secret and `X-PatchLabs-Timestamp`; verification snippet at https://patchlabs.dev/docs/webhooks#security.

Verify a receipt (signed bytes are the receipt as JSON with sorted keys and `(",", ":")` separators):
```python
import base64, json, urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
API, CHECK = "https://api.patchlabs.dev", "<check id>"
r = json.load(urllib.request.urlopen(f"{API}/receipts/{CHECK}"))
k = json.load(urllib.request.urlopen(f"{API}/.well-known/patchlabs-receipt-key"))
assert r["key_id"] == k["key_id"], "signed with a different key"
msg = json.dumps(r["receipt"], sort_keys=True, separators=(",", ":")).encode()
pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(k["public_key"]))
pub.verify(base64.b64decode(r["signature"]), msg)  # raises InvalidSignature if anything was changed
print("receipt is genuine:", r["receipt"]["status"], r["receipt"]["tables_leaking"])
```

Tests: `tools/test-api.sh` runs the whole suite in Docker (throwaway postgres:17 + python:3.13-slim) and cleans up after
itself; extra arguments go to pytest, e.g. `tools/test-api.sh -k webhook -x`.

## Deploy the API
```bash
TAG=$(date +%Y%m%d%H%M)
az acr build -r sponsorjobsregistry -t patchlabs-api:$TAG -f api/Dockerfile .
az containerapp update -g ics-rg -n patchlabs-api --image sponsorjobsregistry.azurecr.io/patchlabs-api:$TAG
```
Before the first v2 deploy, set `RECEIPT_PRIVATE_KEY` as a secret on the container app: without it the new image won't start.
