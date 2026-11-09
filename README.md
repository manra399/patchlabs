# PatchLabs

Leak checks and tested fixes for AI-built apps: https://patchlabs.dev

| Part | Where | Runs on |
|---|---|---|
| `docs/` | Website: landing page, check status and report page, privacy | GitHub Pages (patchlabs.dev) |
| `api/` | FastAPI: check requests, repo-ownership verification, worker queue, results | Azure Container Apps (api.patchlabs.dev) |
| `db/schema.sql` | Postgres schema (checks, check_events, kv); applied by the API on start | Azure Database for PostgreSQL, database `patchlabs` |
| `worker/` | Takes verified checks, runs the lab pipeline (Docker + Claude Code), posts reports | Manraj's Mac, kept alive by launchd |

## Flow
1. Visitor enters a GitHub repo and email on patchlabs.dev → `POST /checks`.
2. They prove the repo is theirs by committing `patchlabs-verify.txt` with a one-time code → `POST /checks/{id}/verify`.
3. The worker claims the check (`POST /worker/claim`), rebuilds the database from the repo's migrations in a lab, finds personal data the wrong people can read, has the fix agent write a fix (Haiku first, escalating to Sonnet then Opus only if the lab proof fails), and posts the report (`POST /worker/checks/{id}/result`).
4. The check page shows the report, the proof table and the fix, and offers the fix as a download. An email goes out at each step once SMTP is configured.

## Deploy the API
```bash
TAG=$(date +%Y%m%d%H%M)
az acr build -r sponsorjobsregistry -t patchlabs-api:$TAG -f api/Dockerfile .
az containerapp update -g ics-rg -n patchlabs-api --image sponsorjobsregistry.azurecr.io/patchlabs-api:$TAG
```
