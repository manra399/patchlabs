"""PatchLabs API: takes leak-check requests, proves the requester controls the repo, hands checks to the
worker and serves the results. Accounts and workspaces live in accounts.py, monitored apps in monitor.py, decisions and
signed receipts in receipts.py, the free RLS tool in rls.py, live posture and the free headers tool in posture.py
and the MCP server in mcp_server.py.

Public:  POST /checks, GET /checks/{id}, POST /checks/{id}/verify, GET /health; early access in interest.py
Worker:  POST /worker/claim, POST /worker/heartbeat, POST /worker/checks/{id}/result   (Bearer WORKER_TOKEN)
Admin:   GET /admin/checks                                                          (Bearer ADMIN_TOKEN)
"""
import os, secrets, uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field

import accounts, audit, interest, mcp_server, monitor, posture, receipts, rls, support, taxonomy, watchdog
from core import (ADMIN_TOKEN, EMAIL_RE, FOUNDER_EMAIL, ORIGINS, SITE_URL, VERIFY_FILE, WORKER_TOKEN, bearer, clean_report, db, event, ip_hash, mail, notify,
                  parse_repo, pool, repo_has_code, repo_lookup, scrub, send_email, verify_info)  # noqa: F401 (send_email re-exported)

MAX_OPEN_PER_EMAIL = 3
MAX_PER_IP_PER_DAY = 10
POSTURE_EVERY = int(os.environ.get("POSTURE_EVERY", "600"))  # seconds between live posture sweeps; 0 turns them off
WATCHDOG_EVERY = int(os.environ.get("WATCHDOG_EVERY", "300"))  # seconds between worker-stall checks (watchdog.py); 0 turns it off
SCHEMA = os.environ.get("SCHEMA_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql"))


@asynccontextmanager
async def lifespan(_):
    pool.open()
    with pool.connection() as c:
        c.execute(open(SCHEMA).read())
    if POSTURE_EVERY > 0:
        posture.start_loop(POSTURE_EVERY)
    if WATCHDOG_EVERY > 0:
        watchdog.start_loop(WATCHDOG_EVERY)
    yield
    posture.stop_loop()
    watchdog.stop_loop()
    pool.close()


app = FastAPI(title="PatchLabs API", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
# The API serves JSON and SVG badges, never pages, so it can lock everything down. Found by running our own Live posture
# check on api.patchlabs.dev (self-check, 11 Nov 2026).
SECURITY_HEADERS = {"Strict-Transport-Security": "max-age=63072000; includeSubDomains", "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
                    "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"}


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    return response


app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
                   allow_headers=["Content-Type", "Authorization", "X-API-Key", "X-Workspace"], expose_headers=["Content-Disposition"])
app.include_router(accounts.router)
app.include_router(monitor.router)
app.include_router(receipts.router)
app.include_router(rls.router)
app.include_router(mcp_server.router)
app.include_router(support.router)
app.include_router(audit.router)
app.include_router(taxonomy.router)
app.include_router(posture.router)
app.include_router(interest.router)


class NewCheck(BaseModel):
    email: str = Field(max_length=254, pattern=EMAIL_RE)
    repo: str = Field(max_length=200)


def public_view(row, events):
    out = {k: row[k] for k in ("id", "repo", "branch", "status", "created_at", "verified_at", "finished_at")}
    if row.get("app_id"):
        out["app_id"] = row["app_id"]
    if row["status"] == "awaiting_verification":
        out["verify"] = verify_info(row["repo"], row["branch"], row["verify_code"])
    if row["status"] in ("done", "no_leaks", "needs_review"):
        out.update(summary=scrub(row["summary"]), report_md=clean_report(row["report_md"]), fix_sql=row["fix_sql"])
    if row["status"] == "failed":
        out["error"] = "The check could not finish. We have been alerted and will email you."
    out["events"] = [{"at": e["at"], "kind": e["kind"]} for e in events if not e["kind"].startswith(("email", "webhook"))]
    return out


@app.get("/health")
def health(c=Depends(db)):
    c.execute("SELECT 1")
    hb = c.execute("SELECT updated_at FROM kv WHERE key = 'worker_heartbeat'").fetchone()
    q = c.execute("SELECT count(*) AS n FROM checks WHERE status = 'queued'").fetchone()
    return {"ok": True, "db": "ok", "worker_last_seen": hb["updated_at"] if hb else None, "queued": q["n"]}


@app.post("/checks", status_code=201)
def create_check(body: NewCheck, request: Request, c=Depends(db)):
    repo = parse_repo(body.repo)
    email = body.email.strip()
    iph = ip_hash(request)
    # unverified requests count for a day only, so strangers can't lock an address out by requesting checks for it
    if c.execute("SELECT count(*) AS n FROM checks WHERE lower(email) = lower(%s) AND app_id IS NULL AND (status IN ('queued','running') "
                 "OR (status = 'awaiting_verification' AND created_at > now() - interval '1 day'))", (email,)).fetchone()["n"] >= MAX_OPEN_PER_EMAIL:
        raise HTTPException(429, "You already have checks in progress. We'll email you when they finish.")
    if c.execute("SELECT count(*) AS n FROM checks WHERE ip_hash = %s AND created_at > now() - interval '1 day'",
                 (iph,)).fetchone()["n"] >= MAX_PER_IP_PER_DAY:
        raise HTTPException(429, "Too many requests today. Email manraj@patchlabs.dev and we'll help.")
    repo, branch = repo_lookup(repo)
    cid, code = uuid.uuid4(), "patchlabs-" + secrets.token_hex(8)
    c.execute("INSERT INTO checks (id, email, repo, verify_code, ip_hash, branch) VALUES (%s, %s, %s, %s, %s, %s)",
              (cid, email, repo, code, iph, branch))
    event(c, cid, "requested", repo)
    link = f"{SITE_URL}/check?id={cid}"
    notify(c, cid, email, f"Your PatchLabs leak check for {repo}",
           f"Thanks for asking us to check {repo}.\n\nOne step left: prove the repo is yours by adding a file named {VERIFY_FILE} "
           f"containing\n\n    {code}\n\nto its default branch, then press 'I've added it' here:\n{link}\n\n"
           "We read your code only. We never touch your live app or see your customers' data.\n\nPatchLabs")
    return {"id": str(cid), "status": "awaiting_verification", "repo": repo, "link": link}


def load(c, cid):
    try:
        uuid.UUID(cid)
    except ValueError:
        raise HTTPException(404, "not found")
    row = c.execute("SELECT * FROM checks WHERE id = %s", (cid,)).fetchone()
    if not row:
        raise HTTPException(404, "not found")
    return row


@app.get("/checks/{cid}")
def get_check(cid: str, c=Depends(db)):
    row = load(c, cid)
    events = c.execute("SELECT at, kind FROM check_events WHERE check_id = %s ORDER BY at", (cid,)).fetchall()
    out = public_view(row, events)
    if out.get("summary"):  # CWE/OWASP per finding; first_seen/days_open/fixed_at across the app's checks
        out["summary"] = taxonomy.enrich_summary(c, out["summary"], row)
    return {**out, **monitor.check_extras(c, row), "decisions": receipts.decisions(c, cid), "answers": receipts.answers(c, cid)}


@app.post("/checks/{cid}/verify")
def verify_check(cid: str, c=Depends(db)):
    row = load(c, cid)
    if row["status"] != "awaiting_verification":
        return {"status": row["status"]}
    if not repo_has_code(row["repo"], row["branch"], row["verify_code"]):
        event(c, cid, "verify_failed")
        raise HTTPException(409, f"We couldn't find {VERIFY_FILE} with your code on the default branch yet. "
                                 "GitHub can take a minute to update; try again shortly.")
    c.execute("UPDATE checks SET status = 'queued', verified_at = now() WHERE id = %s", (cid,))
    event(c, cid, "verified")
    return {"status": "queued"}


@app.post("/worker/heartbeat", dependencies=[Depends(bearer(WORKER_TOKEN))])
def heartbeat(c=Depends(db)):
    c.execute("INSERT INTO kv (key, value) VALUES ('worker_heartbeat', 'ok') "
              "ON CONFLICT (key) DO UPDATE SET value = 'ok', updated_at = now()")
    return {"ok": True}


@app.post("/worker/claim", dependencies=[Depends(bearer(WORKER_TOKEN))])
def claim(c=Depends(db)):
    heartbeat(c)
    # a check left running for 2 hours means the worker died mid-run: put it back in the queue
    c.execute("UPDATE checks SET status = 'queued', claimed_at = NULL WHERE status = 'running' AND claimed_at < now() - interval '2 hours'")
    monitor.schedule_due(c)
    row = c.execute("UPDATE checks SET status = 'running', claimed_at = now() WHERE id = ("
                    " SELECT id FROM checks WHERE status = 'queued' ORDER BY verified_at FOR UPDATE SKIP LOCKED LIMIT 1"
                    ") RETURNING id, repo").fetchone()
    if not row:
        return {"check": None}
    event(c, row["id"], "started")
    return {"check": {"id": str(row["id"]), "repo": row["repo"]}}


class Result(BaseModel):
    status: str = Field(pattern="^(done|no_leaks|needs_review|failed)$")
    summary: dict | None = None
    report_md: str | None = Field(default=None, max_length=200_000)
    fix_sql: str | None = Field(default=None, max_length=200_000)
    cost_usd: float | None = None
    error: str | None = Field(default=None, max_length=5_000)


@app.post("/worker/checks/{cid}/result", dependencies=[Depends(bearer(WORKER_TOKEN))])
def result(cid: str, body: Result, c=Depends(db)):
    row = load(c, cid)
    c.execute("UPDATE checks SET status = %s, summary = %s, report_md = %s, fix_sql = %s, cost_usd = %s, error = %s, finished_at = now() "
              "WHERE id = %s", (body.status, Jsonb(body.summary) if body.summary else None, body.report_md, body.fix_sql,
                                body.cost_usd, body.error, cid))
    event(c, cid, body.status)
    if body.status in ("failed", "needs_review"):  # the customer is told "a person is on it": make that true
        mail(FOUNDER_EMAIL, f"Check {body.status.replace('_', ' ')}: {row['repo']}",
             f"Check {cid} for {row['repo']} finished as {body.status}.\n\n"
             + (f"Error: {(body.error or '')[:1000]}\n\n" if body.error else "")
             + f"Report: {SITE_URL}/check?id={cid}\nAdmin: {SITE_URL}/admin\n")
    if row["app_id"]:
        monitor.notify_app_check(c, cid)
    elif body.status != "failed":
        headline = {"done": "we found leaks and a tested fix is ready", "needs_review": "we found leaks; a person is reviewing the fix",
                    "no_leaks": "we found no data leaks"}[body.status]
        notify(c, cid, row["email"], f"Your PatchLabs leak check for {row['repo']} is ready",
               f"Your check of {row['repo']} has finished: {headline}.\n\nSee the report and the fix here:\n"
               f"{SITE_URL}/check?id={cid}\n\nPatchLabs")
    return {"ok": True}


@app.get("/admin/checks", dependencies=[Depends(bearer(ADMIN_TOKEN))])
def admin_checks(c=Depends(db)):
    rows = c.execute("SELECT id, created_at, email, repo, status, verified_at, finished_at, cost_usd, summary, app_id, trigger FROM checks "
                     "ORDER BY created_at DESC LIMIT 200").fetchall()
    return {"checks": rows}
