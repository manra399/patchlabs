"""PatchLabs API: takes leak-check requests, proves the requester controls the repo, hands checks to the
worker and serves the results.

Public:  POST /checks, GET /checks/{id}, POST /checks/{id}/verify, GET /health
Worker:  POST /worker/claim, POST /worker/heartbeat, POST /worker/checks/{id}/result   (Bearer WORKER_TOKEN)
Admin:   GET /admin/checks                                                          (Bearer ADMIN_TOKEN)
"""
import hashlib, os, re, secrets, smtplib, ssl, uuid
from contextlib import asynccontextmanager
from email.message import EmailMessage

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, Field

DATABASE_URL = os.environ["DATABASE_URL"]
WORKER_TOKEN = os.environ["WORKER_TOKEN"]
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
SITE_URL = os.environ.get("SITE_URL", "https://patchlabs.dev")
ORIGINS = os.environ.get("CORS_ORIGINS", "https://patchlabs.dev,https://www.patchlabs.dev").split(",")
GITHUB_API = os.environ.get("GITHUB_API", "https://api.github.com")
RAW_GITHUB = os.environ.get("RAW_GITHUB", "https://raw.githubusercontent.com")
VERIFY_FILE = "patchlabs-verify.txt"
MAX_OPEN_PER_EMAIL = 3
MAX_PER_IP_PER_DAY = 10
SCHEMA = os.environ.get("SCHEMA_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql"))

pool = ConnectionPool(DATABASE_URL, min_size=0, max_size=5, kwargs={"row_factory": dict_row}, open=False)


@asynccontextmanager
async def lifespan(_):
    pool.open()
    with pool.connection() as c:
        c.execute(open(SCHEMA).read())
    yield
    pool.close()


app = FastAPI(title="PatchLabs API", lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_methods=["GET", "POST"], allow_headers=["Content-Type"])


def db():
    with pool.connection() as c:
        yield c


def event(c, check_id, kind, detail=None):
    c.execute("INSERT INTO check_events (check_id, kind, detail) VALUES (%s, %s, %s)", (check_id, kind, detail))


def bearer(expected):
    def dep(authorization: str = Header(default="")):
        if not expected or not secrets.compare_digest(authorization, f"Bearer {expected}"):
            raise HTTPException(401, "unauthorised")
    return dep


def send_email(to, subject, body):
    """Sends through SMTP when it is configured; returns False (and the caller logs it) when it is not."""
    host = os.environ.get("SMTP_HOST")
    if not host:
        return False
    msg = EmailMessage()
    msg["From"] = os.environ.get("SMTP_FROM", "PatchLabs <manraj@patchlabs.dev>")
    msg["To"], msg["Subject"] = to, subject
    msg.set_content(body)
    with smtplib.SMTP_SSL(host, int(os.environ.get("SMTP_PORT", "465")), context=ssl.create_default_context(), timeout=20) as s:
        s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
        s.send_message(msg)
    return True


def notify(c, check_id, to, subject, body):
    try:
        sent = send_email(to, subject, body)
        event(c, check_id, "email_sent" if sent else "email_skipped", subject if sent else "SMTP not configured")
    except Exception as e:  # a mail outage must never lose the check
        event(c, check_id, "email_failed", str(e)[:300])


REPO_RE = re.compile(r"^(?:https?://)?(?:www\.)?(?:github\.com/)?([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$")


def parse_repo(text):
    m = REPO_RE.match(text.strip())
    if not m:
        raise HTTPException(422, "Enter a GitHub repo, for example github.com/you/your-app")
    return f"{m.group(1)}/{m.group(2)}"


class NewCheck(BaseModel):
    email: str = Field(max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    repo: str = Field(max_length=200)


def public_view(row, events):
    out = {k: row[k] for k in ("id", "repo", "status", "created_at", "verified_at", "finished_at")}
    if row["status"] == "awaiting_verification":
        out["verify"] = {"file": VERIFY_FILE, "code": row["verify_code"],
                         "add_url": f"https://github.com/{row['repo']}/new/{row['branch'] or 'main'}?filename={VERIFY_FILE}&value={row['verify_code']}"}
    if row["status"] in ("done", "no_leaks", "needs_review"):
        out.update(summary=row["summary"], report_md=row["report_md"], fix_sql=row["fix_sql"])
    if row["status"] == "failed":
        out["error"] = "The check could not finish. We have been alerted and will email you."
    out["events"] = [{"at": e["at"], "kind": e["kind"]} for e in events if not e["kind"].startswith("email")]
    return out


@app.get("/health")
def health(c=Depends(db)):
    c.execute("SELECT 1")
    hb = c.execute("SELECT updated_at FROM kv WHERE key = 'worker_heartbeat'").fetchone()
    q = c.execute("SELECT count(*) AS n FROM checks WHERE status = 'queued'").fetchone()
    return {"ok": True, "db": "ok", "worker_last_seen": hb["updated_at"] if hb else None, "queued": q["n"]}


@app.post("/checks", status_code=201)
def create_check(body: NewCheck, request: Request, c=Depends(db)):
    repo, branch = parse_repo(body.repo), None
    email = body.email.strip()
    ip_hash = hashlib.sha256((request.headers.get("x-forwarded-for", request.client.host if request.client else "")
                              .split(",")[0].strip() + WORKER_TOKEN[:8]).encode()).hexdigest()[:16]
    if c.execute("SELECT count(*) AS n FROM checks WHERE lower(email) = lower(%s) AND status IN ('awaiting_verification','queued','running')",
                 (email,)).fetchone()["n"] >= MAX_OPEN_PER_EMAIL:
        raise HTTPException(429, "You already have checks in progress. We'll email you when they finish.")
    if c.execute("SELECT count(*) AS n FROM checks WHERE ip_hash = %s AND created_at > now() - interval '1 day'",
                 (ip_hash,)).fetchone()["n"] >= MAX_PER_IP_PER_DAY:
        raise HTTPException(429, "Too many requests today. Email manraj@patchlabs.dev and we'll help.")
    try:
        r = httpx.get(f"{GITHUB_API}/repos/{repo}", timeout=10, headers={"Accept": "application/vnd.github+json"})
        if r.status_code == 404:
            raise HTTPException(422, "We couldn't find that repo. Check the name, and that it's public on GitHub.")
        if r.status_code == 200:
            repo, branch = r.json().get("full_name", repo), r.json().get("default_branch")
    except httpx.HTTPError:
        pass  # GitHub unreachable or rate-limited: verification will catch a bad repo
    cid, code = uuid.uuid4(), "patchlabs-" + secrets.token_hex(8)
    c.execute("INSERT INTO checks (id, email, repo, verify_code, ip_hash, branch) VALUES (%s, %s, %s, %s, %s, %s)",
              (cid, email, repo, code, ip_hash, branch))
    event(c, cid, "requested", repo)
    link = f"{SITE_URL}/check.html?id={cid}"
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
    return public_view(row, events)


@app.post("/checks/{cid}/verify")
def verify_check(cid: str, c=Depends(db)):
    row = load(c, cid)
    if row["status"] != "awaiting_verification":
        return {"status": row["status"]}
    try:
        # The contents API is always fresh; raw.githubusercontent.com serves a branch's old content for minutes.
        # Fall back to raw only when the unauthenticated API limit (60 an hour) is used up.
        r = httpx.get(f"{GITHUB_API}/repos/{row['repo']}/contents/{VERIFY_FILE}", timeout=10,
                      headers={"Accept": "application/vnd.github.raw"})
        if r.status_code in (403, 429):
            r = httpx.get(f"{RAW_GITHUB}/{row['repo']}/{row['branch'] or 'HEAD'}/{VERIFY_FILE}", timeout=10, follow_redirects=True)
        found = r.status_code == 200 and row["verify_code"] in r.text
    except httpx.HTTPError:
        raise HTTPException(503, "We couldn't reach GitHub. Try again in a minute.")
    if not found:
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
    if body.status != "failed":
        headline = {"done": "we found leaks and a tested fix is ready", "needs_review": "we found leaks; a person is reviewing the fix",
                    "no_leaks": "we found no data leaks"}[body.status]
        notify(c, cid, row["email"], f"Your PatchLabs leak check for {row['repo']} is ready",
               f"Your check of {row['repo']} has finished: {headline}.\n\nSee the report and the fix here:\n"
               f"{SITE_URL}/check.html?id={cid}\n\nPatchLabs")
    return {"ok": True}


@app.get("/admin/checks", dependencies=[Depends(bearer(ADMIN_TOKEN))])
def admin_checks(c=Depends(db)):
    rows = c.execute("SELECT id, created_at, email, repo, status, verified_at, finished_at, cost_usd, summary FROM checks "
                     "ORDER BY created_at DESC LIMIT 200").fetchall()
    return {"checks": rows}
