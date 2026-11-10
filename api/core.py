"""Shared pieces for the PatchLabs API: config, database pool, email, GitHub lookups, auth, plans and webhooks."""
import hashlib, hmac, html, ipaddress, json, os, re, secrets, smtplib, socket, ssl, time, uuid
from email.message import EmailMessage
from urllib.parse import urlsplit

import httpx
from fastapi import Depends, Header, HTTPException
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

DATABASE_URL = os.environ["DATABASE_URL"]
WORKER_TOKEN = os.environ["WORKER_TOKEN"]
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
SITE_URL = os.environ.get("SITE_URL", "https://patchlabs.dev")
ORIGINS = os.environ.get("CORS_ORIGINS", "https://patchlabs.dev,https://www.patchlabs.dev").split(",")
GITHUB_API = os.environ.get("GITHUB_API", "https://api.github.com")
RAW_GITHUB = os.environ.get("RAW_GITHUB", "https://raw.githubusercontent.com")
FOUNDER_EMAIL = os.environ.get("FOUNDER_EMAIL", "manraj@patchlabs.dev")
AUTH_PER_IP_PER_HOUR = int(os.environ.get("AUTH_PER_IP_PER_HOUR", "30"))
VERIFY_FILE = "patchlabs-verify.txt"
EMAIL_RE = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
FINISHED = ("done", "no_leaks", "needs_review")

pool = ConnectionPool(DATABASE_URL, min_size=0, max_size=5, kwargs={"row_factory": dict_row}, open=False)


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


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def as_uuid(value, what="not found"):
    try:
        return uuid.UUID(str(value))
    except ValueError:
        raise HTTPException(404, what)


def client_ip(request):
    """The caller's address for rate limits: the rightmost X-Forwarded-For entry, which the Azure Container Apps ingress
    appends (everything to its left is whatever the client sent). Falls back to the socket peer."""
    xff = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    return xff[-1] if xff else (request.client.host if request.client else "")


def ip_hash(request):
    return hashlib.sha256((client_ip(request) + WORKER_TOKEN[:8]).encode()).hexdigest()[:16]


CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2066-\u2069]+")


def clean_text(s):
    """Names and labels: no control characters, newlines or bidi overrides; single spaces."""
    return re.sub(r" {2,}", " ", CONTROL.sub(" ", s or "")).strip()


def mask_email(email):
    local, _, domain = (email or "").partition("@")
    return f"{local[:1]}\u2022\u2022\u2022@{domain}"


LOCAL_PATH = re.compile(r"^(?:~/|[A-Za-z]:\\|/(?:Users|home|tmp|private|var|opt|root|srv|mnt|Volumes|workspace|app)/)")


def scrub(v):
    """Drops every cost field (admins only) and every local path such as run_dir (the worker's machine)."""
    if isinstance(v, dict):
        return {k: scrub(x) for k, x in v.items()
                if "cost" not in str(k).lower() and str(k).lower() != "run_dir" and not (isinstance(x, str) and LOCAL_PATH.match(x))}
    if isinstance(v, list):
        return [scrub(x) for x in v if not (isinstance(x, str) and LOCAL_PATH.match(x))]
    return v


def clean_report(md):
    """Older reports carry the model cost (", model cost $0.46"): costs are for admins only."""
    return re.sub(r",\s*model cost \$\s?[0-9]+(?:\.[0-9]+)?", "", md, flags=re.I) if md else md


def leaking(summary):
    t = summary.get("tables_leaking") if isinstance(summary, dict) else None
    return [str(x) for x in t] if isinstance(t, list) else []


# ---- email -------------------------------------------------------------------------------------------------------

def html_email(text):
    """Escapes everything; only a line that is exactly one of our own links (SITE_URL...) becomes a link, never user text."""
    own = re.compile(re.escape(SITE_URL.rstrip("/")) + r"(?:/[^\s<>\"'`\\]*)?")
    paras = []
    for p in text.strip().split("\n\n"):
        lines = []
        for line in p.split("\n"):
            e = html.escape(line.strip() if own.fullmatch(line.strip()) else line, quote=True)
            lines.append(f'<a href="{e}" style="color:#1c1917;font-weight:600">{e}</a>' if own.fullmatch(line.strip()) else e)
        paras.append(f'<p style="margin:0 0 16px">{"<br>".join(lines)}</p>')
    return ('<!doctype html><html><body style="margin:0;background:#f5f5f4;color:#1c1917;'
            'font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif">'
            '<div style="max-width:560px;margin:0 auto;padding:28px 16px">'
            '<div style="font-size:18px;font-weight:700;letter-spacing:-.01em;margin:0 0 16px">PatchLabs</div>'
            '<div style="background:#fff;border:1px solid #e7e5e4;border-radius:10px;padding:24px;font-size:15px;line-height:1.55">'
            f'{"".join(paras)}</div><div style="color:#78716c;font-size:12px;margin-top:16px">PatchLabs finds and fixes '
            f'personal-data leaks in AI-built apps. <a href="{SITE_URL}" style="color:#78716c">{SITE_URL.split("//")[-1]}</a></div>'
            '</div></body></html>')


def send_email(to, subject, body, html_body=None):
    """Writes to EMAIL_OUTBOX (tests) or sends through SMTP; returns False when neither is configured."""
    msg = EmailMessage()
    msg["From"] = os.environ.get("SMTP_FROM", "PatchLabs <manraj@patchlabs.dev>")
    msg["To"], msg["Subject"] = to, subject
    msg.set_content(body)
    msg.add_alternative(html_body or html_email(body), subtype="html")
    outbox = os.environ.get("EMAIL_OUTBOX")
    if outbox:
        with open(outbox, "a") as f:
            f.write(json.dumps({"to": to, "from": msg["From"], "subject": subject, "text": body,
                                "html": html_body or html_email(body), "content_type": msg.get_content_type()}) + "\n")
        return True
    host = os.environ.get("SMTP_HOST")
    if not host:
        return False
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


def mail(to, subject, body):
    try:
        return send_email(to, subject, body)
    except Exception as e:
        print(f"email to {to} failed: {e!r}", flush=True)
        return False


# ---- GitHub ------------------------------------------------------------------------------------------------------

REPO_RE = re.compile(r"^(?:https?://)?(?:www\.)?(?:github\.com/)?([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$")


def parse_repo(text):
    m = REPO_RE.match(text.strip())
    if not m:
        raise HTTPException(422, "Enter a GitHub repo, for example github.com/you/your-app")
    return f"{m.group(1)}/{m.group(2)}"


def repo_lookup(repo):
    """Returns (full_name, default_branch); 422 when GitHub says the repo doesn't exist."""
    branch = None
    try:
        r = httpx.get(f"{GITHUB_API}/repos/{repo}", timeout=10, headers={"Accept": "application/vnd.github+json"})
        if r.status_code == 404:
            raise HTTPException(422, "We couldn't find that repo. Check the name, and that it's public on GitHub.")
        if r.status_code == 200:
            repo, branch = r.json().get("full_name", repo), r.json().get("default_branch")
    except httpx.HTTPError:
        pass  # GitHub unreachable or rate-limited: verification will catch a bad repo
    return repo, branch


def repo_has_code(repo, branch, code):
    try:
        # The contents API is always fresh; raw.githubusercontent.com serves a branch's old content for minutes.
        # Fall back to raw only when the unauthenticated API limit (60 an hour) is used up.
        r = httpx.get(f"{GITHUB_API}/repos/{repo}/contents/{VERIFY_FILE}", timeout=10, headers={"Accept": "application/vnd.github.raw"})
        if r.status_code in (403, 429):
            r = httpx.get(f"{RAW_GITHUB}/{repo}/{branch or 'HEAD'}/{VERIFY_FILE}", timeout=10, follow_redirects=True)
        return r.status_code == 200 and r.text.strip() == code  # the whole file is the code: one repo can't vouch for many
    except httpx.HTTPError:
        raise HTTPException(503, "We couldn't reach GitHub. Try again in a minute.")


def verify_info(repo, branch, code):
    return {"file": VERIFY_FILE, "code": code,
            "add_url": f"https://github.com/{repo}/new/{branch or 'main'}?filename={VERIFY_FILE}&value={code}"}


# ---- auth --------------------------------------------------------------------------------------------------------

def current_user(authorization: str = Header(default=""), c=Depends(db)):
    tok = authorization[7:].strip() if authorization.startswith("Bearer ") else ""
    if not tok:
        raise HTTPException(401, "Sign in first.")
    u = c.execute("SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = %s AND s.revoked_at IS NULL "
                  "AND s.expires_at > now()", (token_hash(tok),)).fetchone()
    if not u:
        raise HTTPException(401, "Your session has expired. Sign in again.")
    return u


def api_key(x_api_key: str = Header(default=""), c=Depends(db)):
    if not x_api_key.startswith("pl_live_"):
        raise HTTPException(401, "Send your API key in the X-API-Key header.")
    k = c.execute("UPDATE api_keys SET last_used_at = now() WHERE key_hash = %s RETURNING id, workspace_id",
                  (token_hash(x_api_key),)).fetchone()
    if not k:
        raise HTTPException(401, "That API key is not valid or was revoked.")
    return k


def membership(c, user, wid, owner=False):
    w = c.execute("SELECT w.*, m.role FROM workspaces w JOIN workspace_members m ON m.workspace_id = w.id "
                  "WHERE w.id = %s AND m.user_id = %s", (as_uuid(wid, "Workspace not found."), user["id"])).fetchone()
    if not w:
        raise HTTPException(404, "Workspace not found.")
    if owner and w["role"] != "owner":
        raise HTTPException(403, "Only a workspace owner can do that.")
    return w


# ---- plans -------------------------------------------------------------------------------------------------------

ALL_SCHEDULES = ["off", "weekly", "monthly"]
PLANS = {"free": {"apps": 1, "runs_per_month": 4, "seats": 1, "schedules": ["off", "monthly"]},
         "maker": {"apps": 3, "runs_per_month": 30, "seats": 2, "schedules": ALL_SCHEDULES},
         "agency": {"apps": 10, "runs_per_month": 200, "seats": 10, "schedules": ALL_SCHEDULES},
         "enterprise": {"apps": 50, "runs_per_month": 1000, "seats": 50, "schedules": ALL_SCHEDULES}}
NEXT_AT = "CASE schedule WHEN 'weekly' THEN now() + interval '7 days' WHEN 'monthly' THEN now() + interval '30 days' END"


def limits(w):
    out = dict(PLANS.get(w["plan"], PLANS["free"]))
    for col, key in (("app_limit", "apps"), ("run_limit", "runs_per_month"), ("seat_limit", "seats")):
        if w.get(col) is not None:
            out[key] = w[col]
    return out


def usage(c, wid):
    return c.execute(
        "SELECT (SELECT count(*) FROM apps WHERE workspace_id = %(w)s) AS apps, "
        "(SELECT count(*) FROM usage_events WHERE kind = 'run' AND subject = %(s)s "
        " AND created_at >= date_trunc('month', now())) AS runs_this_month, "
        "(SELECT count(*) FROM workspace_members WHERE workspace_id = %(w)s) AS members", {"w": wid, "s": str(wid)}).fetchone()


def record(c, kind, subject):
    """Usage log for limits that must survive deletes (runs, invites, upgrade requests)."""
    c.execute("INSERT INTO usage_events (kind, subject) VALUES (%s, %s)", (kind, str(subject)))


def recent(c, kind, subject, interval="1 day"):
    return c.execute(f"SELECT count(*) AS n FROM usage_events WHERE kind = %s AND subject = %s AND created_at > now() - interval '{interval}'",
                     (kind, str(subject))).fetchone()["n"]


# ---- webhooks ----------------------------------------------------------------------------------------------------

WEBHOOK_SCHEMES = ("https",)
BLOCKED_NETS = [ipaddress.ip_network(n) for n in (
    "::/96", "64:ff9b::/96", "64:ff9b:1::/48",  # IPv4-compatible and NAT64: they reach IPv4 addresses
    "2002::/16", "2001::/32",                   # 6to4 and Teredo embed IPv4 addresses too
    "100.64.0.0/10", "168.63.129.16/32", "169.254.169.254/32")]  # carrier NAT, Azure host agent, cloud metadata


def ip_allowed(ip):
    ip = ipaddress.ip_address(ip.split("%")[0])
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if any(ip in n for n in BLOCKED_NETS):
        return False
    return ip.is_global and not ip.is_multicast


def webhook_target(url):
    """Checks a webhook URL and resolves it; returns (parts, ip). Raises ValueError with a human sentence."""
    try:
        u = urlsplit((url or "").strip())
        port = u.port
    except ValueError:
        raise ValueError("That webhook URL isn't valid.")
    if u.scheme not in WEBHOOK_SCHEMES or not u.hostname:
        raise ValueError("Webhook URLs must start with https://")
    try:
        infos = socket.getaddrinfo(u.hostname, port or (443 if u.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        raise ValueError("We couldn't find that webhook's host.")
    ips = [i[4][0] for i in infos]
    if not ips or not all(ip_allowed(ip) for ip in ips):
        raise ValueError("Webhook hosts must be public: private, loopback and link-local addresses are blocked.")
    return u, ips[0]


def new_webhook_secret():
    return "whsec_" + secrets.token_urlsafe(32)


def webhook_secret(c, w):
    """The workspace's signing secret, created on first use (for webhooks saved before signing existed)."""
    if w["webhook_secret"]:
        return w["webhook_secret"]
    return c.execute("UPDATE workspaces SET webhook_secret = coalesce(webhook_secret, %s) WHERE id = %s RETURNING webhook_secret",
                     (new_webhook_secret(), w["id"])).fetchone()["webhook_secret"]


def sign_webhook(secret, timestamp, body):
    return "v1=" + hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()


def send_webhook(url, payload, secret):
    """POSTs JSON to a checked URL, pinned to the address we checked (no DNS rebinding), signed with the workspace
    secret: X-PatchLabs-Signature = v1=<hex HMAC-SHA256 of "<timestamp>.<raw body>">. Returns the status code."""
    u, ip = webhook_target(url)
    host = f"[{ip}]" if ":" in ip else ip
    target = u._replace(netloc=host + (f":{u.port}" if u.port else "")).geturl()
    body, ts = json.dumps(payload, default=str).encode(), str(int(time.time()))
    headers = {"Host": u.netloc.rsplit("@", 1)[-1], "Content-Type": "application/json", "User-Agent": "PatchLabs-Webhook/1",
               "X-PatchLabs-Timestamp": ts, "X-PatchLabs-Signature": sign_webhook(secret, ts, body)}
    with httpx.Client(timeout=5, follow_redirects=False, trust_env=False) as cl:
        r = cl.post(target, content=body, headers=headers,
                    extensions={"sni_hostname": u.hostname} if u.scheme == "https" else {})
    return r.status_code
