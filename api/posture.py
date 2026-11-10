"""Live posture (LIVE.md): passive checks of a domain the app's team verified, plus the free headers tool.

One check = one plain http:// request to the home page (does it redirect to https?), one https:// load of the home page
(at most 5 redirects) and the TLS handshake of that load. Nothing else is requested: no other paths, forms or APIs.
Every hop is resolved and checked against core.ip_allowed, then pinned to the checked address (no DNS rebinding), the
same way webhooks are sent. Findings PL-027..PL-036, line "live".
"""
import html, re, secrets, socket, ssl, threading, time, uuid
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field

import alerts, audit, core, monitor, taxonomy
from core import SITE_URL, current_user, db, ip_hash, mail, pool

router = APIRouter()

UA = "PatchLabs-LivePosture/1 (+https://patchlabs.dev/product/live-posture)"
TIMEOUT, MAX_BODY, MAX_REDIRECTS = 8, 1_000_000, 5
VERIFY_FILE = "patchlabs-verify.txt"
RECHECK_GAP = "10 minutes"
TOOL_PER_IP_PER_HOUR = 10
EXPIRY_WARN_DAYS = 21
HSTS_MIN = 180 * 86400
# TLDs on the browsers' HSTS preload list: every site on them is HTTPS-only before the first request.
PRELOADED_TLDS = {"app", "dev", "page", "new", "day", "foo", "bank", "insurance", "how", "soy", "boo", "channel", "esq", "meme",
                  "mov", "nexus", "phd", "prof", "rsvp", "zip", "ing", "search", "youtube", "google", "chrome", "gle"}
SEVERITIES = ("critical", "high", "medium", "low", "info")
PENALTY = {"high": 30, "medium": 15, "low": 5}
SHOWN_HEADERS = ("strict-transport-security", "content-security-policy", "content-security-policy-report-only", "x-frame-options",
                 "x-content-type-options", "referrer-policy", "permissions-policy", "server", "x-powered-by")

CHECKS = {  # id: (title when it fails, title when it passes, fix)
    "PL-027": ("Site doesn't force HTTPS", "HTTPS is forced",
               "Redirect every http:// request to https:// with a 301 or 308 (most hosts have a setting for it)."),
    "PL-028": ("TLS certificate is invalid, expired or about to expire", "TLS certificate is valid",
               "Renew the certificate, or turn on automatic renewal at your host or CDN."),
    "PL-029": ("No HSTS header, or max-age under 180 days", "HSTS is on",
               "Send Strict-Transport-Security: max-age=63072000; includeSubDomains"),
    "PL-030": ("No Content-Security-Policy", "Content-Security-Policy is set",
               "Send a Content-Security-Policy that lists where scripts may load from (start with default-src 'self')."),
    "PL-031": ("Any site can frame the page", "Framing is restricted",
               "Send Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: DENY)."),
    "PL-032": ("No X-Content-Type-Options: nosniff", "X-Content-Type-Options is nosniff",
               "Send X-Content-Type-Options: nosniff"),
    "PL-033": ("Cookie set without Secure, or a session cookie without HttpOnly", "Cookies carry Secure (and HttpOnly on sessions)",
               "Set cookies with Secure and SameSite=Lax; add HttpOnly to session cookies."),
    "PL-034": ("Page loads scripts or styles over plain HTTP", "No scripts or styles over plain HTTP",
               "Load every script and stylesheet over https://."),
    "PL-035": ("Server headers reveal software versions", "No software versions in headers",
               "Remove version numbers from the Server and X-Powered-By headers."),
    "PL-036": ("No Referrer-Policy", "Referrer-Policy is set",
               "Send Referrer-Policy: strict-origin-when-cross-origin"),
}


class Unreachable(Exception):
    """The page couldn't be loaded; the message is a sentence for the user."""


# ---- URLs and fetching ---------------------------------------------------------------------------------------------

def origin(text, schemes=("https",)):
    """'example.com', 'https://example.com/x?y' → 'https://example.com'. Raises ValueError with a sentence."""
    t = (text or "").strip()
    if not t:
        raise ValueError("Enter your app's address, for example https://app.example.com")
    if "://" not in t:
        t = "https://" + t
    try:
        u = urlsplit(t)
        port = u.port
    except ValueError:
        raise ValueError("That address isn't valid.")
    host = (u.hostname or "").rstrip(".").lower()
    if u.scheme not in schemes:
        raise ValueError("Use an https:// address." if schemes == ("https",) else "Use an http:// or https:// address.")
    if u.username or u.password or (port and port not in (80, 443)):
        raise ValueError("Use the plain address of the site, without a login or port.")
    if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}", host or "-"):
        raise ValueError("Use a domain name such as app.example.com (IP addresses and local names aren't allowed).")
    if host.rsplit(".", 1)[-1] in ("local", "localhost", "internal", "test", "invalid", "example", "lan", "home", "corp"):
        raise ValueError("That's a private name. Use your app's public address.")
    return f"https://{host}"


def resolve(host, port):
    try:
        ips = [i[4][0] for i in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]
    except (socket.gaierror, UnicodeError, OSError):
        raise Unreachable(f"We couldn't find {host}. Check the address.")
    if not ips or not all(core.ip_allowed(ip) for ip in ips):
        raise Unreachable(f"{host} points to a private address, so we won't load it.")
    return ips[0]


def fetch(url, verify=True):
    """One GET without following redirects, pinned to the checked address. Returns {status, headers, cookies, body, tls}."""
    u = urlsplit(url)
    ip = resolve(u.hostname, u.port or (443 if u.scheme == "https" else 80))
    netloc = (f"[{ip}]" if ":" in ip else ip) + (f":{u.port}" if u.port else "")
    headers = {"Host": u.netloc, "User-Agent": UA, "Accept": "text/html,*/*;q=0.5", "Accept-Encoding": "gzip, deflate"}
    try:
        with httpx.Client(timeout=TIMEOUT, follow_redirects=False, trust_env=False, verify=verify) as cl:
            with cl.stream("GET", u._replace(netloc=netloc).geturl(), headers=headers,
                           extensions={"sni_hostname": u.hostname} if u.scheme == "https" else {}) as r:
                tls = None
                if u.scheme == "https":
                    so = r.extensions["network_stream"].get_extra_info("ssl_object")
                    tls = {"version": so.version(), "cert": so.getpeercert() if verify else None}
                body = b""
                for chunk in r.iter_bytes():
                    body += chunk
                    if len(body) >= MAX_BODY:
                        break
                return {"status": r.status_code, "headers": {k.lower(): v for k, v in r.headers.items()},
                        "cookies": r.headers.get_list("set-cookie"), "body": body[:MAX_BODY].decode(r.encoding or "utf-8", "replace"),
                        "tls": tls}
    except httpx.ConnectError as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e) or isinstance(e.__context__, ssl.SSLCertVerificationError):
            raise CertError(cert_reason(e))
        raise Unreachable(f"We couldn't connect to {u.hostname}.")
    except httpx.TimeoutException:
        raise Unreachable(f"{u.hostname} didn't answer within {TIMEOUT} seconds.")
    except httpx.HTTPError:
        raise Unreachable(f"We couldn't load {u.hostname}.")


class CertError(Exception):
    pass


def cert_reason(e):
    s = str(e)
    for needle, reason in (("expired", "The certificate has expired."), ("Hostname mismatch", "The certificate is for a different name."),
                           ("self-signed", "The certificate is self-signed."), ("self signed", "The certificate is self-signed."),
                           ("unable to get local issuer", "The certificate isn't signed by a trusted authority.")):
        if needle in s:
            return reason
    return "Browsers won't trust the certificate."


def load(url, verify=True):
    """Follows up to MAX_REDIRECTS redirects, checking every hop. Returns (final response, list of URLs visited)."""
    seen = [url]
    for _ in range(MAX_REDIRECTS + 1):
        r = fetch(url, verify)
        loc = r["headers"].get("location")
        if r["status"] not in (301, 302, 303, 307, 308) or not loc:
            return r, seen
        url = urljoin(url, loc)
        if urlsplit(url).scheme not in ("http", "https"):
            raise Unreachable("The page redirects somewhere we can't follow.")
        seen.append(url)
    raise Unreachable(f"The page redirects more than {MAX_REDIRECTS} times.")


# ---- analysis ------------------------------------------------------------------------------------------------------

def _cert_name(parts, key):
    return next((v for rdn in parts or () for k, v in rdn if k == key), None)


def tls_facts(tls, now=None):
    cert = (tls or {}).get("cert") or {}
    if not cert.get("notAfter"):
        return {"version": (tls or {}).get("version"), "issuer": None, "expires": None, "days_left": None}
    exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    return {"version": tls.get("version"), "issuer": _cert_name(cert.get("issuer"), "organizationName") or _cert_name(cert.get("issuer"), "commonName"),
            "expires": exp.date().isoformat(), "days_left": (exp - (now or datetime.now(timezone.utc))).days}


def parse_cookie(raw):
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {p.split("=", 1)[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else True) for p in parts[1:] if p}
    return {"name": name[:100], "secure": "secure" in attrs, "httponly": "httponly" in attrs,
            "samesite": str(attrs["samesite"]).title() if isinstance(attrs.get("samesite"), str) else None}


SESSION_NAME = re.compile(r"sess|auth|token|sid|jwt|login|remember", re.I)
META = r"<meta\b[^>]*\b{attr}\s*=\s*[\"']?{value}(?=[\"'\s/>])[^>]*>"


def meta_tag(body, attr, value):
    m = re.search(META.format(attr=attr, value=re.escape(value)), body or "", re.I)
    if not m:
        return None
    c = re.search(r"\bcontent\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", m.group(0), re.I)
    return html.unescape(c.group(1).strip("\"'")) if c else ""


def hsts_age(value):
    m = re.search(r"max-age\s*=\s*\"?(\d+)", value or "", re.I)
    return int(m.group(1)) if m else None


def analyze(page_url, r, http_info, cert_problem=None, now=None):
    """Turns one load into findings. r: the final https response; http_info: {"redirects": bool|None, "final": url}."""
    h, body, host = r["headers"], r["body"], urlsplit(page_url).hostname or ""
    preloaded = host.rsplit(".", 1)[-1] in PRELOADED_TLDS
    tls = tls_facts(r.get("tls"), now)
    found = []

    def fail(fid, evidence, severity, obj=None):
        found.append({"id": fid, "line": "live", "severity": severity, "title": CHECKS[fid][0], "object": obj or page_url,
                      "evidence": evidence[:300], "fix": CHECKS[fid][2], **taxonomy.tags(fid)})

    final = r.get("url") or page_url
    if urlsplit(final).scheme != "https":
        fail("PL-027", "Loading the site over https:// ends up on a plain http:// page.", "medium")
    elif http_info.get("redirects") is False and not preloaded:
        fail("PL-027", f"http://{host}/ answers without redirecting to https://.", "medium")
    if cert_problem:
        fail("PL-028", cert_problem, "high")
    elif tls["days_left"] is not None and tls["days_left"] < 0:
        fail("PL-028", f"The certificate expired on {tls['expires']}.", "high")
    elif tls["days_left"] is not None and tls["days_left"] < EXPIRY_WARN_DAYS:
        fail("PL-028", f"The certificate expires on {tls['expires']} ({tls['days_left']} days).", "medium")
    age = hsts_age(h.get("strict-transport-security"))
    if not preloaded and (age is None or age < HSTS_MIN):
        fail("PL-029", "No Strict-Transport-Security header." if age is None else
             f"Strict-Transport-Security max-age is {age} seconds (under 180 days).", "low")
    csp = h.get("content-security-policy") or ""
    meta_csp = meta_tag(body, "http-equiv", "Content-Security-Policy")
    if not csp.strip() and not (meta_csp or "").strip():
        fail("PL-030", "The page sends no Content-Security-Policy header or meta tag" +
             (" (only a Report-Only policy, which blocks nothing)." if h.get("content-security-policy-report-only") else "."), "medium")
    xfo = (h.get("x-frame-options") or "").strip().upper()
    if "frame-ancestors" not in csp.lower() and xfo not in ("DENY", "SAMEORIGIN"):
        fail("PL-031", "No frame-ancestors in the Content-Security-Policy header and no X-Frame-Options.", "low")
    if (h.get("x-content-type-options") or "").strip().lower() != "nosniff":
        fail("PL-032", "X-Content-Type-Options is missing or isn't nosniff.", "low")
    cookies = [parse_cookie(c) for c in r.get("cookies") or []][:20]
    for ck in cookies:
        # SameSite isn't required: browsers treat a cookie without it as Lax
        missing = [a for a, ok in (("Secure", ck["secure"]), ("HttpOnly", ck["httponly"] or not SESSION_NAME.search(ck["name"]))) if not ok]
        if missing and sum(f["id"] == "PL-033" for f in found) < 5:
            fail("PL-033", f"Cookie {ck['name']} is set without {', '.join(missing)}.", "medium", obj=f"cookie {ck['name']}")
    insecure = re.findall(r"<script\b[^>]*\bsrc\s*=\s*[\"']?(http://[^\"'\s>]+)", body, re.I) + \
        [m for tag in re.findall(r"<link\b[^>]*>", body, re.I) if re.search(r"stylesheet", tag, re.I)
         for m in re.findall(r"\bhref\s*=\s*[\"']?(http://[^\"'\s>]+)", tag, re.I)]
    if insecure:
        fail("PL-034", "Loaded over plain HTTP: " + ", ".join(dict.fromkeys(insecure[:3])), "medium")
    leaky = [f"{k}: {h[k]}" for k in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")
             if h.get(k) and re.search(r"\d+\.\d+", h[k])]
    if leaky:
        fail("PL-035", "; ".join(leaky), "info")
    if not (h.get("referrer-policy") or "").strip() and meta_tag(body, "name", "referrer") is None:
        fail("PL-036", "No Referrer-Policy header or meta tag.", "info")

    failed = {f["id"] for f in found}
    counts = {s: sum(f["severity"] == s for f in found) for s in SEVERITIES}
    # each check costs points once, however many cookies it caught
    score = max(0, 100 - sum(PENALTY.get(f["severity"], 0) for f in {f["id"]: f for f in found}.values()))
    grade = "F" if any(f["id"] == "PL-028" and f["severity"] == "high" for f in found) else \
        next(g for g, floor in (("A", 90), ("B", 75), ("C", 60), ("D", 40), ("F", 0)) if score >= floor)
    found.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["id"]))
    return {"url": page_url, "final_url": final, "grade": grade, "score": score, "counts": counts, "findings": found,
            "passed": [{"id": fid, "title": t[1]} for fid, t in CHECKS.items() if fid not in failed],
            "facts": {"status": r["status"], "redirects": http_info.get("seen") or [final], "https_redirect": http_info.get("redirects"),
                      "https_preloaded_tld": preloaded, "tls": tls,
                      "headers": {k: (h[k][:300] if h.get(k) else None) for k in SHOWN_HEADERS}, "cookies": cookies,
                      "server": (h.get("server") or None) and h["server"][:100]}}


def inspect(site):
    """Runs the whole check on an origin from origin(). Raises Unreachable when the https page can't be loaded."""
    host = urlsplit(site).hostname
    try:
        hr = fetch(f"http://{host}/")
        loc = hr["headers"].get("location") or ""
        redirects = hr["status"] in (301, 302, 303, 307, 308) and urljoin(f"http://{host}/", loc).startswith("https://")
    except Unreachable:
        redirects = None  # nothing listens on plain http: nothing to downgrade to
    except CertError:
        redirects = True
    cert_problem = None
    try:
        r, seen = load(site + "/")
    except CertError as e:
        cert_problem = str(e)
        r, seen = load(site + "/", verify=False)  # still read the headers, as a browser would after the warning
    r["url"] = seen[-1]
    out = analyze(site, r, {"redirects": redirects, "seen": seen}, cert_problem)
    out["checked_at"] = datetime.now(timezone.utc)
    return out


def has_code(site, code):
    """The verification file's whole content is the code, or the home page carries the meta tag. Redirects must stay
    on the same host (or its www twin), so a redirect elsewhere can't vouch for this domain."""
    host = urlsplit(site).hostname
    same = {host, host[4:] if host.startswith("www.") else "www." + host}

    def get(path):
        try:
            r, seen = load(site + path)
        except (Unreachable, CertError):
            return None
        return r if all(urlsplit(u).hostname in same for u in seen) and r["status"] == 200 else None

    f = get("/" + VERIFY_FILE)
    if f and f["body"].strip() == code:
        return True
    page = get("/")
    return bool(page and meta_tag(page["body"], "name", "patchlabs-verify") == code)


# ---- storage, views and alerts -------------------------------------------------------------------------------------

def verify_view(a):
    code = a["live_code"]
    return {"file": VERIFY_FILE, "file_url": f"{a['live_url']}/{VERIFY_FILE}", "code": code,
            "meta": f'<meta name="patchlabs-verify" content="{code}">'}


def short(p):
    return {k: p.get(k) for k in ("grade", "score", "checked_at", "counts")}


def result_of(row):
    return {**row["result"], "id": row["id"], "trigger": row["trigger"], "checked_at": row["created_at"]}


def latest(c, aid, n=1):
    return [result_of(r) for r in c.execute("SELECT * FROM posture_checks WHERE app_id = %s ORDER BY created_at DESC LIMIT %s",
                                            (aid, n)).fetchall()]


def live_view(c, a, full=True):
    if not a.get("live_url"):
        return {"url": None, "verified": False, "verified_at": None, "next_check_at": None, "verify": None, "last": None}
    last = latest(c, a["id"])
    last = (last[0] if full else short(last[0])) if last else None
    return {"url": a["live_url"], "verified": a["live_verified_at"] is not None, "verified_at": a["live_verified_at"],
            "next_check_at": a["live_next_at"], "verify": None if a["live_verified_at"] else verify_view(a), "last": last}


def store(c, a, result, trigger):
    pid = uuid.uuid4()
    body = {k: v for k, v in result.items() if k != "checked_at"}
    row = c.execute("INSERT INTO posture_checks (id, app_id, url, grade, score, result, trigger) VALUES (%s, %s, %s, %s, %s, %s, %s) "
                    "RETURNING *", (pid, a["id"], result["url"], result["grade"], result["score"], Jsonb(_jsonable(body)), trigger)).fetchone()
    return result_of(row)


def _jsonable(x):
    if isinstance(x, dict):
        return {k: _jsonable(v) for k, v in x.items()}
    if isinstance(x, list):
        return [_jsonable(v) for v in x]
    return x.isoformat() if isinstance(x, datetime) else x


GRADES = "ABCDF"


def changes(prev, cur):
    """(grade dropped, new findings) between two results; nothing on the first result."""
    if not prev:
        return False, []
    before = {taxonomy.key(f) for f in prev.get("findings") or []}
    return (GRADES.index(cur["grade"]) > GRADES.index(prev["grade"]),
            [f for f in cur["findings"] if taxonomy.key(f) not in before])


def alert(c, a, prev, cur):
    dropped, new = changes(prev, cur)
    if not dropped and not new:
        return False
    name = monitor.app_target(a)["label"]
    app_url = f"{SITE_URL}/app/app?id={a['id']}#live"
    headline = (f"live posture dropped from {prev['grade']} to {cur['grade']}" if dropped else f"live posture is {cur['grade']}") + \
        (f", {len(new)} new finding{'s' if len(new) != 1 else ''}" if new else "")
    lines = [f"PatchLabs re-checked {a['live_url']} for {name}: {headline}."]
    lines += [f"{f['id']} ({f['severity']}): {f['title']}. {f['evidence']}\nFix: {f['fix']}" for f in new[:10]]
    lines += [f"See the details:\n{app_url}", "PatchLabs"]
    for email in monitor.recipients(c, a["workspace_id"], a["id"]):
        mail(email, f"Live posture changed for {name}", "\n\n".join(lines))
    w = c.execute("SELECT id, webhook_url, webhook_secret, webhook_format FROM workspaces WHERE id = %s", (a["workspace_id"],)).fetchone()
    if w and w["webhook_url"]:
        payload = {"event": "posture.changed", "text": f"PatchLabs: {name}: {headline}. {app_url}",
                   "posture": {"app_id": str(a["id"]), "url": a["live_url"], "grade": cur["grade"], "previous_grade": prev["grade"],
                               "score": cur["score"], "counts": cur["counts"], "new_findings": [f["id"] for f in new], "app_url": app_url}}
        message = {"title": f"PatchLabs: {name}", "headline": headline[:1].upper() + headline[1:] + ".", "status": "posture",
                   "counts": cur["counts"], "tables_leaking": [], "new_leaks": [], "fixed": [], "suppressed": [],
                   "findings": [{"id": f["id"], "severity": f["severity"], "title": f["title"], "object": f["object"]} for f in new[:5]],
                   "url": app_url, "app_url": app_url, "link_text": "Open live posture"}
        try:
            alerts.deliver(c, w, payload, message)
        except Exception as e:  # a broken webhook must never lose the check
            print(f"posture webhook for {a['id']} failed: {e!r}", flush=True)
    return True


def run(c, a, trigger, user=None):
    """Checks the app's verified domain, stores the result, alerts on a drop. Unreachable sites are stored as nothing
    and raise, so a flaky host never pages anyone."""
    prev = latest(c, a["id"])
    cur = store(c, a, inspect(a["live_url"]), trigger)
    alert(c, a, prev[0] if prev else None, cur)
    audit.log(c, a["workspace_id"], "posture.checked", user, kind="user" if user else "system",
              target=monitor.app_target(a), detail={"url": a["live_url"], "grade": cur["grade"], "trigger": trigger})
    return cur


NEXT_DAY = "now() + interval '1 day'"


def run_due(limit=5):
    """Re-checks verified domains whose day is up (apps with re-checks off are skipped). Each app is claimed in its own
    transaction (SKIP LOCKED, next time moved on first), so several API replicas never double-check one domain."""
    with pool.connection() as c:
        due = c.execute(f"UPDATE apps SET live_next_at = {NEXT_DAY} WHERE id IN (SELECT id FROM apps WHERE live_verified_at IS NOT NULL "
                        "AND schedule <> 'off' AND live_next_at <= now() ORDER BY live_next_at LIMIT %s FOR UPDATE SKIP LOCKED) "
                        "RETURNING *", (limit,)).fetchall()
    done = 0
    for a in due:
        try:
            with pool.connection() as c:
                run(c, a, "scheduled")
            done += 1
        except Unreachable as e:
            print(f"posture re-check of {a['live_url']} skipped: {e}", flush=True)
        except Exception as e:
            print(f"posture re-check of {a['live_url']} failed: {e!r}", flush=True)
    return done


_stop = threading.Event()


def start_loop(every):
    def loop():
        while not _stop.wait(every):
            try:
                run_due()
            except Exception as e:
                print(f"posture loop: {e!r}", flush=True)
    _stop.clear()
    threading.Thread(target=loop, name="posture", daemon=True).start()


def stop_loop():
    _stop.set()


# ---- routes ----------------------------------------------------------------------------------------------------------

class LiveUrl(BaseModel):
    url: str = Field(max_length=300)


def bad_url(e):
    return HTTPException(422, str(e))


@router.put("/apps/{aid}/live")
def set_live(aid: str, body: LiveUrl, user=Depends(current_user), c=Depends(db)):
    a = monitor.app_for(c, user, aid, "manage")
    try:
        site = origin(body.url)
    except ValueError as e:
        raise bad_url(e)
    if site != a["live_url"]:
        c.execute("DELETE FROM posture_checks WHERE app_id = %s", (a["id"],))
        a = c.execute("UPDATE apps SET live_url = %s, live_code = %s, live_verified_at = NULL, live_next_at = NULL WHERE id = %s RETURNING *",
                      (site, "patchlabs-live-" + secrets.token_hex(8), a["id"])).fetchone()
        audit.log(c, a["workspace_id"], "app.live_set", user, target=monitor.app_target(a), detail={"url": site})
    return live_view(c, a)


@router.delete("/apps/{aid}/live")
def remove_live(aid: str, user=Depends(current_user), c=Depends(db)):
    a = monitor.app_for(c, user, aid, "manage")
    if a["live_url"]:
        c.execute("DELETE FROM posture_checks WHERE app_id = %s", (a["id"],))
        c.execute("UPDATE apps SET live_url = NULL, live_code = NULL, live_verified_at = NULL, live_next_at = NULL WHERE id = %s", (a["id"],))
        audit.log(c, a["workspace_id"], "app.live_removed", user, target=monitor.app_target(a), detail={"url": a["live_url"]})
    return {"ok": True}


@router.post("/apps/{aid}/live/verify")
def verify_live(aid: str, user=Depends(current_user), c=Depends(db)):
    a = monitor.app_for(c, user, aid, "manage")
    if not a["live_url"]:
        raise HTTPException(409, "Add your app's address first.")
    if a["live_verified_at"]:
        return {"verified": True, "posture": (latest(c, a["id"]) or [None])[0]}
    try:
        ok = has_code(a["live_url"], a["live_code"])
    except Unreachable as e:
        raise HTTPException(409, str(e))
    if not ok:
        raise HTTPException(409, f"We couldn't find your code at {a['live_url']}/{VERIFY_FILE} or in a patchlabs-verify meta tag on "
                                 "the home page yet. Publish the change, then try again.")
    a = c.execute(f"UPDATE apps SET live_verified_at = now(), live_next_at = {NEXT_DAY} WHERE id = %s RETURNING *", (a["id"],)).fetchone()
    audit.log(c, a["workspace_id"], "app.live_verified", user, target=monitor.app_target(a), detail={"url": a["live_url"]})
    try:
        return {"verified": True, "posture": run(c, a, "verify", user)}
    except Unreachable as e:
        return {"verified": True, "posture": None, "detail": f"Verified. The first check couldn't load the page: {e}"}


@router.post("/apps/{aid}/live/checks", status_code=201)
def recheck_live(aid: str, user=Depends(current_user), c=Depends(db)):
    a = monitor.app_for(c, user, aid, "run")
    c.execute("SELECT id FROM apps WHERE id = %s FOR UPDATE", (a["id"],))
    if not a["live_verified_at"]:
        raise HTTPException(409, "Verify the domain before checking it.")
    if c.execute(f"SELECT 1 FROM posture_checks WHERE app_id = %s AND created_at > now() - interval '{RECHECK_GAP}'", (a["id"],)).fetchone():
        raise HTTPException(429, "This domain was checked in the last 10 minutes. Try again shortly.")
    try:
        return run(c, a, "manual", user)
    except Unreachable as e:
        raise HTTPException(502, str(e))


@router.get("/apps/{aid}/live/checks")
def live_history(aid: str, user=Depends(current_user), c=Depends(db)):
    a = monitor.app_for(c, user, aid)
    return {"checks": [{"id": r["id"], "grade": r["grade"], "score": r["score"], "counts": r["result"].get("counts"),
                        "trigger": r["trigger"], "checked_at": r["created_at"]}
                       for r in c.execute("SELECT * FROM posture_checks WHERE app_id = %s ORDER BY created_at DESC LIMIT 30",
                                          (a["id"],)).fetchall()]}


GRADE_COLOURS = {"A": "#2ea44f", "B": "#4c9a2a", "C": "#dfb317", "D": "#e16f24", "F": "#d1242f"}


def public_live(c, aid):
    try:
        aid = uuid.UUID(aid)
    except ValueError:
        return None
    a = c.execute("SELECT id FROM apps WHERE id = %s AND badge_public AND live_verified_at IS NOT NULL", (aid,)).fetchone()
    last = latest(c, a["id"]) if a else []
    return {"grade": last[0]["grade"], "checked_at": last[0]["checked_at"]} if last else None


@router.get("/badge/{aid}/live.svg")
def live_badge(aid: str, c=Depends(db)):
    p = public_live(c, aid)
    message, colour = (f"{p['grade']} · {p['checked_at'].day} {p['checked_at']:%b %Y}", GRADE_COLOURS[p["grade"]]) if p else ("private", "#9f9f9f")
    return Response(monitor.svg_badge("live posture", message, colour), media_type="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=3600"})


class HeadersCheck(BaseModel):
    url: str = Field(max_length=300)


@router.post("/tools/headers-check")
def headers_check(body: HeadersCheck, request: Request, c=Depends(db)):
    try:
        site = origin(body.url, schemes=("https", "http"))
    except ValueError as e:
        raise bad_url(e)
    iph = ip_hash(request)
    if c.execute("SELECT count(*) AS n FROM tool_runs WHERE tool = 'headers-check' AND ip_hash = %s AND created_at > now() - interval '1 hour'",
                 (iph,)).fetchone()["n"] >= TOOL_PER_IP_PER_HOUR:
        raise HTTPException(429, f"That's {TOOL_PER_IP_PER_HOUR} checks this hour from your network. Try again later.")
    c.execute("INSERT INTO tool_runs (tool, ip_hash, repo) VALUES ('headers-check', %s, %s)", (iph, urlsplit(site).hostname))
    c.commit()  # count the attempt even if loading the page fails
    try:
        return inspect(site)
    except Unreachable as e:
        raise HTTPException(502, str(e))
