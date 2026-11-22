"""GENERATED from api/posture.py by actor/sync_posture.py. Do not edit by hand; edit api/posture.py and re-run the sync.

Pure headers/TLS/cookie analysis, the same logic as the free PatchLabs headers check, with core.ip_allowed and
taxonomy.tags inlined so the Actor has no database or server dependencies.
"""
import html, ipaddress, re, socket, ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import httpx

UA = "PatchLabs-ApifyActor/1 (+https://patchlabs.dev/tools/headers-check)"
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
    "PL-040": ("Third-party scripts can send your visitors' data anywhere", "Scripts can only send data to listed sites",
               "Add connect-src and img-src to your Content-Security-Policy listing only the sites the page must talk to, so an "
               "injected or hijacked script can't send form data to its own server."),
}
# Script hosts with a public compromise in the last 90 days: (domain, note). Shown in PL-040 evidence and raises its
# severity; remove an entry 90 days after the incident.
SCRIPT_INCIDENTS = {"optimizely.com": "Optimizely's script CDN served injected card-skimming code to 178+ sites on 16 Nov 2026 (OPTIMJACK)"}
# Sources that let a script reach any server: a bare wildcard or a scheme on its own.
OPEN_SOURCES = {"*", "https:", "http:", "wss:", "ws:"}
TWO_PART_SUFFIX = {"co", "com", "org", "net", "ac", "gov", "edu"}




class core:  # stand-in for api/core.py
    BLOCKED_NETS = [ipaddress.ip_network(n) for n in (
        "::/96", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32",
        "100.64.0.0/10", "168.63.129.16/32", "169.254.169.254/32")]

    @staticmethod
    def ip_allowed(ip):
        ip = ipaddress.ip_address(ip.split("%")[0])
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if any(ip in n for n in core.BLOCKED_NETS):
            return False
        return ip.is_global and not ip.is_multicast


class taxonomy:  # stand-in for api/taxonomy.py (live-line findings only)
    TAGS = {
            "PL-027": (["CWE-319"], "A02:2021"),
            "PL-028": (["CWE-295"], "A02:2021"),
            "PL-029": (["CWE-319"], "A05:2021"),
            "PL-030": (["CWE-693"], "A05:2021"),
            "PL-031": (["CWE-1021"], "A05:2021"),
            "PL-032": (["CWE-693"], "A05:2021"),
            "PL-033": (["CWE-614", "CWE-1004"], "A05:2021"),
            "PL-034": (["CWE-319"], "A02:2021"),
            "PL-035": (["CWE-200"], "A05:2021"),
            "PL-036": (["CWE-200"], "A05:2021"),
            "PL-040": (["CWE-829"], "A08:2021"),
    }

    @staticmethod
    def tags(fid):
        cwe, owasp = taxonomy.TAGS.get(fid, ([], None))
        return {"cwe": list(cwe), "owasp": owasp}


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


def csp_directives(policy):
    """{'connect-src': ['https://api.x.com', ...], ...} for one policy string; the first of a repeated directive wins."""
    out = {}
    for part in (policy or "").split(";"):
        words = part.strip().split()
        if words and words[0].lower() not in out:
            out[words[0].lower()] = [w.lower() for w in words[1:]]
    return out


def limits_sends(policy):
    """True if this policy stops scripts sending to arbitrary servers through fetch/XHR/WebSocket/beacon (connect-src)
    and image requests (img-src). Navigation and form posts can still leave, so this narrows, it doesn't close."""
    d = csp_directives(policy)
    for name in ("connect-src", "img-src"):
        sources = d.get(name, d.get("default-src"))
        if sources is None or any(s in OPEN_SOURCES or s.startswith("*.") and s.count(".") < 2 for s in sources):
            return False
    return True


def site_of(host):
    """Rough registrable domain: shop.example.com -> example.com, a.b.co.uk -> b.co.uk."""
    parts = (host or "").lower().rstrip(".").split(".")
    n = 3 if len(parts) >= 3 and parts[-2] in TWO_PART_SUFFIX and len(parts[-1]) == 2 else 2
    return ".".join(parts[-n:])


def third_party_scripts(body, page_host):
    """Hosts of <script src> tags in the HTML that belong to another site (scripts added later at runtime aren't seen)."""
    hosts = []
    for src in re.findall(r"<script\b[^>]*\bsrc\s*=\s*[\"']?((?:https?:)?//[^\"'\s>]+)", body or "", re.I):
        host = urlsplit(src if not src.startswith("//") else "https:" + src).hostname or ""
        if host and site_of(host) != site_of(page_host) and host not in hosts:
            hosts.append(host)
    return hosts


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
    outside = third_party_scripts(body, host)
    if outside and not (limits_sends(csp) or limits_sends(meta_csp)):
        hit = [note for dom, note in SCRIPT_INCIDENTS.items() for x in outside if site_of(x) == dom][:1]
        shown = ", ".join(outside[:4]) + (f" and {len(outside) - 4} more" if len(outside) > 4 else "")
        fail("PL-040", f"The page runs scripts from {len(outside)} other site{'s' if len(outside) > 1 else ''} ({shown}) and no "
             "Content-Security-Policy connect-src and img-src limit where they can send data." + (f" Note: {hit[0]}." if hit else ""),
             "medium" if hit else "low")

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
