"""Looks for secret keys in the code a site ships to every visitor: the home page HTML and its same-site scripts.

Only what any signed-out browser downloads is read. Values are never returned: each hit is reported by type, the file
it was in, its first characters and its length, so the output is safe to store or share.
"""
import base64, json, re
from urllib.parse import urljoin, urlsplit

from . import posture
from .posture import CertError, Unreachable, fetch

posture.MAX_BODY = 5_000_000  # built JS bundles are often over the page limit of 1 MB

MAX_SCRIPTS = 20
SCRIPT_SRC = re.compile(r"<script\b[^>]*\bsrc\s*=\s*[\"']?([^\"'\s>]+)", re.I)
MODULE_PRELOAD = re.compile(r"<link\b[^>]*\brel\s*=\s*[\"']?modulepreload[^>]*\bhref\s*=\s*[\"']?([^\"'\s>]+)", re.I)
JWT = r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"

# (finding id, severity, name, pattern, what to do)
SECRETS = [
    ("PL-010", "critical", "Supabase service_role key", None,
     "This key skips every RLS policy. Rotate it in Supabase (Settings > API) now and move the code that needs it to a server or edge function."),
    ("PL-010", "critical", "Supabase secret key", re.compile(r"sb_secret_[A-Za-z0-9_-]{10,}"),
     "Rotate it in Supabase (Settings > API keys) and use it only on a server or edge function."),
    ("PL-009", "critical", "Stripe live secret key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{10,}"),
     "Roll the key in the Stripe dashboard and call Stripe from a server only."),
    ("PL-009", "critical", "OpenAI API key", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}"),
     "Revoke it at platform.openai.com and call OpenAI from a server or edge function."),
    ("PL-009", "critical", "Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
     "Revoke it in the Anthropic Console and call the API from a server."),
    ("PL-009", "critical", "AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
     "Deactivate it in AWS IAM and check CloudTrail for use you don't recognise."),
    ("PL-009", "critical", "GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}"),
     "Revoke it in GitHub settings."),
    ("PL-009", "high", "Resend API key", re.compile(r"\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}"),
     "Revoke it in Resend and send email from a server."),
    ("PL-009", "high", "SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"),
     "Revoke it in SendGrid and send email from a server."),
    ("PL-009", "high", "Twilio auth token or key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
     "Revoke it in the Twilio console."),
    ("PL-009", "critical", "private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "Treat the key as compromised: replace it and remove it from the front end."),
]
SUPABASE_URL = re.compile(r"https://([a-z0-9]{20})\.supabase\.co")


def jwt_role(token):
    try:
        part = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))).get("role")
    except (ValueError, IndexError, AttributeError):
        return None


def mask(value):
    return {"starts_with": value[:8] + "…", "length": len(value)}


def scan_text(text, where):
    """Returns (findings, facts) for one file's text."""
    found, anon = [], False
    for m in re.finditer(JWT, text):
        role = jwt_role(m.group(0))
        if role == "service_role":
            fid, sev, name, _, fix = SECRETS[0]
            found.append({"id": fid, "severity": sev, "title": f"{name} in code every visitor downloads", "object": where,
                          "evidence": mask(m.group(0)), "fix": fix})
        elif role == "anon":
            anon = True
    for fid, sev, name, rx, fix in SECRETS[1:]:
        for m in rx.finditer(text):
            found.append({"id": fid, "severity": sev, "title": f"{name} in code every visitor downloads", "object": where,
                          "evidence": mask(m.group(0)), "fix": fix})
    return found, {"supabase_projects": sorted(set(SUPABASE_URL.findall(text))), "supabase_anon_key": anon}


def script_urls(page_url, body):
    """Same-site script URLs from the page, in order, deduplicated."""
    host = urlsplit(page_url).hostname or ""
    site = ".".join(host.split(".")[-2:])
    out = []
    for src in SCRIPT_SRC.findall(body) + MODULE_PRELOAD.findall(body):
        u = urljoin(page_url, src)
        h = urlsplit(u).hostname or ""
        if urlsplit(u).scheme in ("http", "https") and (h == host or h.endswith("." + site)) and u not in out:
            out.append(u)
    return out[:MAX_SCRIPTS]


def scan(page_url, body):
    """Scans the page HTML and its same-site scripts. Returns {findings, scripts_read, scripts_failed, supabase}."""
    findings, projects, anon = [], set(), False
    f, facts = scan_text(body, page_url)
    findings += f
    projects |= set(facts["supabase_projects"])
    anon |= facts["supabase_anon_key"]
    read, failed = [], []
    for u in script_urls(page_url, body):
        try:
            r = fetch(u)
        except (Unreachable, CertError):
            failed.append(u)
            continue
        if r["status"] != 200:
            failed.append(u)
            continue
        read.append(u)
        f, facts = scan_text(r["body"], u)
        findings += f
        projects |= set(facts["supabase_projects"])
        anon |= facts["supabase_anon_key"]
    # one row per (type, value prefix): the same key often sits in several chunks
    seen, unique = set(), []
    for x in findings:
        k = (x["title"], x["evidence"]["starts_with"], x["evidence"]["length"])
        if k not in seen:
            seen.add(k)
            unique.append(x)
    return {"findings": unique, "scripts_read": read, "scripts_failed": failed,
            "supabase": {"projects": sorted(projects), "anon_key_in_page": anon,
                         "note": ("This app talks to Supabase from the browser. The anon key is meant to be public; whether data "
                                  "leaks depends on your RLS policies, which a page load can't see. Run the free RLS check on your "
                                  "repo: https://patchlabs.dev/check") if projects or anon else None}}
