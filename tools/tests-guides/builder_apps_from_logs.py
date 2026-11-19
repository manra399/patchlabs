#!/usr/bin/env python3
"""Find apps your staff publish on AI app builders, from your own DNS or proxy
logs, and see what a signed-out stranger gets from each one.

AI app builders (Grok, ChatGPT, Lovable, Base44, Replit, Bolt, v0 and others)
give every app its own hostname, such as four-random-words.grok.me. A hostname
is not a secret: every visit causes a DNS lookup, and passive DNS services log
those lookups. If the app's access setting is "Anyone with the link", anyone
who finds the name can open it.

Read-only. Uses only the Python standard library. Sends nothing anywhere except
one signed-out page load (plus up to 8 of the page's own scripts) to each app
found in your logs. Prints secret TYPES and email DOMAINS, never the values.

    python3 builder_apps_from_logs.py dns-export.csv proxy.log
    zcat resolver-*.log.gz | python3 builder_apps_from_logs.py -
    python3 builder_apps_from_logs.py --list-only logs/*.txt     # no requests
    python3 builder_apps_from_logs.py --org-domain yourfirm.com logs.txt

Any text works as input: resolver query logs, a firewall or secure web gateway
export, a browser-history CSV. Your logs also contain public apps that staff
merely visited, so check who owns an app before acting on it. Test only apps
you can tie to your organisation.

Guide: https://patchlabs.dev/learn/staff-vibe-coded-apps-client-data#ai-builders
"""
import argparse
import collections
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = "patchlabs-builder-apps/1.0"

# Hosting suffixes where an AI builder (or the host it deploys to) gives each
# app its own subdomain. Add your own with --suffix.
SUFFIXES = {
    "grok.me": "Grok app builder",
    "chatgpt.site": "ChatGPT app builder",
    "lovable.app": "Lovable",
    "lovableproject.com": "Lovable (preview)",
    "base44.app": "Base44",
    "replit.app": "Replit",
    "replit.dev": "Replit (dev URL)",
    "bolt.host": "Bolt",
    "vercel.app": "Vercel (v0, Codex, Cowork deploys)",
    "netlify.app": "Netlify (Bolt, others)",
    "web.app": "Firebase Hosting (Firebase Studio)",
    "firebaseapp.com": "Firebase Hosting",
    "run.app": "Google Cloud Run (AI Studio deploys)",
    "pages.dev": "Cloudflare Pages",
    "streamlit.app": "Streamlit",
    "bubbleapps.io": "Bubble",
    "softr.app": "Softr",
}
# Names the platforms themselves use, not customer apps.
PLATFORM_LABELS = {"www", "api", "app", "cdn", "static", "assets", "docs", "status", "auth", "login", "id"}

HOST = re.compile(r"(?<![A-Za-z0-9-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,})\.?(?![A-Za-z0-9-])")
SCRIPT_SRC = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})")
LOGIN_HINT = re.compile(r"type=[\"']?password|sign[ -]?in|log[ -]?in|continue with google", re.I)
SECRETS = [
    ("password in code", re.compile(r"[\"']?pass(?:word|wd)?[\"']?\s*[:=]\s*[\"'][^\"'\s]{4,}[\"']", re.I)),
    ("Supabase secret key", re.compile(r"sb_secret_[A-Za-z0-9_-]{10,}")),
    ("Supabase service_role JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]*(?:c2VydmljZV9yb2xl|InNlcnZpY2Vfcm9sZS)[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{10,}")),
    ("Stripe live secret key", re.compile(r"sk_live_[A-Za-z0-9]{10,}")),
    ("OpenAI key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{30,}")),
    ("Anthropic key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]
SUPABASE_URL = re.compile(r"https://[a-z0-9]{20}\.supabase\.co")
# Common library and framework email addresses that are not your data.
NOISE_EMAIL_DOMAINS = {"example.com", "sentry.io", "email.com", "domain.com", "test.com", "users.noreply.github.com"}


def builder_of(host, suffixes):
    host = host.lower().rstrip(".")
    for suf in sorted(suffixes, key=len, reverse=True):
        if host.endswith("." + suf):
            first = host[: -len(suf) - 1].split(".")[0]
            if first in PLATFORM_LABELS:
                return None
            return suffixes[suf]
    return None


def hosts_from(lines, suffixes):
    counts = collections.Counter()
    builders = {}
    for line in lines:
        for m in HOST.finditer(line):
            h = m.group(1).lower()
            b = builder_of(h, suffixes)
            if b:
                counts[h] += 1
                builders[h] = b
    return counts, builders


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def fetch(url, follow=False):
    """One GET with no cookies. PATCHLABS_TEST_ORIGIN (tests only) sends every
    request to a local server and keeps the real hostname in the Host header."""
    headers = {"User-Agent": UA}
    test_origin = os.environ.get("PATCHLABS_TEST_ORIGIN")
    if test_origin:
        p = urllib.parse.urlparse(url)
        headers["Host"] = p.netloc
        url = test_origin.rstrip("/") + (p.path or "/") + (("?" + p.query) if p.query else "")
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(urllib.request.Request(url, headers=headers), timeout=20) as r:
            return r.status, r.headers.get("Location", ""), r.read(2_000_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Location", ""), ""
    except Exception as e:  # DNS gone, TLS, timeout
        return None, str(e), ""


def check(host, org_domain=None):
    base = f"https://{host}"
    status, location, html = fetch(base)
    if status is None:
        return {"verdict": "offline or unreachable", "detail": location[:70]}
    if status in (401, 403):
        return {"verdict": f"{status}: closed to strangers (good)"}
    if 300 <= status < 400:
        return {"verdict": f"{status}: redirects to {location[:70]}", "detail": "open it in a private window to see what loads"}
    if status == 429:
        return {"verdict": "429: the host rate-limited or challenged the script", "detail": "open it in a private window instead"}
    if status != 200:
        return {"verdict": str(status)}
    blobs = [html]
    for src in SCRIPT_SRC.findall(html)[:8]:
        u = urllib.parse.urljoin(base + "/", src)
        if urllib.parse.urlparse(u).netloc == host:
            s, _, js = fetch(u, follow=True)
            if s == 200:
                blobs.append(js)
    text = "\n".join(blobs)
    domains = collections.Counter(d.lower() for d in EMAIL.findall(text) if d.lower() not in NOISE_EMAIL_DOMAINS)
    secrets = sorted({name for name, rx in SECRETS if rx.search(text)})
    out = {
        "verdict": "200: OPEN, the page loads for anyone",
        "login_screen": bool(LOGIN_HINT.search(text)),
        "email_domains": domains.most_common(5),
        "secrets": secrets,
        "supabase": bool(SUPABASE_URL.search(text)),
    }
    if org_domain:
        out["mentions_org"] = org_domain.lower() in text.lower()
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="+", help="log files, or - for stdin")
    ap.add_argument("--list-only", action="store_true", help="only list builder apps found; make no requests")
    ap.add_argument("--suffix", action="append", default=[], help="extra hosting suffix, e.g. myhost.app")
    ap.add_argument("--org-domain", help="your email domain; marks open apps whose page mentions it and hides open apps that do not")
    ap.add_argument("--max", type=int, default=200, help="most apps to check (default 200)")
    a = ap.parse_args(argv)

    suffixes = dict(SUFFIXES)
    for s in a.suffix:
        suffixes[s.lower().lstrip(".")] = "custom"

    def lines():
        for f in a.files:
            if f == "-":
                yield from sys.stdin
            else:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    yield from fh

    counts, builders = hosts_from(lines(), suffixes)
    if not counts:
        print("No app-builder hostnames found in the input.")
        return 0
    print(f"{len(counts)} app-builder hostname(s) in your logs:\n")
    by_builder = collections.Counter(builders[h] for h in counts)
    for b, n in by_builder.most_common():
        print(f"  {n:4d}  {b}")
    print()
    if a.list_only:
        for h, n in counts.most_common():
            print(f"{h}  ({builders[h]}, seen {n}x)")
        return 0

    open_n = 0
    for h, n in counts.most_common(a.max):
        r = check(h, a.org_domain)
        if a.org_domain and r.get("mentions_org") is False:
            continue
        print(f"{h}  ({builders[h]}, seen {n}x)")
        print(f"  {r['verdict']}" + (f": {r['detail']}" if r.get("detail") else ""))
        if r["verdict"].startswith("200"):
            open_n += 1
            if r["login_screen"]:
                print("  shows a sign-in screen: sign in with an outside account that was never invited and check you see nothing")
            if r["email_domains"]:
                print("  email domains in the page: " + ", ".join(f"{d} ({c})" for d, c in r["email_domains"]))
            if r["secrets"]:
                print("  SECRETS in the page's code: " + ", ".join(r["secrets"]) + ". Treat as compromised and rotate.")
            if r["supabase"]:
                print("  reads Supabase from the browser: check the tables too (https://patchlabs.dev/tools/rls-check)")
            if a.org_domain and r.get("mentions_org"):
                print(f"  mentions {a.org_domain}: likely yours. Switch it to invited users or Only you, or unpublish, then re-run.")
        print()
    print(f"{open_n} open to anyone. Logs also list public apps staff only visited, so confirm the owner first.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
