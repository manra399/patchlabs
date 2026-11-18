#!/usr/bin/env python3
"""List every Vercel project in a team, say who can open its production URL,
and test that URL signed out.

Read-only. Uses only the Python standard library. Needs a Vercel access token
(Account Settings > Tokens) with read access to the team.

    VERCEL_TOKEN=... python3 vercel_public_apps.py            # personal account
    VERCEL_TOKEN=... VERCEL_TEAM=my-firm python3 vercel_public_apps.py

For each project it prints:
  scope    the Deployment Protection scope (ssoProtection.deploymentType),
           plus password / trusted-IP / Passport protection if set
  url      each production domain
  signed-out result   the HTTP status a stranger gets, and whether the page's
           own JavaScript talks to a Supabase project directly (then locking the
           URL does not lock the data: the database answers anyone with the key)

Guide: https://patchlabs.dev/learn/staff-vibe-coded-apps-client-data
"""
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

API = os.environ.get("VERCEL_API", "https://api.vercel.com")
UA = "patchlabs-vercel-public-apps/1.0"

SCOPES = {
    None: "NONE: every URL is public",
    "all": "All Deployments: production protected",
    "all_except_custom_domains": "Standard: production domain PUBLIC",
    "prod_deployment_urls_and_all_previews": "Legacy standard: production domain PUBLIC",
    "preview": "Previews only: production PUBLIC",
}

SUPABASE_URL = re.compile(r"https://[a-z0-9]{20}\.supabase\.co")
SUPABASE_KEY = re.compile(r"sb_publishable_[A-Za-z0-9_-]{10,}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}")
SCRIPT_SRC = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)


def api(path, params):
    token = os.environ.get("VERCEL_TOKEN")
    if not token:
        sys.exit("Set VERCEL_TOKEN (Vercel > Account Settings > Tokens).")
    team = os.environ.get("VERCEL_TEAM")
    if team:
        params["teamId" if team.startswith("team_") else "slug"] = team
    req = urllib.request.Request(
        f"{API}{path}?{urllib.parse.urlencode(params)}",
        headers={"Authorization": f"Bearer {token}", "User-Agent": UA},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        sys.exit(f"Vercel API said {e.code} for {path}: check the token and VERCEL_TEAM.")


def projects():
    params = {"limit": "100"}
    while True:
        data = api("/v10/projects", dict(params))
        items = data["projects"] if isinstance(data, dict) else data
        yield from items
        nxt = data.get("pagination", {}).get("next") if isinstance(data, dict) else None
        if not nxt:
            return
        params["until"] = str(nxt)


def scope(p):
    sso = (p.get("ssoProtection") or {}).get("deploymentType")
    text = SCOPES.get(sso, f"unknown ({sso})")
    extra = []
    if p.get("passwordProtection"):
        extra.append("password")
    if p.get("trustedIps"):
        extra.append("trusted IPs")
    if p.get("passport"):
        extra.append("Passport")
    if extra:
        text += " + " + ", ".join(extra)
    return text


def production_domains(p):
    out = []
    for a in p.get("alias") or []:
        if isinstance(a, dict) and str(a.get("target", "")).upper() == "PRODUCTION" and not a.get("redirect"):
            out.append(a.get("domain"))
    prod = (p.get("targets") or {}).get("production") or {}
    for d in prod.get("alias") or []:
        out.append(d)
    seen, uniq = set(), []
    for d in out:
        if d and d not in seen:
            seen.add(d)
            uniq.append(d)
    return uniq


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def fetch(url, follow=False):
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with opener.open(req, timeout=20) as r:
            return r.status, r.headers.get("Location", ""), r.read(2_000_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Location", ""), ""
    except Exception as e:  # DNS, TLS, timeout
        return None, str(e), ""


def signed_out(domain):
    base = domain if domain.startswith("http") else f"https://{domain}"
    status, location, html = fetch(base)
    if status is None:
        return f"unreachable ({location[:60]})"
    if status in (401, 403):
        return f"{status}: login required (good)"
    if 300 <= status < 400:
        if "vercel.com" in location:
            return f"{status}: sends strangers to the Vercel login (good)"
        return f"{status}: redirects to {location[:70]} (open it signed out to see what loads)"
    if status != 200:
        return f"{status}"
    blobs = [html]
    for src in SCRIPT_SRC.findall(html)[:8]:
        u = urllib.parse.urljoin(base + "/", src)
        if urllib.parse.urlparse(u).netloc == urllib.parse.urlparse(base).netloc:
            s, _, js = fetch(u, follow=True)
            if s == 200:
                blobs.append(js)
    text = "\n".join(blobs)
    note = "200: PUBLIC, the page loads for anyone"
    if SUPABASE_URL.search(text) and SUPABASE_KEY.search(text):
        note += "; its JavaScript reads Supabase directly (check RLS: https://patchlabs.dev/tools/rls-check)"
    return note


def main():
    rows = 0
    for p in projects():
        rows += 1
        print(f"\n{p.get('name')}")
        print(f"  scope: {scope(p)}")
        domains = production_domains(p)
        if not domains:
            print("  no production domain found")
        for d in domains:
            print(f"  {d}: {signed_out(d)}")
    if not rows:
        print("No projects visible to this token. Is VERCEL_TEAM set to the right team?")


if __name__ == "__main__":
    main()
