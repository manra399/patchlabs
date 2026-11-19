"""Apify Actor: PatchLabs site security check.

For each start URL: one plain-http request (does it redirect to https?), one https load of the home page, and the
same-site scripts that page loads. Reports a grade for HTTPS, certificate, security headers and cookies, plus any
secret keys shipped to every visitor (masked). Nothing else is requested: no forms, no logins, no other paths.
"""
import asyncio
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

from apify import Actor

from . import keys
from . import posture

MAX_SITES = 500
EVENT = "site-checked"  # pay-per-event pricing: one charge per site that loaded


def inspect(site):
    """posture.inspect, but also returns the page body so the key scan doesn't load the page twice."""
    host = urlsplit(site).hostname
    try:
        hr = posture.fetch(f"http://{host}/")
        loc = hr["headers"].get("location") or ""
        redirects = hr["status"] in (301, 302, 303, 307, 308) and urljoin(f"http://{host}/", loc).startswith("https://")
    except posture.Unreachable:
        redirects = None
    except posture.CertError:
        redirects = True
    cert_problem = None
    try:
        r, seen = posture.load(site + "/")
    except posture.CertError as e:
        cert_problem = str(e)
        r, seen = posture.load(site + "/", verify=False)
    r["url"] = seen[-1]
    return posture.analyze(site, r, {"redirects": redirects, "seen": seen}, cert_problem), r["body"]


def check_site(raw):
    """Runs both checks for one address. Returns one dataset item (never raises)."""
    started = datetime.now(timezone.utc)
    try:
        site = posture.origin(raw, schemes=("https", "http"))
    except ValueError as e:
        return {"input": raw, "ok": False, "error": str(e)}
    try:
        out, page = inspect(site)
    except posture.Unreachable as e:
        return {"input": raw, "url": site, "ok": False, "error": str(e)}
    k = keys.scan(out["final_url"], page)
    secrets = k["findings"]
    grade = "F" if any(f["severity"] == "critical" for f in secrets) else out["grade"]
    return {
        "input": raw, "url": site, "ok": True, "final_url": out["final_url"],
        "grade": grade, "headers_grade": out["grade"], "headers_score": out["score"],
        "secrets_found": len(secrets), "secrets": secrets,
        "findings": out["findings"], "passed": out["passed"], "counts": out["counts"],
        "supabase": k["supabase"], "scripts_read": len(k["scripts_read"]), "scripts_failed": len(k["scripts_failed"]),
        "facts": out["facts"],
        "report": "https://patchlabs.dev/tools/headers-check",
        "checked_at": started.isoformat(),
    }


async def main():
    async with Actor:
        inp = await Actor.get_input() or {}
        urls = [u.get("url") if isinstance(u, dict) else u for u in (inp.get("startUrls") or inp.get("urls") or [])]
        urls = [u.strip() for u in urls if isinstance(u, str) and u.strip()]
        if not urls:
            await Actor.fail(status_message="Add at least one site address under 'Sites to check'.")
            return
        if len(urls) > MAX_SITES:
            Actor.log.warning(f"Checking the first {MAX_SITES} of {len(urls)} sites.")
            urls = urls[:MAX_SITES]
        sem = asyncio.Semaphore(max(1, min(int(inp.get("maxConcurrency") or 5), 20)))
        done = 0

        async def one(u):
            nonlocal done
            async with sem:
                item = await asyncio.to_thread(check_site, u)
            await Actor.push_data(item)
            if item.get("ok"):
                try:
                    await Actor.charge(event_name=EVENT)
                except Exception as e:  # not on pay-per-event pricing, or an older SDK
                    Actor.log.debug(f"charge skipped: {e}")
            done += 1
            await Actor.set_status_message(f"Checked {done} of {len(urls)} sites")
            Actor.log.info(f"{u}: " + (f"grade {item['grade']}, {item['secrets_found']} secret(s)" if item.get("ok") else item["error"]))

        await asyncio.gather(*(one(u) for u in urls))
        await Actor.set_status_message(f"Done: {done} sites checked. Fix guides: https://patchlabs.dev/learn")
