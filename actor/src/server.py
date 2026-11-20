"""Server interface (Apify Server Actor, formerly Standby mode): one HTTP request checks one site.

    GET  /check?url=https://myapp.lovable.app
    POST /check   {"url": "https://myapp.lovable.app"}

The response is the same JSON item the input interface pushes to the dataset. The site-checked event is charged only
when the site loaded, before the response is sent, with the request's X-Actor-Request-ID so multi-tenant runs bill the
caller (https://docs.apify.com/actors/monetize/server-actors.md). Readiness probes get a plain 200 straight away.
"""
import json
import logging
import os
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import httpx

from .main import EVENT, check_site

log = logging.getLogger("patchlabs.server")
MAX_BODY = 4096
USAGE = {
    "service": "PatchLabs AI-built app security check",
    "usage": "GET /check?url=https://yourapp.example or POST /check with {\"url\": \"...\"}",
    "checks": "HTTPS redirect, TLS certificate, security headers, cookie flags, and secret keys in the page's own "
              "scripts (masked). One plain http request, one https page load and same-site scripts. Nothing else.",
    "only_check": "sites you own or have permission to test",
    "docs": "https://patchlabs.dev/tools/headers-check",
}


def charge(request_id, env=os.environ, post=httpx.post):
    """Charges one site-checked event for this request. Returns True, False (charge refused), or None (not on the
    platform, nothing to charge)."""
    token, run_id = env.get("APIFY_TOKEN"), env.get("ACTOR_RUN_ID")
    if not token or not run_id:
        return None
    body = {"eventName": EVENT, "count": 1}
    if request_id:
        body["requestId"] = request_id
    try:
        r = post(f"https://api.apify.com/v2/actor-runs/{run_id}/charge", json=body, timeout=10,
                 headers={"Authorization": f"Bearer {token}",
                          "idempotency-key": f"{request_id or uuid.uuid4()}:{EVENT}"})
    except httpx.HTTPError as e:
        log.warning("charge failed: %s", e)
        return False
    if r.status_code >= 300:
        log.warning("charge refused %s: %s", r.status_code, r.text[:300])
        return False
    return True


class Handler(BaseHTTPRequestHandler):
    server_version = "patchlabs-actor"
    sys_version = ""
    check = staticmethod(check_site)
    charge = staticmethod(charge)

    def log_message(self, fmt, *args):
        log.info("%s %s", self.address_string(), fmt % args)

    def send_json(self, status, obj):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def run_check(self, url):
        if not isinstance(url, str) or not url.strip():
            return self.send_json(400, {"ok": False, "error": "Pass the site address as ?url=https://... "
                                                              "or a JSON body {\"url\": \"...\"}.", **USAGE})
        item = self.check(url.strip()[:2048])
        if item.get("ok"):
            item["charged"] = self.charge(self.headers.get("x-actor-request-id"))
        self.send_json(200 if item.get("ok") else 422, item)

    def do_GET(self):
        if self.headers.get("x-apify-container-server-readiness-probe"):
            return self.send_json(200, {"ready": True})
        u = urlsplit(self.path)
        if u.path in ("/", ""):
            return self.send_json(200, USAGE)
        if u.path.rstrip("/") == "/check":
            return self.run_check((parse_qs(u.query).get("url") or [""])[0])
        self.send_json(404, {"ok": False, "error": "Unknown path.", **USAGE})

    def do_POST(self):
        if urlsplit(self.path).path.rstrip("/") != "/check":
            return self.send_json(404, {"ok": False, "error": "Unknown path.", **USAGE})
        try:
            n = int(self.headers.get("content-length") or 0)
        except ValueError:
            n = -1
        if n < 0 or n > MAX_BODY:
            return self.send_json(413, {"ok": False, "error": f"Body must be JSON under {MAX_BODY} bytes."})
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self.send_json(400, {"ok": False, "error": "Body is not valid JSON."})
        self.run_check(body.get("url") if isinstance(body, dict) else None)


def serve(port=None):
    port = int(port or os.environ.get("ACTOR_WEB_SERVER_PORT") or os.environ.get("ACTOR_STANDBY_PORT") or 4321)
    httpd = ThreadingHTTPServer(("", port), Handler)
    httpd.daemon_threads = True
    log.info("PatchLabs server interface listening on %s", port)
    httpd.serve_forever()
