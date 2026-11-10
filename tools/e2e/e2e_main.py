# E2E only: lets webhooks reach the local stub (plain http, private address), exactly like the tests' local_webhooks fixture.
import core
core.WEBHOOK_SCHEMES = ("https", "http")
core.ip_allowed = lambda ip: True
from urllib.parse import urlsplit  # noqa: E402

import posture  # noqa: E402

# E2E only: hosts under e2e-site.net are fake live sites served by the stub (plain http inside Docker), dressed as https.
_fetch = posture.fetch


def e2e_fetch(url, verify=True):
    u = urlsplit(url)
    if not (u.hostname or "").endswith(".e2e-site.net"):
        return _fetch(url, verify)
    r = _fetch(f"http://pl-e2e-stub:8080/_site/{u.scheme}/{u.hostname}{u.path or '/'}", verify)
    if r["status"] in (301, 302, 303, 307, 308):
        return r
    if u.scheme == "https":
        r["tls"] = {"version": "TLSv1.3", "cert": {"notAfter": "Feb  7 14:53:23 2099 GMT", "issuer": ((("organizationName", "E2E Test CA"),),)}}
    return r


posture.fetch = e2e_fetch
from app import app  # noqa: E402,F401
