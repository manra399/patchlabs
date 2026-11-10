"""Live posture (LIVE.md): grading, URL rules, the SSRF guard, domain verification, re-checks, alerts, badge and the free tool.
The network is faked by replacing posture.fetch, except in the two tests that drive the real fetch against the local stub."""
import pytest

import core
import posture
from helpers import A, STATE, STUB, invite_as, outbox, sign_in, sql, verified_app

GOOD_TLS = {"version": "TLSv1.3", "cert": {"notAfter": "Feb  7 14:53:23 2099 GMT", "issuer": ((("organizationName", "Let's Encrypt"),),)}}
STRONG = {"strict-transport-security": "max-age=63072000; includeSubDomains", "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
          "x-content-type-options": "nosniff", "referrer-policy": "strict-origin-when-cross-origin", "server": "cloudflare"}


def resp(status=200, headers=None, cookies=(), body="<html></html>", tls=GOOD_TLS):
    return {"status": status, "headers": dict(headers or {}), "cookies": list(cookies), "body": body, "tls": tls}


def http_redirect(host):
    return resp(301, {"location": f"https://{host}/"}, tls=None)


@pytest.fixture
def net(monkeypatch):
    """SITES maps a URL to a response dict or an exception; anything missing is unreachable."""
    sites, calls = {}, []

    def fake(url, verify=True):
        calls.append(url)
        r = sites.get(url)
        if isinstance(r, Exception):
            raise r
        if r is None:
            raise posture.Unreachable(f"We couldn't connect to {url}.")
        return r
    monkeypatch.setattr(posture, "fetch", fake)
    sites["calls"] = calls
    return sites


def site(net, host, headers=STRONG, **kw):
    net[f"http://{host}/"] = http_redirect(host)
    net[f"https://{host}/"] = resp(headers=headers, **kw)


# ---- grading -----------------------------------------------------------------------------------------------------

def grade(headers, http_redirects=True, host="shop.example.com", **kw):
    return posture.analyze(f"https://{host}", resp(headers=headers, **kw), {"redirects": http_redirects})


def test_strong_site_gets_an_a_with_every_check_passed():
    g = grade(STRONG)
    assert g["grade"] == "A" and g["score"] == 100 and g["findings"] == [] and len(g["passed"]) == 10
    assert g["facts"]["tls"] == {"version": "TLSv1.3", "issuer": "Let's Encrypt", "expires": "2099-02-07", "days_left": g["facts"]["tls"]["days_left"]}
    assert g["facts"]["headers"]["content-security-policy"].startswith("default-src") and g["facts"]["headers"]["x-powered-by"] is None


def test_bare_site_findings_and_grade():
    g = grade({"server": "nginx/1.18.0", "x-powered-by": "PHP/7.4.3"}, http_redirects=False)
    ids = [f["id"] for f in g["findings"]]
    assert ids == ["PL-027", "PL-030", "PL-029", "PL-031", "PL-032", "PL-035", "PL-036"]  # worst first, then by id
    assert g["counts"] == {"critical": 0, "high": 0, "medium": 2, "low": 3, "info": 2}
    assert g["score"] == 100 - 2 * 15 - 3 * 5 == 55 and g["grade"] == "D"
    f = g["findings"][0]
    assert f["line"] == "live" and f["severity"] == "medium" and f["cwe"] == ["CWE-319"] and f["owasp"] == "A02:2021" and f["fix"]
    assert "nginx/1.18.0" in next(x for x in g["findings"] if x["id"] == "PL-035")["evidence"]


def test_meta_tags_count_but_report_only_csp_does_not():
    body = ('<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">'
            '<meta name="referrer" content="no-referrer">')
    ids = {f["id"] for f in grade({}, body=body)["findings"]}
    assert "PL-030" not in ids and "PL-036" not in ids and "PL-031" in ids  # a meta CSP can't set frame-ancestors
    g = grade({"content-security-policy-report-only": "default-src 'self'"},
              body='<meta http-equiv="Content-Security-Policy-Report-Only" content="x">')
    assert "Report-Only" in next(f for f in g["findings"] if f["id"] == "PL-030")["evidence"]


def test_x_frame_options_and_short_hsts():
    g = grade({**STRONG, "content-security-policy": "default-src 'self'", "x-frame-options": "DENY",
               "strict-transport-security": "max-age=86400"})
    assert [f["id"] for f in g["findings"]] == ["PL-029"] and "86400" in g["findings"][0]["evidence"] and g["grade"] == "A"


def test_preloaded_tld_needs_no_redirect_or_hsts():
    g = grade({k: v for k, v in STRONG.items() if k != "strict-transport-security"}, http_redirects=False, host="shop.lovable.app")
    assert g["findings"] == [] and g["facts"]["https_preloaded_tld"] is True


def test_cookie_flags():
    g = grade(STRONG, cookies=["sb-session=abc; Path=/; Secure; SameSite=Lax", "theme=dark; Path=/",
                               "auth_token=x; Secure; SameSite=Strict", "ok=1; Secure", "pref=1; Secure; HttpOnly"])
    cookie = [f for f in g["findings"] if f["id"] == "PL-033"]
    assert [f["object"] for f in cookie] == ["cookie sb-session", "cookie theme", "cookie auth_token"]
    by = {f["object"]: f["evidence"] for f in cookie}
    assert by["cookie theme"] == "Cookie theme is set without Secure."  # no SameSite is fine: browsers default to Lax
    assert by["cookie auth_token"] == "Cookie auth_token is set without HttpOnly."
    assert by["cookie sb-session"] == "Cookie sb-session is set without HttpOnly."
    assert {"name": "ok", "secure": True, "httponly": False, "samesite": None} in g["facts"]["cookies"]
    assert g["score"] == 85 and g["grade"] == "B"  # three bad cookies cost one check's points


def test_mixed_content():
    body = ('<script src="http://cdn.example.net/a.js"></script><script src="https://ok.example.net/b.js"></script>'
            '<link rel="stylesheet" href="http://cdn.example.net/s.css"><link rel="icon" href="http://cdn.example.net/i.png">')
    f = next(f for f in grade(STRONG, body=body)["findings"] if f["id"] == "PL-034")
    assert f["evidence"] == "Loaded over plain HTTP: http://cdn.example.net/a.js, http://cdn.example.net/s.css"


def test_certificate_problems():
    soon = {"version": "TLSv1.2", "cert": {"notAfter": "Jan  1 00:00:00 2000 GMT", "issuer": ()}}
    g = grade(STRONG, tls=soon)
    assert g["grade"] == "F" and g["findings"][0]["id"] == "PL-028" and g["findings"][0]["severity"] == "high"
    g = posture.analyze("https://shop.example.com", resp(headers=STRONG), {"redirects": True}, cert_problem="The certificate has expired.")
    assert g["grade"] == "F" and g["findings"][0]["evidence"] == "The certificate has expired."


def test_expiring_certificate_is_medium():
    from datetime import datetime, timedelta, timezone
    now = datetime(2098, 1, 1, tzinfo=timezone.utc)
    tls = {"version": "TLSv1.3", "cert": {"notAfter": (now + timedelta(days=10)).strftime("%b %d %H:%M:%S %Y GMT"), "issuer": ()}}
    g = posture.analyze("https://shop.example.com", resp(headers=STRONG, tls=tls), {"redirects": True}, now=now)
    assert [(f["id"], f["severity"]) for f in g["findings"]] == [("PL-028", "medium")] and "(10 days)" in g["findings"][0]["evidence"]


# ---- URLs and the SSRF guard ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("text,out", [("shop.example.com", "https://shop.example.com"), ("https://Shop.Example.com/a?b=1", "https://shop.example.com"),
                                      ("https://shop.example.com.", "https://shop.example.com"), ("https://shop.example.com:443/", "https://shop.example.com")])
def test_origin_normalises(text, out):
    assert posture.origin(text) == out


@pytest.mark.parametrize("text", ["", "http://shop.example.com", "ftp://x.example.com", "https://10.0.0.1", "https://[::1]/", "localhost",
                                  "https://intranet", "https://db.internal", "https://x.local", "https://shop.example.com:8443",
                                  "https://u:p@shop.example.com", "https://-bad-.example.com", "javascript:alert(1)"])
def test_origin_rejects(text):
    with pytest.raises(ValueError):
        posture.origin(text)
    assert posture.origin("http://shop.example.com", schemes=("https", "http")) == "https://shop.example.com"


def test_fetch_refuses_private_addresses(monkeypatch):
    with pytest.raises(posture.Unreachable, match="private address"):
        posture.fetch(f"{STUB}/gh/repos/acme/x")  # the real stub on 127.0.0.1
    monkeypatch.setattr(posture.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.1.2.3", 443))])
    with pytest.raises(posture.Unreachable, match="private address"):
        posture.fetch("https://evil.example.com/")


def test_fetch_reads_a_real_response_pinned_to_the_checked_address(monkeypatch):
    monkeypatch.setattr(core, "ip_allowed", lambda ip: True)
    r = posture.fetch(f"{STUB}/gh/repos/acme/missing")
    assert r["status"] == 404 and r["headers"]["content-type"] == "application/json" and "Not Found" in r["body"] and r["tls"] is None
    assert STATE.calls[-1] == "/gh/repos/acme/missing"


def test_redirects_are_followed_and_capped(net):
    net["https://a.example.com/"] = resp(302, {"location": "/home"})
    net["https://a.example.com/home"] = resp(headers=STRONG)
    r, seen = posture.load("https://a.example.com/")
    assert seen == ["https://a.example.com/", "https://a.example.com/home"] and r["status"] == 200
    for i in range(7):
        net[f"https://loop.example.com/{i}"] = resp(301, {"location": f"/{i + 1}"})
    with pytest.raises(posture.Unreachable, match="more than 5"):
        posture.load("https://loop.example.com/0")
    net["https://js.example.com/"] = resp(302, {"location": "javascript:alert(1)"})
    with pytest.raises(posture.Unreachable):
        posture.load("https://js.example.com/")


def test_bad_certificate_still_reads_headers(net, monkeypatch):
    net["http://bad.example.com/"] = http_redirect("bad.example.com")
    calls = []

    def fake(url, verify=True):
        calls.append((url, verify))
        if url.startswith("https") and verify:
            raise posture.CertError("The certificate has expired.")
        return net[url] if url.startswith("http:") else resp(headers=STRONG, tls={"version": "TLSv1.2", "cert": None})
    monkeypatch.setattr(posture, "fetch", fake)
    g = posture.inspect("https://bad.example.com")
    assert g["grade"] == "F" and [f["id"] for f in g["findings"]] == ["PL-028"] and ("https://bad.example.com/", False) in calls


# ---- the app flow --------------------------------------------------------------------------------------------------

def live_app(client, net, host="shop.example.com"):
    u = sign_in(client, "owner@example.com")
    a, _ = verified_app(client, u)
    r = client.put(f"/apps/{a['id']}/live", json={"url": host}, headers=u.h)
    assert r.status_code == 200, r.text
    return u, a, r.json()


def test_set_verify_and_view(client, net):
    u, a, live = live_app(client, net)
    assert live["url"] == "https://shop.example.com" and live["verified"] is False and live["last"] is None
    code = live["verify"]["code"]
    assert code.startswith("patchlabs-live-") and live["verify"]["file_url"] == "https://shop.example.com/patchlabs-verify.txt"
    assert live["verify"]["meta"] == f'<meta name="patchlabs-verify" content="{code}">'
    assert client.get(f"/apps/{a['id']}", headers=u.h).json()["live"]["verify"]["code"] == code

    site(net, "shop.example.com")
    r = client.post(f"/apps/{a['id']}/live/verify", headers=u.h)
    assert r.status_code == 409 and "patchlabs-verify.txt" in r.json()["detail"]
    net["https://shop.example.com/patchlabs-verify.txt"] = resp(body=code + "\n")
    r = client.post(f"/apps/{a['id']}/live/verify", headers=u.h)
    assert r.status_code == 200 and r.json()["verified"] is True and r.json()["posture"]["grade"] == "A"
    assert r.json()["posture"]["trigger"] == "verify" and r.json()["posture"]["id"]

    view = client.get(f"/apps/{a['id']}", headers=u.h).json()["live"]
    assert view["verified"] and view["verify"] is None and view["last"]["grade"] == "A" and view["last"]["passed"]
    assert view["next_check_at"] is not None
    listed = client.get(f"/workspaces/{u.wid}/apps", headers=u.h).json()["apps"][0]["live"]["last"]
    assert set(listed) == {"grade", "score", "checked_at", "counts"}
    acts = [r["action"] for r in sql("SELECT action FROM audit_log ORDER BY id")]
    assert acts[-3:] == ["app.live_set", "app.live_verified", "posture.checked"]
    assert client.post(f"/apps/{a['id']}/live/verify", headers=u.h).json()["verified"] is True  # idempotent


def test_meta_tag_verifies_and_other_hosts_cannot_vouch(client, net):
    u, a, live = live_app(client, net)
    code = live["verify"]["code"]
    site(net, "shop.example.com")
    net["https://shop.example.com/patchlabs-verify.txt"] = resp(302, {"location": "https://attacker.example.net/v.txt"})
    net["https://attacker.example.net/v.txt"] = resp(body=code)
    assert client.post(f"/apps/{a['id']}/live/verify", headers=u.h).status_code == 409
    net["https://shop.example.com/"] = resp(headers=STRONG, body=f'<head><meta content="{code}" name="patchlabs-verify"></head>')
    assert client.post(f"/apps/{a['id']}/live/verify", headers=u.h).json()["verified"] is True


def test_wrong_code_and_lookalike_meta_do_not_verify(client, net):
    u, a, live = live_app(client, net)
    site(net, "shop.example.com", body=f'<meta name="patchlabs-verify-old" content="{live["verify"]["code"]}">')
    net["https://shop.example.com/patchlabs-verify.txt"] = resp(body="patchlabs-live-0000000000000000")
    assert client.post(f"/apps/{a['id']}/live/verify", headers=u.h).status_code == 409


def test_bad_urls_and_permissions(client, net):
    u = sign_in(client, "owner@example.com")
    a, _ = verified_app(client, u)
    for bad in ("https://127.0.0.1", "localhost", "http://shop.example.com"):
        r = client.put(f"/apps/{a['id']}/live", json={"url": bad}, headers=u.h)
        assert r.status_code == 422 and r.json()["detail"]
    client.patch(f"/admin/workspaces/{u.wid}", json={"plan": "agency"}, headers=A)
    viewer = invite_as(client, u, "viewer@example.com", "viewer")
    assert client.put(f"/apps/{a['id']}/live", json={"url": "shop.example.com"}, headers=viewer.h).status_code == 403
    stranger = sign_in(client, "stranger@example.com")
    assert client.put(f"/apps/{a['id']}/live", json={"url": "shop.example.com"}, headers=stranger.h).status_code == 404
    assert client.get(f"/apps/{a['id']}/live/checks", headers=stranger.h).status_code == 404
    client.put(f"/apps/{a['id']}/live", json={"url": "shop.example.com"}, headers=u.h)
    assert client.post(f"/apps/{a['id']}/live/verify", headers=viewer.h).status_code == 403
    assert client.post(f"/apps/{a['id']}/live/checks", headers=u.h).status_code == 409  # not verified yet
    assert client.get(f"/apps/{a['id']}", headers=viewer.h).json()["live"]["url"] == "https://shop.example.com"


def verified_live(client, net, host="shop.example.com", headers=STRONG):
    u, a, live = live_app(client, net, host)
    site(net, host, headers=headers)
    net[f"https://{host}/patchlabs-verify.txt"] = resp(body=live["verify"]["code"])
    assert client.post(f"/apps/{a['id']}/live/verify", headers=u.h).json()["verified"]
    return u, a


def test_recheck_rate_limit_history_and_drop_alert(client, net, local_webhooks):
    u, a = verified_live(client, net)
    assert client.patch(f"/workspaces/{u.wid}", json={"webhook_url": local_webhooks}, headers=u.h).status_code == 200
    r = client.post(f"/apps/{a['id']}/live/checks", headers=u.h)
    assert r.status_code == 429 and "10 minutes" in r.json()["detail"]
    sql("UPDATE posture_checks SET created_at = created_at - interval '11 minutes'")
    before = len(outbox("owner@example.com"))
    site(net, "shop.example.com", headers={k: v for k, v in STRONG.items() if k != "content-security-policy"})
    r = client.post(f"/apps/{a['id']}/live/checks", headers=u.h)
    assert r.status_code == 201 and r.json()["grade"] == "B" and r.json()["trigger"] == "manual"
    mails = outbox("owner@example.com")[before:]
    assert len(mails) == 1 and mails[0]["subject"] == "Live posture changed for acme/shop"
    assert "dropped from A to B" in mails[0]["text"] and "PL-030 (medium)" in mails[0]["text"] and "#live" in mails[0]["text"]
    hook = STATE.hooks[-1]["body"]
    assert hook["event"] == "posture.changed" and hook["posture"]["grade"] == "B" and hook["posture"]["previous_grade"] == "A"
    assert sorted(hook["posture"]["new_findings"]) == ["PL-030", "PL-031"]
    hist = client.get(f"/apps/{a['id']}/live/checks", headers=u.h).json()["checks"]
    assert [h["grade"] for h in hist] == ["B", "A"] and [h["trigger"] for h in hist] == ["manual", "verify"]

    sql("UPDATE posture_checks SET created_at = created_at - interval '11 minutes'")
    before = len(outbox("owner@example.com"))
    assert client.post(f"/apps/{a['id']}/live/checks", headers=u.h).json()["grade"] == "B"
    assert len(outbox("owner@example.com")) == before  # same result: no alert


def test_unreachable_recheck_is_502_and_stores_nothing(client, net):
    u, a = verified_live(client, net)
    sql("UPDATE posture_checks SET created_at = created_at - interval '11 minutes'")
    del net["https://shop.example.com/"]
    r = client.post(f"/apps/{a['id']}/live/checks", headers=u.h)
    assert r.status_code == 502 and "couldn't connect" in r.json()["detail"]
    assert sql("SELECT count(*) AS n FROM posture_checks")[0]["n"] == 1


def test_badge_and_public_status(client, net):
    u, a = verified_live(client, net)
    svg = client.get(f"/badge/{a['id']}/live.svg").text
    assert "private" in svg and client.get(f"/public/apps/{a['id']}").status_code == 404
    client.patch(f"/apps/{a['id']}", json={"badge_public": True}, headers=u.h)
    r = client.get(f"/badge/{a['id']}/live.svg")
    assert r.headers["content-type"] == "image/svg+xml" and "live posture" in r.text and ">A · " in r.text
    assert client.get(f"/public/apps/{a['id']}").json()["live"]["grade"] == "A"
    assert "private" in client.get("/badge/not-a-uuid/live.svg").text


def test_change_and_remove_domain(client, net):
    u, a = verified_live(client, net)
    old_code = sql("SELECT live_code FROM apps")[0]["live_code"]
    same = client.put(f"/apps/{a['id']}/live", json={"url": "https://shop.example.com/pricing"}, headers=u.h).json()
    assert same["verified"] is True  # same origin: nothing changes
    moved = client.put(f"/apps/{a['id']}/live", json={"url": "www.example.com"}, headers=u.h).json()
    assert moved["verified"] is False and moved["last"] is None and moved["verify"]["code"] != old_code
    assert sql("SELECT count(*) AS n FROM posture_checks")[0]["n"] == 0
    assert client.delete(f"/apps/{a['id']}/live", headers=u.h).json() == {"ok": True}
    assert client.get(f"/apps/{a['id']}", headers=u.h).json()["live"] == {"url": None, "verified": False, "verified_at": None,
                                                                          "next_check_at": None, "verify": None, "last": None}
    assert [r["action"] for r in sql("SELECT action FROM audit_log ORDER BY id")][-2:] == ["app.live_set", "app.live_removed"]


def test_daily_sweep_rechecks_due_domains_only(client, net):
    u, a = verified_live(client, net)
    assert posture.run_due() == 0  # next check is a day away
    sql("UPDATE apps SET live_next_at = now() - interval '1 minute'")
    assert posture.run_due() == 1
    assert sql("SELECT trigger FROM posture_checks ORDER BY created_at DESC LIMIT 1")[0]["trigger"] == "scheduled"
    assert sql("SELECT live_next_at > now() + interval '23 hours' AS later FROM apps")[0]["later"] is True
    sql("UPDATE apps SET live_next_at = now() - interval '1 minute', schedule = 'off'")
    assert posture.run_due() == 0
    acts = sql("SELECT actor_kind FROM audit_log WHERE action = 'posture.checked' ORDER BY id")
    assert [r["actor_kind"] for r in acts] == ["user", "system"]


def test_client_sees_live_posture_read_only(client, net):
    u, a = verified_live(client, net)
    client.patch(f"/admin/workspaces/{u.wid}", json={"plan": "agency"}, headers=A)
    cl = invite_as(client, u, "client@example.com", "client", app_ids=[a["id"]])
    assert client.get(f"/apps/{a['id']}", headers=cl.h).json()["live"]["last"]["grade"] == "A"
    assert client.get(f"/apps/{a['id']}/live/checks", headers=cl.h).status_code == 200
    assert client.post(f"/apps/{a['id']}/live/checks", headers=cl.h).status_code == 403
    assert client.delete(f"/apps/{a['id']}/live", headers=cl.h).status_code == 403


# ---- the free tool -------------------------------------------------------------------------------------------------

def test_headers_tool(client, net):
    site(net, "shop.example.com", headers={"server": "Vercel"})
    r = client.post("/tools/headers-check", json={"url": "http://shop.example.com/some/page"})
    assert r.status_code == 200, r.text
    g = r.json()
    assert g["url"] == "https://shop.example.com" and g["grade"] == "C" and "id" not in g and g["checked_at"]
    assert net["calls"][:2] == ["http://shop.example.com/", "https://shop.example.com/"]  # the home page only
    assert sql("SELECT tool, repo FROM tool_runs")[0] == {"tool": "headers-check", "repo": "shop.example.com"}
    assert client.post("/tools/headers-check", json={"url": "https://localhost"}).status_code == 422
    r = client.post("/tools/headers-check", json={"url": "https://down.example.com"})
    assert r.status_code == 502 and r.json()["detail"]
    for _ in range(8):
        client.post("/tools/headers-check", json={"url": "shop.example.com"})
    r = client.post("/tools/headers-check", json={"url": "shop.example.com"})
    assert r.status_code == 429 and "10 checks this hour" in r.json()["detail"]
    assert sql("SELECT count(*) AS n FROM posture_checks")[0]["n"] == 0  # nothing stored


def test_taxonomy_lists_live_findings(client):
    t = client.get("/taxonomy/findings").json()
    assert t["findings"]["PL-033"]["cwe"] == ["CWE-614", "CWE-1004"] and t["cwe"]["CWE-1021"]
    assert all(f"PL-0{n}" in t["findings"] for n in range(27, 37))
    assert set(posture.CHECKS) == {f"PL-0{n}" for n in range(27, 37)}
