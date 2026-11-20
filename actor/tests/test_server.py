import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import httpx

from src import main, server


class FakeResp:
    def __init__(self, code, text=""):
        self.status_code, self.text = code, text


def start(check, charged=True):
    calls = []

    class H(server.Handler):
        pass
    H.check = staticmethod(lambda url: (calls.append(url), check(url))[1])
    H.charge = staticmethod(lambda rid: (calls.append(("charge", rid)), charged)[1])
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}", calls


def req(url, data=None, headers=None):
    r = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(r) as resp:
            return resp.status, json.loads(resp.read()), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()), e.headers


OK = lambda url: {"input": url, "ok": True, "grade": "A", "secrets_found": 0}
BAD = lambda url: {"input": url, "ok": False, "error": "That's a private name."}


def test_readiness_probe_skips_work():
    httpd, base, calls = start(OK)
    code, body, _ = req(base + "/", headers={"x-apify-container-server-readiness-probe": "1"})
    httpd.shutdown()
    assert code == 200 and body == {"ready": True} and calls == []


def test_get_check_charges_with_request_id():
    httpd, base, calls = start(OK)
    code, body, h = req(base + "/check?url=https://a.example.com", headers={"X-Actor-Request-ID": "r1"})
    httpd.shutdown()
    assert code == 200 and body["grade"] == "A" and body["charged"] is True
    assert calls == ["https://a.example.com", ("charge", "r1")]
    assert h["X-Content-Type-Options"] == "nosniff"


def test_post_check_and_failed_site_not_charged():
    httpd, base, calls = start(BAD)
    code, body, _ = req(base + "/check", data=b'{"url": "http://x.local"}', headers={"Content-Type": "application/json"})
    httpd.shutdown()
    assert code == 422 and body["ok"] is False and "charged" not in body
    assert calls == ["http://x.local"]


def test_missing_url_bad_json_and_unknown_path():
    httpd, base, calls = start(OK)
    assert req(base + "/check")[0] == 400
    assert req(base + "/check", data=b"{nope")[0] == 400
    assert req(base + "/check", data=b"[1]")[0] == 400
    assert req(base + "/nope")[0] == 404
    assert req(base + "/")[1]["usage"].startswith("GET /check")
    httpd.shutdown()
    assert calls == []


def test_charge_body_and_headers():
    seen = {}

    def post(url, json, timeout, headers):
        seen.update(url=url, json=json, headers=headers)
        return FakeResp(201)
    env = {"APIFY_TOKEN": "t", "ACTOR_RUN_ID": "run1"}
    assert server.charge("req9", env=env, post=post) is True
    assert seen["url"] == "https://api.apify.com/v2/actor-runs/run1/charge"
    assert seen["json"] == {"eventName": "site-checked", "count": 1, "requestId": "req9"}
    assert seen["headers"]["idempotency-key"] == "req9:site-checked"
    assert server.charge(None, env=env, post=lambda *a, **k: FakeResp(400, "no")) is False
    assert server.charge("x", env={}, post=post) is None

    def boom(*a, **k):
        raise httpx.ConnectError("down")
    assert server.charge("x", env=env, post=boom) is False


def test_started_by_server():
    assert main.started_by_server({"APIFY_META_ORIGIN": "STANDBY"})
    assert not main.started_by_server({"APIFY_META_ORIGIN": "API"})
    assert not main.started_by_server({})
