"""Webhooks: https only, no private/loopback/link-local targets (checked after DNS), pinned to the checked address, 5 s timeout."""
import socket, time

import pytest

import core
from helpers import STATE, STUB, sign_in


@pytest.fixture
def owner(client):
    return sign_in(client, "owner@example.com")


def set_hook(client, u, url):
    return client.patch(f"/workspaces/{u.wid}", json={"webhook_url": url}, headers=u.h)


@pytest.mark.parametrize("url", [
    "http://hooks.example.com/x", "ftp://1.1.1.1/x", "hooks.slack.com/x", "https://", "https://127.0.0.1/x", "https://localhost/x",
    "https://10.0.0.5/x", "https://172.16.3.4/x", "https://192.168.1.1/x", "https://169.254.169.254/latest/meta-data",
    "https://[::1]/x", "https://[fe80::1]/x", "https://[fc00::1]/x", "https://[::ffff:127.0.0.1]/x", "https://0.0.0.0/x",
    "https://100.64.0.1/x", "https://0x7f000001/x", "https://2130706433/x", "https://224.0.0.1/x", "https://name.invalid/x",
    "https://1.1.1.1:99999/x"])
def test_ssrf_targets_rejected(client, owner, url):
    r = set_hook(client, owner, url)
    assert r.status_code == 422, url
    assert client.get(f"/workspaces/{owner.wid}", headers=owner.h).json()["webhook_url"] is None


def test_public_https_accepted_and_cleared(client, owner):
    r = set_hook(client, owner, "https://1.1.1.1/hooks/abc")
    assert r.status_code == 200 and r.json()["webhook_url"] == "https://1.1.1.1/hooks/abc"
    assert set_hook(client, owner, "").json()["webhook_url"] is None
    set_hook(client, owner, "https://1.1.1.1/hooks/abc")
    assert set_hook(client, owner, None).json()["webhook_url"] is None


def fake_dns(monkeypatch, mapping):
    real = socket.getaddrinfo

    def gai(host, port, *a, **kw):
        if host in mapping:
            return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in mapping[host]]
        return real(host, port, *a, **kw)
    monkeypatch.setattr(core.socket, "getaddrinfo", gai)


def test_hostnames_checked_after_dns_resolution(client, owner, monkeypatch):
    fake_dns(monkeypatch, {"evil.example": ["10.1.2.3"], "mixed.example": ["8.8.8.8", "127.0.0.1"], "ok.example": ["8.8.8.8"],
                           "meta.example": ["169.254.169.254"], "v6.example": ["::1"]})
    for host in ("evil.example", "mixed.example", "meta.example", "v6.example"):
        assert set_hook(client, owner, f"https://{host}/x").status_code == 422, host
    assert set_hook(client, owner, "https://ok.example/x").status_code == 200


def test_dns_rebinding_blocked_at_send_time(client, owner, monkeypatch):
    fake_dns(monkeypatch, {"rebind.example": ["8.8.8.8"]})
    assert set_hook(client, owner, "https://rebind.example/x").status_code == 200
    fake_dns(monkeypatch, {"rebind.example": ["127.0.0.1"]})
    r = client.post(f"/workspaces/{owner.wid}/webhook/test", headers=owner.h).json()
    assert r["ok"] is False and r["status_code"] is None and "private" in r["detail"]


def test_members_cannot_set_webhook(client, owner):
    other = sign_in(client, "other@example.com")
    r = client.patch(f"/workspaces/{owner.wid}", json={"webhook_url": "https://1.1.1.1/x"}, headers=other.h)
    assert r.status_code == 404


def test_webhook_test_requires_url(client, owner):
    assert client.post(f"/workspaces/{owner.wid}/webhook/test", headers=owner.h).status_code == 409
    assert client.post(f"/workspaces/{owner.wid}/webhook/test").status_code == 401


def test_webhook_test_posts_slack_compatible_payload(client, owner, local_webhooks):
    set_hook(client, owner, local_webhooks)
    r = client.post(f"/workspaces/{owner.wid}/webhook/test", headers=owner.h).json()
    assert r == {"ok": True, "status_code": 200, "format": "json"}
    body = STATE.hooks[-1]["body"]
    assert body["event"] == "test" and body["text"].startswith("PatchLabs: webhooks for")
    assert STATE.hooks[-1]["headers"]["Content-Type"] == "application/json"
    STATE.hook_status = 500
    assert client.post(f"/workspaces/{owner.wid}/webhook/test", headers=owner.h).json() == {"ok": False, "status_code": 500, "format": "json"}


def test_send_is_pinned_to_the_checked_address(client, owner, local_webhooks, monkeypatch):
    port = STUB.rsplit(":", 1)[1]
    fake_dns(monkeypatch, {"hooks.example": ["127.0.0.1"]})
    set_hook(client, owner, f"http://hooks.example:{port}/hook")
    assert client.post(f"/workspaces/{owner.wid}/webhook/test", headers=owner.h).json()["ok"] is True
    assert STATE.hooks[-1]["host"] == f"hooks.example:{port}"


def test_redirects_are_not_followed(client, owner, local_webhooks):
    STATE.hook_status = 302
    set_hook(client, owner, local_webhooks)
    assert client.post(f"/workspaces/{owner.wid}/webhook/test", headers=owner.h).json() == {"ok": False, "status_code": 302, "format": "json"}


def test_webhook_times_out_after_five_seconds(client, owner, local_webhooks):
    set_hook(client, owner, local_webhooks.replace("/hook", "/slow"))
    t = time.time()
    r = client.post(f"/workspaces/{owner.wid}/webhook/test", headers=owner.h).json()
    assert r["ok"] is False and r["status_code"] is None
    assert 4.5 < time.time() - t < 6.4


def test_ip_allowed_unit():
    assert core.ip_allowed("8.8.8.8") and core.ip_allowed("2606:4700:4700::1111")
    for ip in ("127.0.0.1", "10.0.0.1", "192.168.0.1", "172.31.255.255", "169.254.1.1", "::1", "fe80::1%eth0", "::ffff:10.0.0.1",
               "100.64.0.1", "0.0.0.0", "fd00::1", "239.1.1.1"):
        assert not core.ip_allowed(ip), ip
