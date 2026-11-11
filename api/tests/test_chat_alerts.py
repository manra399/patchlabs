"""Native chat alerts: Slack, Discord and Teams get their own message format; other URLs keep the signed JSON."""
import socket

import pytest

import alerts
import core
from helpers import A, STATE, STUB, claim, finish_with, outbox, sign_in, verified_app

FINDINGS = [{"id": "PL-023", "line": "code", "severity": "high", "title": "lodash 4.17.15 has a known vulnerability", "object": "package.json"},
            {"id": "PL-001", "line": "lab", "severity": "critical", "title": "Anyone can read profiles", "object": "public.profiles"},
            {"id": "PL-018", "line": "code", "severity": "low", "title": "Sign-ups need no email confirmation", "object": "supabase/config.toml"},
            {"id": "PL-001", "line": "lab", "severity": "critical", "title": "Anyone can read shops", "object": "public.shops"}]
PORT = STUB.rsplit(":", 1)[1]


@pytest.mark.parametrize("url,kind", [
    ("https://hooks.slack.com/services/T000/B000/XXXX", "slack"),
    ("https://hooks.slack.com/workflows/T000/A000/1/abc", "slack"),
    ("https://discord.com/api/webhooks/123/abc", "discord"),
    ("https://discordapp.com/api/webhooks/123/abc", "discord"),
    ("https://canary.discord.com/api/webhooks/123/abc", "discord"),
    ("https://acme.webhook.office.com/webhookb2/abc@def/IncomingWebhook/x/y", "teams"),
    ("https://default123.ab.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/x/triggers/manual/paths/invoke",
     "teams"),
    ("https://prod-01.westus.logic.azure.com/workflows/x/triggers/manual/paths/invoke", "json"),  # any Logic App: needs format=teams
    ("https://hooks.slack.com.evil.example/services/x", "json"),
    ("https://evil.example/hooks.slack.com/services/x", "json"),
    ("https://discord.com/channels/1/2", "json"),
    ("https://example.com/hook", "json"),
])
def test_detect(url, kind):
    assert alerts.detect(url) == kind


def test_forced_format_wins():
    assert alerts.kind("https://example.com/hook", "slack") == "slack"
    assert alerts.kind("https://hooks.slack.com/services/x", "json") == "json"
    assert alerts.kind("https://hooks.slack.com/services/x", "auto") == "slack"


@pytest.fixture
def chat_dns(monkeypatch, local_webhooks):
    """hooks.slack.com, discord.com and acme.webhook.office.com resolve to the local stub."""
    real = socket.getaddrinfo
    hosts = {"hooks.slack.com", "discord.com", "acme.webhook.office.com"}

    def gai(host, port, *a, **kw):
        if host in hosts:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
        return real(host, port, *a, **kw)
    monkeypatch.setattr(core.socket, "getaddrinfo", gai)
    return {"slack": f"http://hooks.slack.com:{PORT}/services/T000/B000/XXXX", "discord": f"http://discord.com:{PORT}/api/webhooks/1/abc",
            "teams": f"http://acme.webhook.office.com:{PORT}/webhookb2/abc/IncomingWebhook/x/y", "json": local_webhooks}


def finished_check(client, u, url, fmt=None):
    body = {"webhook_url": url, **({"webhook_format": fmt} if fmt else {})}
    w = client.patch(f"/workspaces/{u.wid}", json=body, headers=u.h).json()
    a, cid = verified_app(client, u, client_label="Bakery")
    claim(client)
    finish_with(client, cid, FINDINGS, tables=["profiles", "shops"])
    return w, a, cid


def test_slack_message(client, chat_dns):
    u = sign_in(client, "owner@example.com")
    w, a, cid = finished_check(client, u, chat_dns["slack"])
    assert w["webhook_kind"] == "slack" and w["webhook_format"] == "auto"
    hook = STATE.hooks[-1]
    body = hook["body"]
    assert hook["path"] == "/services/T000/B000/XXXX" and hook["headers"]["X-PatchLabs-Signature"].startswith("v1=")
    assert body["text"].startswith("PatchLabs: acme/shop (Bakery): ") and f"/check?id={cid}" in body["text"]
    blocks = body["blocks"]
    assert blocks[0] == {"type": "header", "text": {"type": "plain_text", "text": "PatchLabs: acme/shop (Bakery)", "emoji": False}}
    assert "Leaks found and a tested fix is ready." in blocks[1]["text"]["text"] and "profiles, shops" in blocks[1]["text"]["text"]
    fields = {f["text"].split("\n")[0]: f["text"].split("\n")[1] for f in blocks[2]["fields"]}
    assert fields == {"*Critical*": "2", "*High*": "1", "*Medium*": "0", "*Low*": "1", "*Info*": "0"}
    top = blocks[3]["text"]["text"].split("\n")
    assert top[0] == "*Top findings*" and top[1].startswith("• PL-001 (critical)") and top[-1].startswith("• PL-018 (low)")
    assert blocks[4]["elements"][0]["url"] == f"https://patchlabs.test/check?id={cid}"


def test_discord_message(client, chat_dns):
    u = sign_in(client, "owner@example.com")
    finished_check(client, u, chat_dns["discord"])
    body = STATE.hooks[-1]["body"]
    assert body["allowed_mentions"] == {"parse": []} and body["username"] == "PatchLabs"
    e = body["embeds"][0]
    assert e["title"] == "PatchLabs: acme/shop (Bakery)" and e["url"].startswith("https://patchlabs.test/check?id=")
    assert e["color"] == alerts.COLOURS["critical"] and "**Top findings**" in e["description"]
    assert {f["name"]: f["value"] for f in e["fields"]} == {"Critical": "2", "High": "1", "Medium": "0", "Low": "1", "Info": "0"}


def test_teams_message(client, chat_dns):
    u = sign_in(client, "owner@example.com")
    finished_check(client, u, chat_dns["teams"])
    body = STATE.hooks[-1]["body"]
    assert body["type"] == "message"
    att = body["attachments"][0]
    assert att["contentType"] == "application/vnd.microsoft.card.adaptive"
    card = att["content"]
    assert card["type"] == "AdaptiveCard" and card["body"][0]["text"] == "PatchLabs: acme/shop (Bakery)"
    facts = {f["title"]: f["value"] for f in card["body"][2]["facts"]}
    assert facts["Critical"] == "2" and facts["High"] == "1"
    assert card["actions"][0]["type"] == "Action.OpenUrl" and card["actions"][0]["url"].startswith("https://patchlabs.test/check?id=")


def test_generic_url_keeps_signed_json(client, chat_dns):
    u = sign_in(client, "owner@example.com")
    w, a, cid = finished_check(client, u, chat_dns["json"])
    assert w["webhook_kind"] == "json"
    body = STATE.hooks[-1]["body"]
    assert body["event"] == "check.finished" and body["check"]["id"] == str(cid) and "blocks" not in body


def test_forced_format_and_suppressed_tables_left_out(client, local_webhooks):
    u = sign_in(client, "owner@example.com")
    w, a, cid = finished_check(client, u, local_webhooks, fmt="slack")
    assert w["webhook_kind"] == "slack" and "blocks" in STATE.hooks[-1]["body"]
    client.post(f"/checks/{cid}/decision", json={"action": "reject", "tables": ["shops"]}, headers=u.h)
    cid2 = client.post(f"/apps/{a['id']}/checks", headers=u.h).json()["check_id"]
    claim(client)
    finish_with(client, cid2, FINDINGS, tables=["profiles", "shops"])
    text = str(STATE.hooks[-1]["body"])
    assert "Anyone can read shops" not in text and "Marked as intended (no alert): shops" in text
    # switching back to JSON
    w = client.patch(f"/workspaces/{u.wid}", json={"webhook_format": "json"}, headers=u.h).json()
    assert w["webhook_kind"] == "json"
    assert client.patch(f"/workspaces/{u.wid}", json={"webhook_format": "irc"}, headers=u.h).status_code == 422


@pytest.mark.parametrize("kind", ["slack", "discord", "teams", "json"])
def test_send_test_uses_the_platform_format(client, chat_dns, kind):
    u = sign_in(client, "owner@example.com")
    client.patch(f"/workspaces/{u.wid}", json={"webhook_url": chat_dns[kind]}, headers=u.h)
    r = client.post(f"/workspaces/{u.wid}/webhook/test", headers=u.h).json()
    assert r == {"ok": True, "status_code": 200, "format": kind}
    body = STATE.hooks[-1]["body"]
    text = str(body)
    assert "webhooks for owner's workspace are working" in text or "webhooks for owner" in text
    if kind == "json":
        assert body["event"] == "test"
    else:
        assert "Critical" not in text  # a test message has no severity table


def test_chat_urls_still_ssrf_checked(client, monkeypatch):
    """A chat host that resolves to a private address is refused like any other."""
    u = sign_in(client, "owner@example.com")
    real = socket.getaddrinfo
    monkeypatch.setattr(core.socket, "getaddrinfo", lambda h, p, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", p))]
                        if h == "hooks.slack.com" else real(h, p, *a, **k))
    r = client.patch(f"/workspaces/{u.wid}", json={"webhook_url": "https://hooks.slack.com/services/T/B/X"}, headers=u.h)
    assert r.status_code == 422 and "private" in r.json()["detail"]
    assert A  # imported for parity


def test_failed_check_alert_has_no_findings(client, chat_dns):
    u = sign_in(client, "owner@example.com")
    client.patch(f"/workspaces/{u.wid}", json={"webhook_url": chat_dns["slack"]}, headers=u.h)
    a, cid = verified_app(client, u)
    claim(client)
    client.post(f"/worker/checks/{cid}/result", headers={"Authorization": "Bearer worker-test-token"}, json={"status": "failed", "error": "x"})
    body = STATE.hooks[-1]["body"]
    assert "could not finish" in body["text"] and all(b["type"] != "section" or "Top findings" not in str(b) for b in body["blocks"])


def test_failed_and_needs_review_checks_email_the_founder(client, chat_dns):
    u = sign_in(client, "owner@example.com")
    a, cid = verified_app(client, u)
    claim(client)
    client.post(f"/worker/checks/{cid}/result", headers={"Authorization": "Bearer worker-test-token"}, json={"status": "failed", "error": "lab timeout"})
    m = [x for x in outbox() if x["subject"].startswith("Check failed:")]
    assert m and "lab timeout" in m[-1]["text"] and cid in m[-1]["text"]


def test_watchdog_emails_once_when_worker_stops_with_work_waiting(client):
    import watchdog
    from helpers import sql
    u = sign_in(client, "owner@example.com")
    verified_app(client, u)  # leaves a queued check
    sql("DELETE FROM kv WHERE key IN ('worker_heartbeat', 'watchdog_alert')")
    with core.pool.connection() as c:
        assert watchdog.check_once(c)            # no heartbeat ever, a check waiting: alert
        assert watchdog.check_once(c) is None    # same stall: no second email inside the gap
    assert [m for m in outbox() if m["subject"].startswith("PatchLabs worker has stopped")]
    sql("UPDATE kv SET updated_at = now() - interval '1 day' WHERE key = 'watchdog_alert'")
    sql("INSERT INTO kv (key, value) VALUES ('worker_heartbeat', 'ok') ON CONFLICT (key) DO UPDATE SET updated_at = now()")
    with core.pool.connection() as c:
        assert watchdog.check_once(c) is None    # worker alive again: quiet
