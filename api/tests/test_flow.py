"""End to end: sign in, add an app, verify, worker run, notifications to every member and the webhook, scheduler, diff."""
from helpers import A, STATE, claim, create_app, finish, link_param, outbox, sign_in, sql, verify


def test_end_to_end_monitoring(client, local_webhooks):
    owner = sign_in(client, "owner@example.com")
    client.patch(f"/admin/workspaces/{owner.wid}", json={"plan": "maker"}, headers=A)
    client.post(f"/workspaces/{owner.wid}/invites", json={"email": "dev@example.com"}, headers=owner.h)
    dev = sign_in(client, "dev@example.com", invite=link_param(outbox("dev@example.com")[-1], "invite"))
    assert dev.finish["invite"]["accepted"]
    r = client.patch(f"/workspaces/{owner.wid}", json={"webhook_url": local_webhooks}, headers=owner.h)
    assert r.status_code == 200 and r.json()["webhook_url"] == local_webhooks

    a = create_app(client, dev, "acme/shop", wid=owner.wid, client_label="Bakery", schedule="weekly")
    cid1 = verify(client, dev, a)["check_id"]

    # worker claims the first check and reports two leaking tables
    job = claim(client)
    assert job == {"id": str(cid1), "repo": "acme/shop"}
    finish(client, cid1, "done", ["profiles", "orders"])
    for who in ("owner@example.com", "dev@example.com"):
        m = outbox(who)[-1]
        assert m["subject"] == "New leak found in acme/shop (Bakery)"
        assert "profiles, orders" in m["text"] and f"https://patchlabs.test/check?id={cid1}" in m["text"]
        assert m["content_type"] == "multipart/alternative" and "<a href=\"https://patchlabs.test/check?id=" in m["html"]
    assert len(STATE.hooks) == 1
    hook = STATE.hooks[0]["body"]
    assert hook["event"] == "check.finished" and "acme/shop (Bakery)" in hook["text"] and str(cid1) in hook["text"]
    assert hook["check"] == {"id": str(cid1), "app_id": a["id"], "repo": "acme/shop", "status": "done",
                             "tables_leaking": ["profiles", "orders"], "url": f"https://patchlabs.test/check?id={cid1}",
                             "new_leaks": ["profiles", "orders"], "fixed": [], "suppressed": []}
    kinds = [e["kind"] for e in sql("SELECT kind FROM check_events WHERE check_id = %s ORDER BY id", (cid1,))]
    assert kinds.count("email_sent") == 2 and "webhook_sent" in kinds
    assert [e["kind"] for e in client.get(f"/checks/{cid1}").json()["events"]] == ["requested", "started", "done"]

    # nothing due yet: the scheduler queues nothing
    assert claim(client) is None
    # a week passes: the scheduler queues a 'scheduled' check inside /worker/claim and advances next_check_at by 7 days
    sql("UPDATE apps SET next_check_at = now() - interval '1 minute'")
    job = claim(client)
    assert job and job["repo"] == "acme/shop"
    cid2 = job["id"]
    assert sql("SELECT trigger FROM checks WHERE id = %s", (cid2,))[0]["trigger"] == "scheduled"
    days = float(sql("SELECT extract(epoch FROM next_check_at - now()) / 86400 AS d FROM apps")[0]["d"])
    assert 6.9 < days <= 7
    assert claim(client) is None  # not queued twice

    finish(client, cid2, "done", ["orders", "messages"])
    m = outbox("owner@example.com")[-1]
    assert m["subject"] == "New leak found in acme/shop (Bakery)"
    assert "New leaks since the last check: messages" in m["text"] and "Fixed since the last check: profiles" in m["text"]
    d = client.get(f"/apps/{a['id']}", headers=owner.h).json()
    assert d["diff"]["new_leaks"] == ["messages"] and d["diff"]["fixed"] == ["profiles"] and d["diff"]["still_leaking"] == ["orders"]
    assert d["diff"]["to_check_id"] == cid2 and d["diff"]["from_check_id"] == str(cid1)
    assert [c["trigger"] for c in d["checks"]] == ["scheduled", "verify"]

    # run now, everything fixed: no "new leak" subject
    r = client.post(f"/apps/{a['id']}/checks", headers=owner.h)
    cid3 = claim(client)["id"]
    assert cid3 == r.json()["check_id"]
    finish(client, cid3, "no_leaks")
    m = outbox("dev@example.com")[-1]
    assert m["subject"] == "PatchLabs check finished for acme/shop (Bakery)" and "no data leaks found" in m["text"]
    assert STATE.hooks[-1]["body"]["check"]["status"] == "no_leaks"
    assert client.get(f"/apps/{a['id']}", headers=owner.h).json()["diff"]["fixed"] == ["orders", "messages"]


def test_failed_app_check_sends_webhook_but_no_email(client, local_webhooks):
    u = sign_in(client, "owner@example.com")
    client.patch(f"/workspaces/{u.wid}", json={"webhook_url": local_webhooks}, headers=u.h)
    a = create_app(client, u)
    cid = verify(client, u, a)["check_id"]
    claim(client)
    n = len(outbox("owner@example.com"))
    finish(client, cid, "failed")
    assert len(outbox("owner@example.com")) == n
    assert STATE.hooks[-1]["body"]["check"]["status"] == "failed"
    assert client.get(f"/apps/{a['id']}", headers=u.h).json()["last_check"]["status"] == "failed"


def test_scheduler_skips_off_unverified_and_open(client):
    u = sign_in(client, "owner@example.com")
    client.patch(f"/admin/workspaces/{u.wid}", json={"plan": "agency"}, headers=A)
    off = create_app(client, u, "acme/off")
    verify(client, u, off)
    client.patch(f"/apps/{off['id']}", json={"schedule": "off"}, headers=u.h)
    create_app(client, u, "acme/unverified")
    busy = create_app(client, u, "acme/busy")
    verify(client, u, busy)  # has an open (queued) check
    sql("UPDATE checks SET status = 'no_leaks', finished_at = now() WHERE app_id = %s", (off["id"],))
    sql("UPDATE apps SET next_check_at = now() - interval '1 day'")
    first = claim(client)
    assert first["repo"] == "acme/busy"
    assert claim(client) is None
    assert sql("SELECT count(*) AS n FROM checks WHERE trigger = 'scheduled'")[0]["n"] == 0


def test_webhook_failure_never_loses_result(client, local_webhooks):
    u = sign_in(client, "owner@example.com")
    client.patch(f"/workspaces/{u.wid}", json={"webhook_url": local_webhooks.replace("/hook", "/missing")}, headers=u.h)
    a = create_app(client, u)
    cid = verify(client, u, a)["check_id"]
    claim(client)
    finish(client, cid, "no_leaks")
    assert client.get(f"/checks/{cid}").json()["status"] == "no_leaks"
    assert sql("SELECT detail FROM check_events WHERE check_id = %s AND kind = 'webhook_sent'", (cid,))[0]["detail"] == "404"
