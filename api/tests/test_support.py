"""Support tickets: raising, threads, permissions, status changes, emails, limits, export and account deletion."""
import uuid

from helpers import A, W, link_param, outbox, sign_in, sql, create_app

FOUNDER = "manraj@patchlabs.dev"


def team(client):
    """An owner on the maker plan with a teammate (member) in the same workspace."""
    u = sign_in(client, "owner@example.com")
    client.patch(f"/admin/workspaces/{u.wid}", json={"plan": "maker"}, headers=A)
    client.post(f"/workspaces/{u.wid}/invites", json={"email": "bob@example.com"}, headers=u.h)
    bob = sign_in(client, "bob@example.com", invite=link_param(outbox("bob@example.com")[-1], "invite"))
    return u, bob


def raise_ticket(client, u, wid=None, **kw):
    body = {"subject": "Report says profiles leak", "category": "finding", "message": "Is this real?\n\nThanks", **kw}
    r = client.post(f"/workspaces/{wid or u.wid}/support/tickets", json=body, headers=u.h)
    assert r.status_code == 201, r.text
    return r.json()


def test_raise_ticket_list_and_emails(client):
    u = sign_in(client, "owner@example.com")
    client.patch("/me", json={"name": "Olive"}, headers=u.h)
    a = create_app(client, u)
    t = raise_ticket(client, u, app_id=a["id"], priority="urgent")
    assert t["status"] == "open" and t["priority"] == "urgent" and t["category"] == "finding"
    assert t["app"] == {"id": a["id"], "repo": "acme/shop"} and t["created_by"] == "Olive" and t["number"] >= 1
    assert [(m["author"], m["kind"], m["by"], m["body"]) for m in t["messages"]] == [("customer", "message", "Olive", "Is this real?\n\nThanks")]
    admin_mail = outbox(FOUNDER)[-1]
    assert admin_mail["subject"] == f"New ticket: URGENT [PatchLabs #{t['number']}] Report says profiles leak"
    assert "owner@example.com" in admin_mail["text"] and "Is this real?" in admin_mail["text"] and "App: acme/shop" in admin_mail["text"]
    assert f"https://patchlabs.test/admin?ticket={t['id']}" in admin_mail["text"]
    mine = outbox("owner@example.com")[-1]
    assert mine["subject"] == f"We've got your ticket: [PatchLabs #{t['number']}] Report says profiles leak"  # no URGENT for customers
    assert f"https://patchlabs.test/app/support?id={t['id']}" in mine["text"] and f'href="https://patchlabs.test/app/support?id={t["id"]}"' in mine["html"]
    r = client.get(f"/workspaces/{u.wid}/support/tickets", headers=u.h).json()
    assert [x["id"] for x in r["tickets"]] == [t["id"]] and r["tickets"][0]["message_count"] == 1 and r["tickets"][0]["last_from"] == "customer"
    assert r["counts"] == {"open": 1, "waiting_on_customer": 0, "resolved": 0, "closed": 0}
    assert client.get(f"/workspaces/{u.wid}/support/tickets?status=active", headers=u.h).json()["tickets"]
    assert client.get(f"/workspaces/{u.wid}/support/tickets?status=closed", headers=u.h).json()["tickets"] == []
    assert client.get(f"/workspaces/{u.wid}/support/tickets?status=bogus", headers=u.h).status_code == 422


def test_permissions(client):
    u, bob = team(client)
    t = raise_ticket(client, u)
    tid = t["id"]
    # any member of the workspace sees and answers the workspace's tickets
    assert [x["id"] for x in client.get(f"/workspaces/{u.wid}/support/tickets", headers=bob.h).json()["tickets"]] == [tid]
    assert client.get(f"/support/tickets/{tid}", headers=bob.h).status_code == 200
    assert client.post(f"/support/tickets/{tid}/messages", json={"body": "Me too"}, headers=bob.h).status_code == 201
    # a different workspace never sees it: 404, as if it didn't exist
    eve = sign_in(client, "eve@example.com")
    assert client.get(f"/workspaces/{u.wid}/support/tickets", headers=eve.h).status_code == 404
    assert client.post(f"/workspaces/{u.wid}/support/tickets", json={"subject": "x", "category": "bug", "message": "x"}, headers=eve.h).status_code == 404
    for method, path, kw in (("get", f"/support/tickets/{tid}", {}), ("post", f"/support/tickets/{tid}/messages", {"json": {"body": "hi"}}),
                             ("post", f"/support/tickets/{tid}/close", {})):
        assert getattr(client, method)(path, headers=eve.h, **kw).status_code == 404
        assert getattr(client, method)(path, **kw).status_code == 401  # anonymous
    assert client.get(f"/workspaces/{eve.wid}/support/tickets", headers=eve.h).json()["tickets"] == []
    assert client.get(f"/support/tickets/{uuid.uuid4()}", headers=u.h).status_code == 404
    assert client.get("/support/tickets/not-a-uuid", headers=u.h).status_code == 404
    # admin endpoints: the admin token only, never a session or the worker token
    for method, path, kw in (("get", "/admin/support/tickets", {}), ("get", f"/admin/support/tickets/{tid}", {}),
                             ("post", f"/admin/support/tickets/{tid}/messages", {"json": {"body": "hi"}}),
                             ("patch", f"/admin/support/tickets/{tid}", {"json": {"status": "closed"}})):
        for h in ({}, u.h, W):
            assert getattr(client, method)(path, headers=h, **kw).status_code == 401, (method, path, h)
    assert client.get(f"/support/tickets/{tid}", headers=u.h).json()["status"] == "open"
    # someone who leaves the workspace loses access
    client.delete(f"/workspaces/{u.wid}/members/{bob.user['id']}", headers=bob.h)
    assert client.get(f"/support/tickets/{tid}", headers=bob.h).status_code == 404


def test_status_transitions_and_emails(client):
    u, bob = team(client)
    t = raise_ticket(client, bob, wid=u.wid)
    tid, n = t["id"], t["number"]
    sent = len(outbox())
    # support reply: waiting on the customer, emailed to whoever raised it
    r = client.post(f"/admin/support/tickets/{tid}/messages", json={"body": "Yes, it's real. Apply the fix."}, headers=A)
    assert r.status_code == 201 and r.json()["status"] == "waiting_on_customer"
    new = outbox()[sent:]
    assert [m["to"] for m in new] == ["bob@example.com"]
    assert new[0]["subject"] == f"Re: [PatchLabs #{n}] Report says profiles leak" and "Yes, it's real" in new[0]["text"]
    # customer reply: back to open, emailed to the founder
    sent = len(outbox())
    r = client.post(f"/support/tickets/{tid}/messages", json={"body": "Applied, thanks"}, headers=u.h)
    assert r.status_code == 201, r.text
    r = r.json()
    assert r["status"] == "open" and r["last_from"] == "customer"
    new = outbox()[sent:]
    assert [m["to"] for m in new] == [FOUNDER] and "owner@example.com replied" in new[0]["text"] and "opens it again" not in new[0]["text"]
    # reply and resolve in one go: a visible status event, and the email says so
    sent = len(outbox())
    r = client.post(f"/admin/support/tickets/{tid}/messages", json={"body": "Great.", "status": "resolved"}, headers=A).json()
    assert r["status"] == "resolved" and r["closed_at"] and r["messages"][-1]["kind"] == "status" and r["messages"][-1]["body"] == "resolved"
    assert "marked this ticket resolved" in outbox()[sent]["text"]
    # a customer reply reopens a resolved ticket and says so
    sent = len(outbox())
    r = client.post(f"/support/tickets/{tid}/messages", json={"body": "Actually, one more thing"}, headers=bob.h).json()
    assert r["status"] == "open" and r["closed_at"] is None
    assert [(m["kind"], m["body"]) for m in r["messages"][-2:]] == [("message", "Actually, one more thing"), ("status", "open")]
    assert "opens it again" in outbox()[sent]["text"]
    # the customer closes it; closing twice is harmless; replying opens it again
    r = client.post(f"/support/tickets/{tid}/close", headers=bob.h).json()
    assert r["status"] == "closed" and r["messages"][-1] == {**r["messages"][-1], "kind": "status", "body": "closed", "author": "customer"}
    before = len(r["messages"])
    assert len(client.post(f"/support/tickets/{tid}/close", headers=bob.h).json()["messages"]) == before
    assert client.post(f"/support/tickets/{tid}/messages", json={"body": "Reopen"}, headers=bob.h).json()["status"] == "open"
    # admin status and priority changes
    r = client.patch(f"/admin/support/tickets/{tid}", json={"status": "waiting_on_customer", "priority": "urgent"}, headers=A).json()
    assert r["status"] == "waiting_on_customer" and r["priority"] == "urgent"
    assert client.patch(f"/admin/support/tickets/{tid}", json={"status": "done"}, headers=A).status_code == 422
    assert client.patch(f"/admin/support/tickets/{tid}", json={"priority": "high"}, headers=A).status_code == 422
    assert client.post(f"/admin/support/tickets/{tid}/messages", json={"body": "x", "status": "nope"}, headers=A).status_code == 422
    assert client.patch(f"/admin/support/tickets/{uuid.uuid4()}", json={"status": "closed"}, headers=A).status_code == 404
    # support messages are signed as PatchLabs support, never the founder's address
    msgs = client.get(f"/support/tickets/{tid}", headers=u.h).json()["messages"]
    assert {m["by"] for m in msgs if m["author"] == "support"} == {"PatchLabs support"}


def test_internal_notes_are_admin_only(client):
    u = sign_in(client, "owner@example.com")
    t = raise_ticket(client, u)
    before = client.get(f"/support/tickets/{t['id']}", headers=u.h).json()
    sent = len(outbox())
    r = client.post(f"/admin/support/tickets/{t['id']}/messages", json={"body": "Customer is on the free plan; check repo size.", "internal": True},
                    headers=A).json()
    assert r["messages"][-1]["kind"] == "note" and r["status"] == "open"
    assert len(outbox()) == sent  # notes are never emailed
    after = client.get(f"/support/tickets/{t['id']}", headers=u.h).json()
    assert after == before and "free plan" not in str(after)
    assert "free plan" not in client.get(f"/workspaces/{u.wid}/support/tickets", headers=u.h).text
    assert "free plan" not in client.get("/me/export", headers=u.h).text
    full = client.get(f"/admin/support/tickets/{t['id']}", headers=A).json()
    assert [m["kind"] for m in full["messages"]] == ["message", "note"] and full["messages"][0]["by_email"] == "owner@example.com"
    assert full["workspace_name"] and full["created_by_email"] == "owner@example.com" and full["needs_reply"] is True


def test_limits_and_cleaning(client):
    u = sign_in(client, "owner@example.com")
    url = f"/workspaces/{u.wid}/support/tickets"
    ok = {"subject": "Hello", "category": "bug", "message": "Hi"}
    assert client.post(url, json={**ok, "subject": "x" * 201}, headers=u.h).json()["detail"] == "Keep the subject to 200 characters."
    assert client.post(url, json={**ok, "subject": "x" * 200}, headers=u.h).status_code == 201
    assert client.post(url, json={**ok, "message": "x" * 10_001}, headers=u.h).json()["detail"] == "Keep each message to 10,000 characters."
    assert client.post(url, json={**ok, "message": "x" * 10_000}, headers=u.h).status_code == 201
    assert client.post(url, json={**ok, "subject": " \n\t "}, headers=u.h).status_code == 422
    assert client.post(url, json={**ok, "message": "\x00\x07 \n "}, headers=u.h).status_code == 422
    assert client.post(url, json={**ok, "category": "sales"}, headers=u.h).status_code == 422
    assert client.post(url, json={**ok, "priority": "critical"}, headers=u.h).status_code == 422
    assert client.post(url, json={**ok, "message": "x" * 50_000}, headers=u.h).status_code == 422
    # control characters, bidi overrides and zero-width characters go; line breaks in messages stay
    t = client.post(url, json={**ok, "subject": "Billing\u202e\x00 \r\nissue\u200b", "message": "Line 1\r\nLine 2\x07\tend\u2066\n\n\n\n\n\nLast  \n"},
                    headers=u.h).json()
    assert t["subject"] == "Billing issue" and t["messages"][0]["body"] == "Line 1\nLine 2    end\n\n\nLast"
    assert "\n" not in outbox(FOUNDER)[-1]["subject"]
    # HTML in user text is escaped in the emails, and stored as plain text
    t = client.post(url, json={**ok, "subject": "<img src=x onerror=alert(1)>", "message": "<script>alert('x')</script>\n<a href=\"https://evil.example\">click</a>"},
                    headers=u.h).json()
    assert t["subject"] == "<img src=x onerror=alert(1)>"
    for m in (outbox(FOUNDER)[-1], outbox("owner@example.com")[-1]):
        assert "<script>" not in m["html"] and "&lt;script&gt;" in m["html"] and "<img" not in m["html"] and 'href="https://evil' not in m["html"]
    # an app link must be an app in this workspace
    other = sign_in(client, "eve@example.com")
    theirs = create_app(client, other, "eve/app")
    assert client.post(url, json={**ok, "app_id": theirs["id"]}, headers=u.h).status_code == 422
    assert client.post(url, json={**ok, "app_id": "nope"}, headers=u.h).status_code == 404
    # 20 tickets a day per person (counted in the usage log, so deleting doesn't give them back)
    made = sql("SELECT count(*) AS n FROM usage_events WHERE kind = 'support_ticket' AND subject = %s", (u.user["id"],))[0]["n"]
    for _ in range(20 - made):
        sql("INSERT INTO usage_events (kind, subject) VALUES ('support_ticket', %s)", (u.user["id"],))
    r = client.post(url, json=ok, headers=u.h)
    assert r.status_code == 429 and "20 tickets" in r.json()["detail"]
    # the limit is per person: a teammate or another user can still raise one
    assert client.post(f"/workspaces/{other.wid}/support/tickets", json=ok, headers=other.h).status_code == 201
    # replies have their own daily cap
    t = client.get(url, headers=u.h).json()["tickets"][0]
    for _ in range(200):
        sql("INSERT INTO usage_events (kind, subject) VALUES ('support_reply', %s)", (u.user["id"],))
    assert client.post(f"/support/tickets/{t['id']}/messages", json={"body": "hi"}, headers=u.h).status_code == 429
    assert client.post(f"/support/tickets/{t['id']}/messages", json={"body": "x" * 10_001}, headers=u.h).status_code == 422


def test_admin_list_filters(client):
    u = sign_in(client, "owner@example.com")
    eve = sign_in(client, "eve@example.com")
    a = raise_ticket(client, u, subject="Card was charged twice", category="billing", priority="urgent")
    b = raise_ticket(client, eve, subject="Fix did not apply", category="fix")
    c = raise_ticket(client, eve, subject="Delete my workspace", category="account")
    client.post(f"/admin/support/tickets/{b['id']}/messages", json={"body": "Try again"}, headers=A)
    client.post(f"/support/tickets/{c['id']}/close", headers=eve.h)
    r = client.get("/admin/support/tickets", headers=A).json()
    assert [t["id"] for t in r["tickets"]] == [a["id"], b["id"], c["id"]]  # open (urgent first), waiting, closed
    assert r["counts"] == {"open": 1, "waiting_on_customer": 1, "resolved": 0, "closed": 1}
    first = r["tickets"][0]
    assert first["created_by_email"] == "owner@example.com" and first["needs_reply"] is True and first["workspace_name"]
    assert r["tickets"][1]["needs_reply"] is False and r["tickets"][1]["last_from"] == "support"
    ids = lambda q: [t["id"] for t in client.get("/admin/support/tickets" + q, headers=A).json()["tickets"]]
    assert ids("?status=active") == [a["id"], b["id"]]
    assert ids("?status=closed") == [c["id"]]
    assert ids("?category=fix") == [b["id"]]
    assert ids("?priority=urgent") == [a["id"]]
    assert ids(f"?workspace_id={eve.wid}") == [b["id"], c["id"]]
    assert ids("?q=CHARGED") == [a["id"]]
    assert ids("?q=eve@") == [b["id"], c["id"]]
    assert ids(f"?q=%23{c['number']}") == [c["id"]]
    assert ids("?q=100%25") == []  # LIKE wildcards are plain text
    for bad in ("?status=x", "?category=x", "?priority=x"):
        assert client.get("/admin/support/tickets" + bad, headers=A).status_code == 422
    assert client.get(f"/admin/support/tickets/{uuid.uuid4()}", headers=A).status_code == 404


def test_export_includes_tickets(client):
    u, bob = team(client)
    mine = raise_ticket(client, u, subject="Mine")
    client.post(f"/support/tickets/{mine['id']}/messages", json={"body": "Teammate's private aside"}, headers=bob.h)
    client.post(f"/admin/support/tickets/{mine['id']}/messages", json={"body": "Our answer"}, headers=A)
    client.post(f"/admin/support/tickets/{mine['id']}/messages", json={"body": "Secret note", "internal": True}, headers=A)
    theirs = raise_ticket(client, bob, wid=u.wid, subject="Bob's")
    client.post(f"/support/tickets/{theirs['id']}/messages", json={"body": "My comment on Bob's"}, headers=u.h)
    client.post(f"/admin/support/tickets/{theirs['id']}/messages", json={"body": "Answer to Bob"}, headers=A)
    raise_ticket(client, bob, wid=u.wid, subject="Untouched")
    d = client.get("/me/export", headers=u.h).json()
    tk = {t["subject"]: t for t in d["support_tickets"]}
    assert set(tk) == {"Mine", "Bob's"}
    assert tk["Mine"]["raised_by_you"] is True and tk["Bob's"]["raised_by_you"] is False
    assert [m["body"] for m in tk["Mine"]["messages"]] == ["Is this real?\n\nThanks", "Our answer"]
    assert [m["body"] for m in tk["Bob's"]["messages"]] == ["My comment on Bob's"]
    assert "Secret note" not in str(d) and "private aside" not in str(d)


def test_delete_account_anonymises_shared_tickets(client):
    u, bob = team(client)
    t = raise_ticket(client, bob, wid=u.wid, subject="From Bob")
    client.post(f"/support/tickets/{t['id']}/messages", json={"body": "Bob again"}, headers=bob.h)
    client.post(f"/support/tickets/{t['id']}/messages", json={"body": "Owner here"}, headers=u.h)
    assert client.delete("/me", headers=bob.h).json()["ok"]
    r = client.get(f"/support/tickets/{t['id']}", headers=u.h).json()
    assert r["created_by"] == "a former member" and r["created_by_id"] is None
    assert [m["by"] for m in r["messages"]] == ["a former member", "a former member", "owner@example.com"]
    assert "bob@example.com" not in client.get(f"/admin/support/tickets/{t['id']}", headers=A).text
    assert "bob@example.com" not in client.get("/admin/support/tickets", headers=A).text
    # with the person who raised it gone, support replies go to the workspace's owners
    sent = len(outbox())
    client.post(f"/admin/support/tickets/{t['id']}/messages", json={"body": "Answer"}, headers=A)
    assert [m["to"] for m in outbox()[sent:]] == ["owner@example.com"]


def test_delete_account_removes_solely_owned_workspace_tickets(client):
    u = sign_in(client, "owner@example.com")
    raise_ticket(client, u)
    other = sign_in(client, "eve@example.com")
    keep = raise_ticket(client, other)
    assert client.delete("/me", headers=u.h).json()["deleted_workspaces"] == 1
    assert [str(r["id"]) for r in sql("SELECT id FROM support_tickets")] == [keep["id"]]
    assert sql("SELECT count(*) AS n FROM support_messages")[0]["n"] == 1
