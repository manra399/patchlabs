"""Account audit log: what is recorded, who can read it, filters, pagination, CSV, masking, no secrets, append-only."""
import csv, io, json

import psycopg
import pytest

import core
from helpers import A, claim, finish_with, invite_as, sign_in, sql, verified_app

FINDING = {"id": "PL-001", "line": "lab", "severity": "critical", "title": "Anyone can read profiles", "object": "public.profiles"}


def events(client, u, wid=None, **params):
    r = client.get(f"/workspaces/{wid or u.wid}/audit", params=params, headers=u.h)
    assert r.status_code == 200, r.text
    return r.json()


def actions(client, u, **params):
    return [e["action"] for e in events(client, u, limit=200, **params)["events"]]


def test_records_the_account_lifecycle(client, local_webhooks):
    o = sign_in(client, "owner@example.com")
    client.patch("/me", json={"name": "Olive"}, headers=o.h)
    client.patch(f"/admin/workspaces/{o.wid}", json={"plan": "agency"}, headers=A)
    bob = invite_as(client, o, "bob@example.com", "approver")
    a, cid = verified_app(client, o)
    claim(client)
    finish_with(client, cid, [FINDING], tables=["profiles"], questions=["Public?"])
    client.post(f"/checks/{cid}/decision", json={"action": "reject", "reason": "public by design"}, headers=bob.h)
    client.post(f"/checks/{cid}/decision", json={"action": "approve"}, headers=bob.h)
    client.post(f"/checks/{cid}/answers", json={"answers": [{"question": "Public?", "answer": "No"}]}, headers=bob.h)
    client.post(f"/apps/{a['id']}/checks", headers=bob.h)
    client.patch(f"/apps/{a['id']}", json={"schedule": "weekly", "badge_public": True}, headers=o.h)
    k = client.post(f"/workspaces/{o.wid}/api-keys", json={"name": "CI"}, headers=o.h).json()
    client.delete(f"/workspaces/{o.wid}/api-keys/{k['id']}", headers=o.h)
    client.patch(f"/workspaces/{o.wid}", json={"webhook_url": local_webhooks}, headers=o.h)
    client.patch(f"/workspaces/{o.wid}", json={"webhook_url": local_webhooks + "?v=2"}, headers=o.h)
    client.post(f"/workspaces/{o.wid}/webhook/rotate-secret", headers=o.h)
    client.post(f"/workspaces/{o.wid}/webhook/test", headers=o.h)
    client.patch(f"/workspaces/{o.wid}", json={"webhook_url": None}, headers=o.h)
    client.get("/me/export", headers=o.h)
    client.post(f"/workspaces/{o.wid}/support/tickets", json={"subject": "Help", "category": "other", "message": "Hi"}, headers=bob.h)
    client.patch(f"/workspaces/{o.wid}/members/{bob.user['id']}", json={"role": "viewer"}, headers=o.h)
    client.delete(f"/workspaces/{o.wid}/members/{bob.user['id']}", headers=o.h)
    client.patch(f"/admin/workspaces/{o.wid}", json={"plan": "maker", "app_limit": 5}, headers=A)
    client.delete(f"/apps/{a['id']}", headers=o.h)
    client.post("/auth/logout", headers=bob.h)
    got = actions(client, o)[::-1]
    expected = ["auth.sign_in", "plan.changed", "member.invited", "member.joined", "auth.sign_in", "app.added", "app.verified",
                "check.started", "decision.made", "suppression.added", "decision.made", "suppression.removed", "check.answered",
                "check.started", "app.updated", "api_key.created", "api_key.revoked", "webhook.created", "webhook.changed",
                "webhook.secret_rotated", "webhook.tested", "webhook.deleted", "data.exported", "ticket.raised", "member.role_changed",
                "member.removed", "plan.changed", "app.removed"]
    assert got == expected
    ev = {e["action"]: e for e in reversed(events(client, o, limit=200)["events"])}  # the newest of each action
    assert ev["plan.changed"]["actor"] == {"kind": "admin", "id": None, "label": "PatchLabs admin", "email": None}
    assert ev["plan.changed"]["detail"] == {"plan": {"from": "agency", "to": "maker"}, "app_limit": {"from": None, "to": 5}}
    assert ev["member.role_changed"]["detail"] == {"from": "approver", "to": "viewer"}
    assert ev["app.updated"]["detail"] == {"schedule": {"from": "monthly", "to": "weekly"}, "badge_public": {"from": False, "to": True}}
    assert ev["check.started"]["detail"]["trigger"] == "manual" and ev["webhook.created"]["detail"]["host"] == "127.0.0.1"
    assert ev["app.added"]["actor"]["label"] == "Olive" and ev["app.added"]["target"]["label"] == "acme/shop"


def test_never_logs_secrets(client, local_webhooks):
    o = sign_in(client, "owner@example.com")
    w = client.patch(f"/workspaces/{o.wid}", json={"webhook_url": local_webhooks + "/T000/B000/s3cr3tpath"}, headers=o.h).json()
    secret = client.post(f"/workspaces/{o.wid}/webhook/rotate-secret", headers=o.h).json()["webhook_secret"]
    k = client.post(f"/workspaces/{o.wid}/api-keys", json={"name": "CI"}, headers=o.h).json()
    blob = json.dumps(sql("SELECT * FROM audit_log"), default=str) + client.get(f"/workspaces/{o.wid}/audit/export", headers=o.h).text
    for s in (secret, w["webhook_secret"], k["key"], "s3cr3tpath", o.session):
        assert s not in blob
    assert k["prefix"] in blob  # the display prefix is fine


def test_only_owners_and_admins_read_it(client):
    o = sign_in(client, "owner@example.com")
    client.patch(f"/admin/workspaces/{o.wid}", json={"plan": "agency"}, headers=A)
    for role in ("approver", "member", "viewer", "client"):
        u = invite_as(client, o, f"{role}@example.com", role, app_ids=[] if role == "client" else None)
        assert client.get(f"/workspaces/{o.wid}/audit", headers=u.h).status_code == 403
        assert client.get(f"/workspaces/{o.wid}/audit/export", headers=u.h).status_code == 403
    adm = invite_as(client, o, "admin@example.com", "admin")
    assert client.get(f"/workspaces/{o.wid}/audit", headers=adm.h).status_code == 200
    stranger = sign_in(client, "stranger@example.com")
    assert client.get(f"/workspaces/{o.wid}/audit", headers=stranger.h).status_code == 404
    assert client.get(f"/workspaces/{o.wid}/audit").status_code == 401


def test_filters_and_pagination(client):
    o = sign_in(client, "owner@example.com")
    client.patch(f"/admin/workspaces/{o.wid}", json={"plan": "agency"}, headers=A)
    bob = invite_as(client, o, "bob@example.com", "admin")
    for i in range(3):
        client.post(f"/workspaces/{o.wid}/api-keys", json={"name": f"k{i}"}, headers=bob.h)
    assert actions(client, o, action="api_key.created") == ["api_key.created"] * 3
    assert set(actions(client, o, action="member")) == {"member.invited", "member.joined"}
    assert set(actions(client, o, actor=bob.user["id"])) == {"auth.sign_in", "member.joined", "api_key.created"}
    assert actions(client, o, actor="admin") == ["plan.changed"]
    assert actions(client, o, since="2000-01-01", until="2000-01-02") == []
    assert len(actions(client, o, since="2000-01-01")) == len(actions(client, o))
    assert client.get(f"/workspaces/{o.wid}/audit", params={"since": "yesterday"}, headers=o.h).status_code == 422
    assert client.get(f"/workspaces/{o.wid}/audit", params={"actor": "nobody"}, headers=o.h).status_code == 404
    page = events(client, o, limit=2)
    assert len(page["events"]) == 2 and page["next_before"] == page["events"][-1]["id"]
    seen = [e["id"] for e in page["events"]]
    while page["next_before"]:
        page = events(client, o, limit=2, before=page["next_before"])
        seen += [e["id"] for e in page["events"]]
    assert seen == sorted(seen, reverse=True) and len(seen) == len(actions(client, o))
    assert "member.role_changed" in page["actions"]


def test_csv_export(client):
    o = sign_in(client, "owner@example.com")
    client.patch(f"/workspaces/{o.wid}", json={"name": "=HYPERLINK(\"http://x\")"}, headers=o.h)
    r = client.get(f"/workspaces/{o.wid}/audit/export", headers=o.h)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0][:5] == ["id", "at", "action", "actor_kind", "actor"]
    renamed = [x for x in rows if x[2] == "workspace.renamed"][0]
    assert renamed[8].startswith("'=")  # no formula injection
    assert actions(client, o)[0] == "audit.exported"
    assert len(list(csv.reader(io.StringIO(client.get(f"/workspaces/{o.wid}/audit/export", params={"action": "auth"},
                                                      headers=o.h).text)))) == 2


def test_removed_and_deleted_members_are_masked(client):
    o = sign_in(client, "owner@example.com")
    client.patch(f"/admin/workspaces/{o.wid}", json={"plan": "agency"}, headers=A)
    bob = invite_as(client, o, "bob@example.com", "member")
    client.post(f"/workspaces/{o.wid}/api-keys", json={"name": "ci"}, headers=bob.h)
    by_bob = [e for e in events(client, o, actor=bob.user["id"])["events"]]
    assert by_bob[0]["actor"]["email"] == "bob@example.com"
    client.delete(f"/workspaces/{o.wid}/members/{bob.user['id']}", headers=o.h)
    text = json.dumps(events(client, o, limit=200)) + client.get(f"/workspaces/{o.wid}/audit/export", headers=o.h).text
    assert "bob@example.com" not in text and "b•••@example.com" in text
    # and after deleting their account they are "a former member", with nothing personal left in the table
    carol = invite_as(client, o, "carol@example.com", "member")
    client.patch("/me", json={"name": "Carol"}, headers=carol.h)
    client.post(f"/workspaces/{o.wid}/api-keys", json={"name": "c"}, headers=carol.h)
    client.delete("/me", headers=carol.h)
    rows = sql("SELECT * FROM audit_log")
    assert "carol@example.com" not in json.dumps(rows, default=str) and "Carol" not in json.dumps(rows, default=str)
    left = [e for e in events(client, o, limit=200)["events"] if e["action"] == "member.left"][0]
    assert left["actor"]["label"] == "a former member" and left["actor"]["email"] is None
    assert left["target"]["email"] == "c•••@example.com"


def test_append_only(client):
    o = sign_in(client, "owner@example.com")
    with pytest.raises(psycopg.errors.RaiseException):
        sql("UPDATE audit_log SET action = 'auth.sign_out'")
    with pytest.raises(psycopg.errors.RaiseException):
        sql("UPDATE audit_log SET actor_id = gen_random_uuid()")
    with pytest.raises(psycopg.errors.RaiseException):
        sql("DELETE FROM audit_log")
    assert sql("SELECT count(*) AS n FROM audit_log")[0]["n"] == 1
    # a workspace deleted with its only owner's account takes its log with it
    assert client.delete("/me", headers=o.h).json()["deleted_workspaces"] == 1
    assert sql("SELECT count(*) AS n FROM audit_log")[0]["n"] == 0


def test_scheduled_and_api_checks_name_their_actor(client):
    o = sign_in(client, "owner@example.com")
    a, cid = verified_app(client, o)
    finish_with(client, claim(client)["id"], [])
    key = client.post(f"/workspaces/{o.wid}/api-keys", json={"name": "CI"}, headers=o.h).json()
    client.post(f"/v1/apps/{a['id']}/checks", headers={"X-API-Key": key["key"]})
    finish_with(client, claim(client)["id"], [])
    sql("UPDATE apps SET next_check_at = now() - interval '1 minute'")
    claim(client)
    started = [e for e in events(client, o)["events"] if e["action"] == "check.started"]
    assert [(e["actor"]["kind"], e["detail"]["trigger"]) for e in started] == [("system", "scheduled"), ("api_key", "api"), ("user", "verify")]
    assert started[1]["actor"]["label"] == f"API key CI ({key['prefix']}…)" and started[0]["actor"]["label"] == "PatchLabs"
    assert core  # imported for parity with other suites
