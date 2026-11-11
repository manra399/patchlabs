"""Workspaces: view, rename, members, invites and seats, roles, API keys, upgrade requests."""
import uuid

from helpers import A, link_param, outbox, sign_in, sql


def test_get_workspace_shape(client):
    u = sign_in(client, "owner@example.com")
    w = client.get(f"/workspaces/{u.wid}", headers=u.h).json()
    assert w["plan"] == "free" and w["role"] == "owner" and w["webhook_url"] is None
    assert w["limits"] == {"apps": 1, "runs_per_month": 4, "seats": 1, "schedules": ["off", "monthly"], "fix_price_gbp": 29}
    assert w["usage"] == {"apps": 0, "runs_this_month": 0, "members": 1, "clients": 0}
    assert w["members"][0]["email"] == "owner@example.com" and w["members"][0]["role"] == "owner"
    assert w["invites"] == []


def test_workspace_access_control(client):
    u = sign_in(client, "owner@example.com")
    other = sign_in(client, "other@example.com")
    assert client.get(f"/workspaces/{u.wid}").status_code == 401
    assert client.get(f"/workspaces/{u.wid}", headers=other.h).status_code == 404
    assert client.get(f"/workspaces/{uuid.uuid4()}", headers=u.h).status_code == 404
    assert client.get("/workspaces/not-a-uuid", headers=u.h).status_code == 404
    assert client.patch(f"/workspaces/{u.wid}", json={"name": "x"}, headers=other.h).status_code == 404


def test_rename(client):
    u = sign_in(client, "owner@example.com")
    r = client.patch(f"/workspaces/{u.wid}", json={"name": "Acme Agency"}, headers=u.h)
    assert r.status_code == 200 and r.json()["name"] == "Acme Agency"
    assert client.patch(f"/workspaces/{u.wid}", json={"name": ""}, headers=u.h).status_code == 422


def make_team(client, plan="maker"):
    u = sign_in(client, "owner@example.com")
    client.patch(f"/admin/workspaces/{u.wid}", json={"plan": plan}, headers=A)
    return u


def invite(client, u, email, role="member"):
    r = client.post(f"/workspaces/{u.wid}/invites", json={"email": email, "role": role}, headers=u.h)
    assert r.status_code == 201, r.text
    return r.json(), link_param(outbox(email.lower())[-1], "invite")


def test_free_plan_has_one_seat(client):
    u = sign_in(client, "owner@example.com")
    r = client.post(f"/workspaces/{u.wid}/invites", json={"email": "b@example.com"}, headers=u.h)
    assert r.status_code == 403 and "seat" in r.json()["detail"]


def test_invite_accept_via_sign_in(client):
    u = make_team(client)
    inv, tok = invite(client, u, "Bob@Example.com")
    assert inv["email"] == "bob@example.com" and inv["role"] == "member"
    msg = outbox("bob@example.com")[-1]
    assert "owner@example.com" in msg["text"] and "/app/login?invite=" in msg["text"]
    w = client.get(f"/workspaces/{u.wid}", headers=u.h).json()
    assert [i["email"] for i in w["invites"]] == ["bob@example.com"]
    # seats: owner + pending invite = 2 = maker limit
    assert client.post(f"/workspaces/{u.wid}/invites", json={"email": "c@example.com"}, headers=u.h).status_code == 403

    bob = sign_in(client, "bob@example.com", invite=tok)
    assert bob.finish["invite"]["accepted"] is True and bob.finish["invite"]["workspace_id"] == u.wid
    me = client.get("/me", headers=bob.h).json()
    assert {w["id"]: w["role"] for w in me["workspaces"]}[u.wid] == "member"
    w = client.get(f"/workspaces/{u.wid}", headers=bob.h).json()
    assert w["usage"]["members"] == 2 and w["invites"] == []
    # used invite can't be reused
    assert sign_in(client, "bob@example.com", invite=tok).finish["invite"]["accepted"] is False


def test_invite_for_other_email_is_refused(client):
    u = make_team(client)
    _, tok = invite(client, u, "bob@example.com")
    mallory = sign_in(client, "mallory@example.com", invite=tok)
    assert mallory.finish["invite"]["accepted"] is False and "different email" in mallory.finish["invite"]["detail"]
    assert client.get(f"/workspaces/{u.wid}", headers=mallory.h).status_code == 404


def test_accept_invite_while_signed_in(client):
    u = make_team(client)
    bob = sign_in(client, "bob@example.com")
    _, tok = invite(client, u, "bob@example.com")
    assert client.post("/invites/accept", json={"invite": "bad"}, headers=bob.h).status_code == 409
    r = client.post("/invites/accept", json={"invite": tok}, headers=bob.h)
    assert r.status_code == 200 and r.json()["accepted"] is True
    assert client.get(f"/workspaces/{u.wid}", headers=bob.h).status_code == 200


def test_invite_rules(client):
    u = make_team(client, "agency")
    assert client.post(f"/workspaces/{u.wid}/invites", json={"email": "owner@example.com"}, headers=u.h).status_code == 409
    assert client.post(f"/workspaces/{u.wid}/invites", json={"email": "x@example.com", "role": "superuser"}, headers=u.h).status_code == 422
    inv, _ = invite(client, u, "b@example.com")
    inv2, tok2 = invite(client, u, "b@example.com")  # re-inviting replaces the old invite
    assert len(client.get(f"/workspaces/{u.wid}", headers=u.h).json()["invites"]) == 1
    assert client.delete(f"/workspaces/{u.wid}/invites/{inv['id']}", headers=u.h).status_code == 404
    assert client.delete(f"/workspaces/{u.wid}/invites/{inv2['id']}", headers=u.h).json() == {"ok": True}
    assert sign_in(client, "b@example.com", invite=tok2).finish["invite"]["accepted"] is False


def test_members_cannot_do_owner_things(client):
    u = make_team(client, "agency")
    _, tok = invite(client, u, "bob@example.com")
    bob = sign_in(client, "bob@example.com", invite=tok)
    assert client.post(f"/workspaces/{u.wid}/invites", json={"email": "z@example.com"}, headers=bob.h).status_code == 403
    assert client.patch(f"/workspaces/{u.wid}", json={"name": "mine"}, headers=bob.h).status_code == 403
    assert client.delete(f"/workspaces/{u.wid}/members/{u.user['id']}", headers=bob.h).status_code == 403
    assert client.patch(f"/workspaces/{u.wid}/members/{bob.user['id']}", json={"role": "owner"}, headers=bob.h).status_code == 403
    # but members see the workspace and can leave it
    assert client.get(f"/workspaces/{u.wid}", headers=bob.h).status_code == 200
    assert client.delete(f"/workspaces/{u.wid}/members/{bob.user['id']}", headers=bob.h).json() == {"ok": True}
    assert client.get(f"/workspaces/{u.wid}", headers=bob.h).status_code == 404


def test_roles_and_last_owner(client):
    u = make_team(client, "agency")
    _, tok = invite(client, u, "bob@example.com")
    bob = sign_in(client, "bob@example.com", invite=tok)
    r = client.delete(f"/workspaces/{u.wid}/members/{u.user['id']}", headers=u.h)
    assert r.status_code == 409 and "owner" in r.json()["detail"]
    assert client.patch(f"/workspaces/{u.wid}/members/{u.user['id']}", json={"role": "member"}, headers=u.h).status_code == 409
    r = client.patch(f"/workspaces/{u.wid}/members/{bob.user['id']}", json={"role": "owner"}, headers=u.h)
    assert {m["email"]: m["role"] for m in r.json()["members"]}["bob@example.com"] == "owner"
    assert client.delete(f"/workspaces/{u.wid}/members/{u.user['id']}", headers=bob.h).json() == {"ok": True}
    assert client.get(f"/workspaces/{u.wid}", headers=u.h).status_code == 404
    assert client.delete(f"/workspaces/{u.wid}/members/{uuid.uuid4()}", headers=bob.h).status_code == 404


def test_owner_invite_role(client):
    u = make_team(client, "agency")
    _, tok = invite(client, u, "co@example.com", role="owner")
    co = sign_in(client, "co@example.com", invite=tok)
    assert {w["id"]: w["role"] for w in client.get("/me", headers=co.h).json()["workspaces"]}[u.wid] == "owner"


def test_api_keys_crud(client):
    u = sign_in(client, "owner@example.com")
    r = client.post(f"/workspaces/{u.wid}/api-keys", json={"name": "CI"}, headers=u.h)
    assert r.status_code == 201
    k = r.json()
    assert k["key"].startswith("pl_live_") and len(k["key"]) == len("pl_live_") + 32 and k["prefix"] == k["key"][:12]
    assert sql("SELECT count(*) AS n FROM api_keys WHERE key_hash = %s", (k["key"],))[0]["n"] == 0
    keys = client.get(f"/workspaces/{u.wid}/api-keys", headers=u.h).json()["api_keys"]
    assert len(keys) == 1 and "key" not in keys[0] and "key_hash" not in keys[0]
    assert client.post(f"/workspaces/{u.wid}/api-keys", json={"name": ""}, headers=u.h).status_code == 422
    other = sign_in(client, "other@example.com")
    assert client.get(f"/workspaces/{u.wid}/api-keys", headers=other.h).status_code == 404
    assert client.delete(f"/workspaces/{u.wid}/api-keys/{k['id']}", headers=other.h).status_code == 404
    assert client.delete(f"/workspaces/{u.wid}/api-keys/{k['id']}", headers=u.h).json() == {"ok": True}
    assert client.delete(f"/workspaces/{u.wid}/api-keys/{k['id']}", headers=u.h).status_code == 404


def test_upgrade_request(client):
    u = sign_in(client, "owner@example.com")
    r = client.post(f"/workspaces/{u.wid}/upgrade-request", json={"plan": "agency", "note": "12 client apps"}, headers=u.h)
    assert r.status_code == 201 and r.json()["plan"] == "agency"
    msg = outbox("manraj@patchlabs.dev")[-1]
    assert "agency" in msg["subject"] and "owner@example.com" in msg["text"] and "12 client apps" in msg["text"]
    assert client.post(f"/workspaces/{u.wid}/upgrade-request", json={"plan": "platinum"}, headers=u.h).status_code == 422
    reqs = client.get("/admin/upgrade-requests", headers=A).json()["upgrade_requests"]
    assert reqs[0]["email"] == "owner@example.com" and reqs[0]["plan"] == "agency" and reqs[0]["current_plan"] == "free"
