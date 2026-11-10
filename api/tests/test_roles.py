"""Roles: owner, admin, approver, member, viewer, client. Every route is checked server-side against core.PERMS."""
import os, uuid

import psycopg
import pytest

from helpers import A, ROOT, STATE, add_repo, claim, finish_with, invite_as, sign_in, sql, verified_app

ROLES = ("owner", "admin", "approver", "member", "viewer", "client")
FINDING = {"id": "PL-001", "line": "lab", "severity": "critical", "title": "Anyone can read profiles", "object": "public.profiles"}


@pytest.fixture
def team(client):
    """An agency workspace with one user per role. The client sees app `a` only; app `b` is someone else's."""
    o = sign_in(client, "owner@example.com")
    client.patch(f"/admin/workspaces/{o.wid}", json={"plan": "agency"}, headers=A)
    a, cid = verified_app(client, o, "acme/shop")
    b, cid_b = verified_app(client, o, "other/client")
    for k in (cid, cid_b):
        assert claim(client)["id"] in (str(cid), str(cid_b))
        finish_with(client, k, [FINDING], tables=["profiles"], questions=["Should profiles be public?"])
    users = {"owner": o}
    for r in ROLES[1:]:
        users[r] = invite_as(client, o, f"{r}@example.com", r, app_ids=[a["id"]] if r == "client" else None)
    return {"u": users, "wid": o.wid, "a": a, "b": b, "cid": str(cid), "cid_b": str(cid_b)}


def allowed(code):
    return code not in (401, 403, 404, 422)


# (description, permitted roles, request builder) — run against every role
MATRIX = [
    ("view workspace", set(ROLES), lambda c, t, h: c.get(f"/workspaces/{t['wid']}", headers=h)),
    ("list apps", set(ROLES), lambda c, t, h: c.get(f"/workspaces/{t['wid']}/apps", headers=h)),
    ("view shared app", set(ROLES), lambda c, t, h: c.get(f"/apps/{t['a']['id']}", headers=h)),
    ("view other app", set(ROLES) - {"client"}, lambda c, t, h: c.get(f"/apps/{t['b']['id']}", headers=h)),
    ("member decisions", set(ROLES), lambda c, t, h: c.get(f"/checks/{t['cid']}/decisions", headers=h)),
    ("other app decisions", set(ROLES) - {"client"}, lambda c, t, h: c.get(f"/checks/{t['cid_b']}/decisions", headers=h)),
    ("run check", {"owner", "admin", "approver", "member"}, lambda c, t, h: c.post(f"/apps/{t['a']['id']}/checks", headers=h)),
    ("decide", {"owner", "admin", "approver"},
     lambda c, t, h: c.post(f"/checks/{t['cid']}/decision", json={"action": "approve"}, headers=h)),
    ("answer", {"owner", "admin", "approver"},
     lambda c, t, h: c.post(f"/checks/{t['cid']}/answers", json={"answers": [{"question": "Should profiles be public?", "answer": "No"}]},
                            headers=h)),
    ("add app", {"owner", "admin"}, lambda c, t, h: (add_repo(f"x/{h['Authorization'][-6:]}"),
                                                     c.post(f"/workspaces/{t['wid']}/apps", json={"repo": f"x/{h['Authorization'][-6:]}"},
                                                            headers=h))[1]),
    ("edit app", {"owner", "admin"}, lambda c, t, h: c.patch(f"/apps/{t['a']['id']}", json={"client_label": "Bakery"}, headers=h)),
    ("verify app", {"owner", "admin"}, lambda c, t, h: c.post(f"/apps/{t['a']['id']}/verify", headers=h)),
    ("rename workspace", {"owner", "admin"}, lambda c, t, h: c.patch(f"/workspaces/{t['wid']}", json={"name": "Acme"}, headers=h)),
    ("set webhook", {"owner", "admin"}, lambda c, t, h: c.patch(f"/workspaces/{t['wid']}", json={"webhook_url": None}, headers=h)),
    ("test webhook", {"owner", "admin"}, lambda c, t, h: c.post(f"/workspaces/{t['wid']}/webhook/test", headers=h)),
    ("rotate secret", {"owner", "admin"}, lambda c, t, h: c.post(f"/workspaces/{t['wid']}/webhook/rotate-secret", headers=h)),
    ("invite", {"owner", "admin"},
     lambda c, t, h: c.post(f"/workspaces/{t['wid']}/invites", json={"email": f"n{h['Authorization'][-6:]}@example.com"}, headers=h)),
    ("upgrade request", {"owner", "admin"}, lambda c, t, h: c.post(f"/workspaces/{t['wid']}/upgrade-request", json={"plan": "enterprise"},
                                                                   headers=h)),
    ("audit log", {"owner", "admin"}, lambda c, t, h: c.get(f"/workspaces/{t['wid']}/audit", headers=h)),
    ("audit export", {"owner", "admin"}, lambda c, t, h: c.get(f"/workspaces/{t['wid']}/audit/export", headers=h)),
    ("list keys", set(ROLES) - {"client"}, lambda c, t, h: c.get(f"/workspaces/{t['wid']}/api-keys", headers=h)),
    ("create key", {"owner", "admin", "approver", "member"},
     lambda c, t, h: c.post(f"/workspaces/{t['wid']}/api-keys", json={"name": "ci"}, headers=h)),
    ("list tickets", set(ROLES), lambda c, t, h: c.get(f"/workspaces/{t['wid']}/support/tickets", headers=h)),
    ("raise ticket", {"owner", "admin", "approver", "member"},
     lambda c, t, h: c.post(f"/workspaces/{t['wid']}/support/tickets", json={"subject": "Hi", "category": "other", "message": "Hello"},
                            headers=h)),
]


@pytest.mark.parametrize("name,ok,call", MATRIX, ids=[m[0] for m in MATRIX])
def test_role_matrix(client, team, name, ok, call):
    for role in ROLES:
        r = call(client, team, team["u"][role].h)
        assert allowed(r.status_code) == (role in ok), f"{name} as {role}: {r.status_code} {r.text}"


def test_delete_app_is_owner_or_admin(client, team):
    for role in ("approver", "member", "viewer"):
        assert client.delete(f"/apps/{team['b']['id']}", headers=team["u"][role].h).status_code == 403
    assert client.delete(f"/apps/{team['b']['id']}", headers=team["u"]["client"].h).status_code == 404
    assert client.delete(f"/apps/{team['b']['id']}", headers=team["u"]["admin"].h).json() == {"ok": True}


def test_client_sees_only_assigned_apps_and_no_team(client, team):
    cl = team["u"]["client"]
    apps = client.get(f"/workspaces/{team['wid']}/apps", headers=cl.h).json()["apps"]
    assert [x["id"] for x in apps] == [team["a"]["id"]]
    w = client.get(f"/workspaces/{team['wid']}", headers=cl.h).json()
    assert w["role"] == "client" and w["webhook_url"] is None and w["invites"] == [] and w["usage"] is None and w["limits"] is None
    assert [m["email"] for m in w["members"]] == ["client@example.com"]
    assert w["permissions"] == ["support", "view"]
    # the export never lists another client's app
    exp = client.get("/me/export", headers=cl.h).json()
    ws = [x for x in exp["workspaces"] if x["id"] == team["wid"]][0]
    assert [x["repo"] for x in ws["apps"]] == ["acme/shop"]
    # a ticket that isn't about one of their apps is invisible to a client
    t = client.post(f"/workspaces/{team['wid']}/support/tickets", json={"subject": "Hi", "category": "other", "message": "Hello"},
                    headers=team["u"]["owner"].h).json()
    assert client.get(f"/support/tickets/{t['id']}", headers=cl.h).status_code == 404
    assert client.get(f"/support/tickets/{t['id']}", headers=team["u"]["viewer"].h).status_code == 200
    assert client.post(f"/support/tickets/{t['id']}/messages", json={"body": "x"}, headers=team["u"]["viewer"].h).status_code == 403
    assert client.post(f"/support/tickets/{t['id']}/close", headers=team["u"]["viewer"].h).status_code == 403


def test_owner_view_shows_roles_and_client_apps(client, team):
    w = client.get(f"/workspaces/{team['wid']}", headers=team["u"]["owner"].h).json()
    roles = {m["email"]: (m["role"], m["app_ids"]) for m in w["members"]}
    assert roles["client@example.com"] == ("client", [team["a"]["id"]]) and roles["viewer@example.com"] == ("viewer", None)
    assert set(w["permissions"]) == {"view", "view_team", "run", "support", "decide", "manage", "owner"}
    adm = client.get(f"/workspaces/{team['wid']}", headers=team["u"]["admin"].h).json()
    assert "owner" not in adm["permissions"] and "manage" in adm["permissions"]
    v = client.get(f"/workspaces/{team['wid']}", headers=team["u"]["viewer"].h).json()
    assert v["webhook_url"] is None and v["webhook_secret"] is None and v["invites"] == [] and len(v["members"]) == 6


def test_client_emails_only_for_their_apps(client, team):
    from helpers import outbox
    o = team["u"]["owner"]
    for aid in (team["a"]["id"], team["b"]["id"]):
        cid = client.post(f"/apps/{aid}/checks", headers=o.h).json()["check_id"]
        claim(client)
        finish_with(client, cid, [])
    subjects = [m["subject"] for m in outbox("client@example.com") if "check finished" in m["subject"]]
    assert subjects == ["PatchLabs check finished for acme/shop"]
    assert len([m for m in outbox("viewer@example.com") if "check finished" in m["subject"]]) == 2


def test_invite_roles_and_admin_limits(client, team):
    adm, o = team["u"]["admin"], team["u"]["owner"]
    r = client.post(f"/workspaces/{team['wid']}/invites", json={"email": "x@example.com", "role": "owner"}, headers=adm.h)
    assert r.status_code == 403 and "owner" in r.json()["detail"]
    r = client.post(f"/workspaces/{team['wid']}/invites", json={"email": "x@example.com", "role": "viewer", "app_ids": [team["a"]["id"]]},
                    headers=adm.h)
    assert r.status_code == 422
    r = client.post(f"/workspaces/{team['wid']}/invites", json={"email": "x@example.com", "role": "client", "app_ids": [str(uuid.uuid4())]},
                    headers=adm.h)
    assert r.status_code == 422
    r = client.post(f"/workspaces/{team['wid']}/invites", json={"email": "x@example.com", "role": "client", "app_ids": [team["b"]["id"]]},
                    headers=adm.h)
    assert r.status_code == 201 and r.json()["role"] == "client" and r.json()["app_ids"] == [team["b"]["id"]]
    # admins can't change or remove owners, or make anyone an owner
    oid = o.user["id"]
    assert client.patch(f"/workspaces/{team['wid']}/members/{oid}", json={"role": "member"}, headers=adm.h).status_code == 403
    assert client.delete(f"/workspaces/{team['wid']}/members/{oid}", headers=adm.h).status_code == 403
    mid = team["u"]["member"].user["id"]
    assert client.patch(f"/workspaces/{team['wid']}/members/{mid}", json={"role": "owner"}, headers=adm.h).status_code == 403
    r = client.patch(f"/workspaces/{team['wid']}/members/{mid}", json={"role": "approver"}, headers=adm.h)
    assert r.status_code == 200 and {m["email"]: m["role"] for m in r.json()["members"]}["member@example.com"] == "approver"
    assert client.delete(f"/workspaces/{team['wid']}/members/{mid}", headers=adm.h).json() == {"ok": True}
    # non-managers can't change roles at all
    vid = team["u"]["viewer"].user["id"]
    assert client.patch(f"/workspaces/{team['wid']}/members/{vid}", json={"role": "member"}, headers=team["u"]["approver"].h).status_code == 403


def test_last_owner_cannot_be_demoted_or_leave(client, team):
    o, wid = team["u"]["owner"], team["wid"]
    for role in ROLES[1:]:
        r = client.patch(f"/workspaces/{wid}/members/{o.user['id']}", json={"role": role}, headers=o.h)
        assert r.status_code == 409 and "owner" in r.json()["detail"]
    assert client.delete(f"/workspaces/{wid}/members/{o.user['id']}", headers=o.h).status_code == 409
    client.patch(f"/workspaces/{wid}/members/{team['u']['admin'].user['id']}", json={"role": "owner"}, headers=o.h)
    assert client.patch(f"/workspaces/{wid}/members/{o.user['id']}", json={"role": "viewer"}, headers=o.h).status_code == 200
    assert client.get(f"/workspaces/{wid}", headers=o.h).json()["role"] == "viewer"


def test_client_app_access_can_change(client, team):
    o, cl = team["u"]["owner"], team["u"]["client"]
    url = f"/workspaces/{team['wid']}/members/{cl.user['id']}/apps"
    assert client.put(url, json={"app_ids": [team["b"]["id"]]}, headers=team["u"]["member"].h).status_code == 403
    r = client.put(url, json={"app_ids": [team["b"]["id"]]}, headers=o.h)
    assert r.status_code == 200
    assert client.get(f"/apps/{team['a']['id']}", headers=cl.h).status_code == 404
    assert client.get(f"/apps/{team['b']['id']}", headers=cl.h).status_code == 200
    assert client.put(f"/workspaces/{team['wid']}/members/{team['u']['viewer'].user['id']}/apps", json={"app_ids": []},
                      headers=o.h).status_code == 409
    # promoting a client drops the list (they see everything); demoting with app_ids sets it
    client.patch(f"/workspaces/{team['wid']}/members/{cl.user['id']}", json={"role": "viewer"}, headers=o.h)
    assert sql("SELECT count(*) AS n FROM member_app_access")[0]["n"] == 0
    assert client.get(f"/apps/{team['a']['id']}", headers=cl.h).status_code == 200
    client.patch(f"/workspaces/{team['wid']}/members/{cl.user['id']}", json={"role": "client", "app_ids": [team["a"]["id"]]}, headers=o.h)
    assert client.get(f"/apps/{team['b']['id']}", headers=cl.h).status_code == 404
    # deleting an app removes it from every client's list
    client.delete(f"/apps/{team['a']['id']}", headers=o.h)
    assert client.get(f"/workspaces/{team['wid']}/apps", headers=cl.h).json()["apps"] == []


def test_api_keys_follow_the_role(client, team):
    o, m = team["u"]["owner"], team["u"]["member"]
    k = client.post(f"/workspaces/{team['wid']}/api-keys", json={"name": "ci"}, headers=m.h).json()
    mine = client.post(f"/workspaces/{team['wid']}/api-keys", json={"name": "own"}, headers=o.h).json()
    h = {"X-API-Key": k["key"]}
    assert client.get(f"/v1/checks/{team['cid']}", headers=h).status_code == 200
    # members revoke their own keys only
    assert client.delete(f"/workspaces/{team['wid']}/api-keys/{mine['id']}", headers=m.h).status_code == 403
    # demoted to viewer: their keys are revoked (viewers can't run checks)
    client.patch(f"/workspaces/{team['wid']}/members/{m.user['id']}", json={"role": "viewer"}, headers=o.h)
    assert client.get(f"/v1/checks/{team['cid']}", headers=h).status_code == 401
    assert [x["name"] for x in client.get(f"/workspaces/{team['wid']}/api-keys", headers=o.h).json()["api_keys"]] == ["own"]


def test_api_key_dies_if_creator_role_cannot_run(client, team):
    """Defence in depth: even a key that survived (e.g. a role changed directly in the database) stops working."""
    m = team["u"]["member"]
    k = client.post(f"/workspaces/{team['wid']}/api-keys", json={"name": "ci"}, headers=m.h).json()
    sql("UPDATE workspace_members SET role = 'viewer' WHERE user_id = %s", (m.user["id"],))
    assert client.get(f"/v1/checks/{team['cid']}", headers={"X-API-Key": k["key"]}).status_code == 401


def test_owner_deleting_account_never_hands_workspace_to_a_client(client):
    o = sign_in(client, "owner@example.com")
    client.patch(f"/admin/workspaces/{o.wid}", json={"plan": "agency"}, headers=A)
    a, _ = verified_app(client, o)
    cl = invite_as(client, o, "client@example.com", "client", app_ids=[a["id"]])
    v = invite_as(client, o, "viewer@example.com", "viewer")
    adm = invite_as(client, o, "admin@example.com", "admin")
    assert client.delete("/me", headers=o.h).json()["deleted_workspaces"] == 0
    roles = {m["email"]: m["role"] for m in client.get(f"/workspaces/{o.wid}", headers=adm.h).json()["members"]}
    assert roles == {"client@example.com": "client", "viewer@example.com": "viewer", "admin@example.com": "owner"}
    # a workspace with only clients left goes with the account
    o2 = sign_in(client, "solo@example.com")
    client.patch(f"/admin/workspaces/{o2.wid}", json={"plan": "agency"}, headers=A)
    a2, _ = verified_app(client, o2, "solo/app")
    cl2 = invite_as(client, o2, "client2@example.com", "client", app_ids=[a2["id"]])
    assert client.delete("/me", headers=o2.h).json()["deleted_workspaces"] == 1
    assert client.get(f"/workspaces/{o2.wid}", headers=cl2.h).status_code == 404
    assert v and cl


def test_existing_members_keep_their_role_after_migration():
    """Production has workspace_members/invites with CHECK (role IN ('owner','member')): the schema widens it in place."""
    full = open(os.path.join(ROOT, "db", "schema.sql")).read()
    old = full.split("-- ---- roles, client app access")[0]
    base = os.environ["DATABASE_URL"]
    name = "roles_" + uuid.uuid4().hex[:8]
    with psycopg.connect(base, autocommit=True) as c:
        c.execute(f"CREATE DATABASE {name}")
    url = base.rsplit("/", 1)[0] + "/" + name
    try:
        with psycopg.connect(url) as c:
            c.execute(old)
            uid, wid = uuid.uuid4(), uuid.uuid4()
            c.execute("INSERT INTO users (id, email) VALUES (%s, 'm@example.com')", (uid,))
            c.execute("INSERT INTO workspaces (id, name) VALUES (%s, 'w')", (wid,))
            c.execute("INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (%s, %s, 'member')", (wid, uid))
            c.commit()
            with pytest.raises(psycopg.errors.CheckViolation):
                c.execute("UPDATE workspace_members SET role = 'viewer'")
        for _ in range(2):
            with psycopg.connect(url) as c:
                c.execute(full)
        with psycopg.connect(url) as c:
            assert c.execute("SELECT role FROM workspace_members").fetchone()[0] == "member"
            for role in ROLES:
                c.execute("UPDATE workspace_members SET role = %s", (role,))
            with pytest.raises(psycopg.errors.CheckViolation):
                c.execute("UPDATE workspace_members SET role = 'god'")
    finally:
        with psycopg.connect(base, autocommit=True) as c:
            c.execute(f"DROP DATABASE {name} WITH (FORCE)")


def test_webhook_test_needs_manage_even_with_url(client, team, local_webhooks):
    o = team["u"]["owner"]
    client.patch(f"/workspaces/{team['wid']}", json={"webhook_url": local_webhooks}, headers=o.h)
    assert client.post(f"/workspaces/{team['wid']}/webhook/test", headers=team["u"]["member"].h).status_code == 403
    assert client.post(f"/workspaces/{team['wid']}/webhook/test", headers=team["u"]["admin"].h).json()["ok"] is True
    assert STATE.hooks


# ---- lead decisions (10 Nov): clients take no seats; clients use support for their own apps only ------------------------

def test_clients_do_not_take_seats(client):
    o = sign_in(client, "owner@example.com")  # free plan: 1 seat, taken by the owner
    a, _ = verified_app(client, o)
    cl = invite_as(client, o, "client@example.com", "client", app_ids=[a["id"]])
    w = client.get(f"/workspaces/{o.wid}", headers=o.h).json()
    assert w["usage"]["members"] == 1 and w["usage"]["clients"] == 1
    # a viewer still needs a seat
    r = client.post(f"/workspaces/{o.wid}/invites", json={"email": "v@example.com", "role": "viewer"}, headers=o.h)
    assert r.status_code == 403 and "seat" in r.json()["detail"]
    # pending client invites don't hold seats either
    client.patch(f"/admin/workspaces/{o.wid}", json={"plan": "maker"}, headers=A)  # 2 seats
    assert client.post(f"/workspaces/{o.wid}/invites", json={"email": "c2@example.com", "role": "client", "app_ids": []},
                       headers=o.h).status_code == 201
    v = invite_as(client, o, "v@example.com", "viewer")
    # seats now full: turning the client into a teammate is refused, staying a client is fine
    r = client.patch(f"/workspaces/{o.wid}/members/{cl.user['id']}", json={"role": "member"}, headers=o.h)
    assert r.status_code == 403 and "seat" in r.json()["detail"]
    client.delete(f"/workspaces/{o.wid}/members/{v.user['id']}", headers=o.h)
    assert client.patch(f"/workspaces/{o.wid}/members/{cl.user['id']}", json={"role": "member"}, headers=o.h).status_code == 200


def test_clients_support_tickets_for_their_apps_only(client, team):
    from helpers import outbox
    o, cl, wid = team["u"]["owner"], team["u"]["client"], team["wid"]
    new = lambda u, **kw: client.post(f"/workspaces/{wid}/support/tickets",  # noqa: E731
                                      json={"subject": "Leak?", "category": "finding", "message": "Is this real?", **kw}, headers=u.h)
    # clients must name one of their apps
    assert new(cl).status_code == 422
    assert new(cl, app_id=team["b"]["id"]).status_code == 422
    mine = new(cl, app_id=team["a"]["id"]).json()
    assert mine["app"]["id"] == team["a"]["id"] and mine["created_by"] == "client@example.com"
    # the team sees it and replies; the client sees teammates' emails masked
    on_a = new(team["u"]["member"], app_id=team["a"]["id"]).json()
    on_b = new(o, app_id=team["b"]["id"]).json()
    general = new(o).json()
    client.post(f"/support/tickets/{mine['id']}/messages", json={"body": "Looking at it"}, headers=o.h)
    t = client.get(f"/support/tickets/{mine['id']}", headers=cl.h).json()
    assert [m["by"] for m in t["messages"]] == ["client@example.com", "o•••@example.com"]
    assert "owner@example.com" not in str(t)
    assert client.get(f"/support/tickets/{on_a['id']}", headers=cl.h).json()["created_by"] == "m•••@example.com"
    for other in (on_b, general):
        assert client.get(f"/support/tickets/{other['id']}", headers=cl.h).status_code == 404
        assert client.post(f"/support/tickets/{other['id']}/messages", json={"body": "x"}, headers=cl.h).status_code == 404
    lst = client.get(f"/workspaces/{wid}/support/tickets", headers=cl.h).json()
    assert {x["id"] for x in lst["tickets"]} == {mine["id"], on_a["id"]} and sum(lst["counts"].values()) == 2
    assert len(client.get(f"/workspaces/{wid}/support/tickets", headers=o.h).json()["tickets"]) == 4
    # clients reply and close their tickets; the owner still sees the real email
    assert client.post(f"/support/tickets/{mine['id']}/messages", json={"body": "Thanks"}, headers=cl.h).status_code == 201
    assert client.post(f"/support/tickets/{mine['id']}/close", headers=cl.h).json()["status"] == "closed"
    assert client.get(f"/support/tickets/{mine['id']}", headers=o.h).json()["created_by"] == "client@example.com"
    # losing access to the app hides its tickets
    client.put(f"/workspaces/{wid}/members/{cl.user['id']}/apps", json={"app_ids": []}, headers=o.h)
    assert client.get(f"/support/tickets/{mine['id']}", headers=cl.h).status_code == 404
    assert client.get(f"/workspaces/{wid}/support/tickets", headers=cl.h).json()["tickets"] == []
    assert any("We've got your ticket" in m["subject"] for m in outbox("client@example.com"))
