"""Admin endpoints, data export and account deletion."""
import uuid

from helpers import A, W, add_repo, claim, finish, link_param, outbox, sign_in, sql, verified_app


def test_admin_requires_token(client):
    for method, path in (("get", "/admin/workspaces"), ("get", "/admin/upgrade-requests"), ("patch", f"/admin/workspaces/{uuid.uuid4()}")):
        kw = {"json": {"plan": "maker"}} if method == "patch" else {}
        assert getattr(client, method)(path, **kw).status_code == 401
        assert getattr(client, method)(path, headers=W, **kw).status_code == 401
    u = sign_in(client, "owner@example.com")
    assert client.get("/admin/workspaces", headers=u.h).status_code == 401


def test_admin_workspaces_and_plan_editor(client):
    u = sign_in(client, "owner@example.com")
    ws = client.get("/admin/workspaces", headers=A).json()["workspaces"]
    assert len(ws) == 1 and ws[0]["id"] == u.wid and ws[0]["members"][0]["email"] == "owner@example.com"
    r = client.patch(f"/admin/workspaces/{u.wid}", json={"plan": "agency", "app_limit": 25}, headers=A)
    assert r.status_code == 200
    w = r.json()
    assert w["plan"] == "agency" and w["limits"]["apps"] == 25 and w["limits"]["seats"] == 10 and w["app_limit"] == 25
    r = client.patch(f"/admin/workspaces/{u.wid}", json={"plan": "enterprise", "run_limit": 5000, "seat_limit": 3}, headers=A).json()
    assert r["limits"] == {"apps": 25, "runs_per_month": 5000, "seats": 3, "schedules": ["off", "weekly", "monthly"]}
    r = client.patch(f"/admin/workspaces/{u.wid}", json={"app_limit": None}, headers=A).json()
    assert r["limits"]["apps"] == 50 and r["plan"] == "enterprise"
    assert client.patch(f"/admin/workspaces/{u.wid}", json={"plan": "gold"}, headers=A).status_code == 422
    assert client.patch(f"/admin/workspaces/{u.wid}", json={"app_limit": -1}, headers=A).status_code == 422
    assert client.patch(f"/admin/workspaces/{uuid.uuid4()}", json={"plan": "maker"}, headers=A).status_code == 404
    assert client.get(f"/workspaces/{u.wid}", headers=u.h).json()["plan"] == "enterprise"


def test_export(client):
    add_repo("acme/anon")
    anon = client.post("/checks", json={"email": "owner@example.com", "repo": "acme/anon"}).json()["id"]
    u = sign_in(client, "owner@example.com")
    client.patch("/me", json={"name": "Olive"}, headers=u.h)
    a, cid = verified_app(client, u)
    finish(client, claim(client)["id"], "no_leaks")  # the anonymous check isn't verified, so the app check is claimed
    client.post(f"/workspaces/{u.wid}/api-keys", json={"name": "CI"}, headers=u.h)
    client.post(f"/workspaces/{u.wid}/upgrade-request", json={"plan": "maker"}, headers=u.h)
    r = client.get("/me/export", headers=u.h)
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    d = r.json()
    assert d["user"]["email"] == "owner@example.com" and d["user"]["name"] == "Olive"
    assert len(d["sessions"]) == 1 and "token_hash" not in str(d)
    assert d["workspaces"][0]["apps"][0]["repo"] == "acme/shop"
    assert [k["id"] for k in d["anonymous_checks"]] == [anon] and d["anonymous_checks"][0]["events"]
    assert d["api_keys_created"][0]["name"] == "CI" and "key_hash" not in d["api_keys_created"][0]
    assert d["upgrade_requests"][0]["plan"] == "maker"
    assert "cost" not in r.text.lower()
    assert client.get("/me/export").status_code == 401


def test_delete_me_solely_owned_workspace(client):
    add_repo("acme/anon")
    anon = client.post("/checks", json={"email": "owner@example.com", "repo": "acme/anon"}).json()["id"]
    keep = client.post("/checks", json={"email": "someone@example.com", "repo": "acme/anon"}).json()["id"]
    u = sign_in(client, "owner@example.com")
    a, cid = verified_app(client, u)
    client.post(f"/workspaces/{u.wid}/api-keys", json={"name": "CI"}, headers=u.h)
    r = client.delete("/me", headers=u.h)
    assert r.json() == {"ok": True, "deleted_workspaces": 1}
    assert client.get("/me", headers=u.h).status_code == 401
    for table in ("users", "sessions", "workspaces", "workspace_members", "apps", "api_keys", "login_tokens"):
        assert sql(f"SELECT count(*) AS n FROM {table}")[0]["n"] == 0, table
    ids = [str(r["id"]) for r in sql("SELECT id FROM checks")]
    assert ids == [keep] and anon not in ids


def test_delete_me_shared_workspace_passes_to_teammate(client):
    u = sign_in(client, "owner@example.com")
    client.patch(f"/admin/workspaces/{u.wid}", json={"plan": "maker"}, headers=A)
    client.post(f"/workspaces/{u.wid}/invites", json={"email": "bob@example.com"}, headers=u.h)
    bob = sign_in(client, "bob@example.com", invite=link_param(outbox("bob@example.com")[-1], "invite"))
    a, cid = verified_app(client, u, wid=u.wid)
    assert client.delete("/me", headers=u.h).json()["deleted_workspaces"] == 0
    w = client.get(f"/workspaces/{u.wid}", headers=bob.h).json()
    assert [(m["email"], m["role"]) for m in w["members"]] == [("bob@example.com", "owner")]
    assert client.get(f"/apps/{a['id']}", headers=bob.h).status_code == 200
    assert sql("SELECT email FROM checks WHERE id = %s", (cid,))[0]["email"] == ""  # their address is scrubbed from app checks
    assert client.delete("/me").status_code == 401
