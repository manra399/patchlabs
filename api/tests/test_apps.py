"""Monitored apps: create, verify, list, detail, patch, delete, run-now and plan limits."""
import uuid

from helpers import A, STATE, add_repo, claim, create_app, finish, sign_in, sql, verified_app, verify


def test_create_app_returns_verification(client):
    u = sign_in(client, "owner@example.com")
    a = create_app(client, u, "Acme/Shop", client_label="Bakery Ltd")
    assert a["repo"] == "Acme/Shop" and a["branch"] == "main" and a["client_label"] == "Bakery Ltd"
    assert a["verified"] is False and a["schedule"] == "monthly" and a["next_check_at"] is None and a["badge_public"] is False
    assert a["last_check"] is None and a["open_check_id"] is None
    assert a["verify"]["file"] == "patchlabs-verify.txt" and a["verify"]["code"].startswith("patchlabs-")
    assert a["verify"]["add_url"] == f"https://github.com/Acme/Shop/new/main?filename=patchlabs-verify.txt&value={a['verify']['code']}"


def test_create_app_validation(client):
    u = sign_in(client, "owner@example.com")
    assert client.post(f"/workspaces/{u.wid}/apps", json={"repo": "nope"}, headers=u.h).status_code == 422
    r = client.post(f"/workspaces/{u.wid}/apps", json={"repo": "acme/missing"}, headers=u.h)
    assert r.status_code == 422 and "couldn't find" in r.json()["detail"]
    assert client.post(f"/workspaces/{u.wid}/apps", json={"repo": "acme/x", "schedule": "daily"}, headers=u.h).status_code == 422
    assert client.post(f"/workspaces/{u.wid}/apps", json={"repo": "acme/x"}).status_code == 401
    other = sign_in(client, "other@example.com")
    add_repo("acme/x")
    assert client.post(f"/workspaces/{u.wid}/apps", json={"repo": "acme/x"}, headers=other.h).status_code == 404


def test_plan_limits_apps_and_schedules(client):
    u = sign_in(client, "owner@example.com")
    add_repo("acme/a")
    r = client.post(f"/workspaces/{u.wid}/apps", json={"repo": "acme/a", "schedule": "weekly"}, headers=u.h)
    assert r.status_code == 403 and "weekly" in r.json()["detail"]
    create_app(client, u, "acme/a")
    add_repo("acme/b")
    r = client.post(f"/workspaces/{u.wid}/apps", json={"repo": "acme/b"}, headers=u.h)
    assert r.status_code == 403 and "allows 1 app" in r.json()["detail"]
    client.patch(f"/admin/workspaces/{u.wid}", json={"plan": "maker"}, headers=A)
    create_app(client, u, "acme/b", schedule="weekly")
    create_app(client, u, "acme/c")
    add_repo("acme/d")
    assert client.post(f"/workspaces/{u.wid}/apps", json={"repo": "acme/d"}, headers=u.h).status_code == 403
    client.patch(f"/admin/workspaces/{u.wid}", json={"app_limit": 4}, headers=A)
    create_app(client, u, "acme/d")


def test_duplicate_repo_in_workspace(client):
    u = sign_in(client, "owner@example.com")
    client.patch(f"/admin/workspaces/{u.wid}", json={"plan": "maker"}, headers=A)
    create_app(client, u, "acme/shop")
    r = client.post(f"/workspaces/{u.wid}/apps", json={"repo": "https://github.com/ACME/shop"}, headers=u.h)
    assert r.status_code == 409
    other = sign_in(client, "other@example.com")
    create_app(client, other, "acme/shop")  # other workspaces may add the same repo


def test_verify_app(client):
    u = sign_in(client, "owner@example.com")
    a = create_app(client, u)
    r = client.post(f"/apps/{a['id']}/verify", headers=u.h)
    assert r.status_code == 409 and "patchlabs-verify.txt" in r.json()["detail"]
    STATE.files["acme/shop"] = "wrong code"
    assert client.post(f"/apps/{a['id']}/verify", headers=u.h).status_code == 409
    v = verify(client, u, a)
    assert v["verified"] is True and v["check_id"]
    k = sql("SELECT status, trigger, verified_at, email FROM checks WHERE id = %s", (v["check_id"],))[0]
    assert k["status"] == "queued" and k["trigger"] == "verify" and k["verified_at"] and k["email"] == "owner@example.com"
    g = client.get(f"/apps/{a['id']}", headers=u.h).json()
    assert g["verified"] is True and "verify" not in g and g["open_check_id"] == v["check_id"]
    days = sql("SELECT extract(epoch FROM next_check_at - now()) / 86400 AS d FROM apps")[0]["d"]
    assert 29.9 < float(days) <= 30
    # verifying again is a no-op and doesn't queue another check
    assert client.post(f"/apps/{a['id']}/verify", headers=u.h).json() == {"verified": True, "check_id": None}
    assert sql("SELECT count(*) AS n FROM checks")[0]["n"] == 1
    # the queued app check skips email verification and is claimable
    assert claim(client)["id"] == v["check_id"]


def test_list_and_detail(client):
    u = sign_in(client, "owner@example.com")
    a, cid = verified_app(client, u)
    claim(client)
    finish(client, cid, "done", ["profiles", "orders"])
    apps = client.get(f"/workspaces/{u.wid}/apps", headers=u.h).json()["apps"]
    assert len(apps) == 1
    x = apps[0]
    assert set(x) >= {"id", "repo", "client_label", "verified", "schedule", "next_check_at", "badge_public", "last_check", "open_check_id"}
    assert x["last_check"]["id"] == cid and x["last_check"]["status"] == "done" and x["last_check"]["tables_leaking"] == ["profiles", "orders"]
    assert x["open_check_id"] is None
    d = client.get(f"/apps/{a['id']}", headers=u.h).json()
    assert d["checks"] == [{"id": cid, "status": "done", "trigger": "verify", "created_at": d["checks"][0]["created_at"],
                            "finished_at": d["checks"][0]["finished_at"], "tables_leaking": ["profiles", "orders"], "lab_proof_passed": True}]
    assert d["diff"]["new_leaks"] == ["profiles", "orders"] and d["diff"]["fixed"] == [] and d["diff"]["still_leaking"] == []
    assert "cost" not in str(d).lower()


def test_app_access_control(client):
    u = sign_in(client, "owner@example.com")
    a = create_app(client, u)
    other = sign_in(client, "other@example.com")
    for method, path in (("get", f"/apps/{a['id']}"), ("patch", f"/apps/{a['id']}"), ("delete", f"/apps/{a['id']}"),
                         ("post", f"/apps/{a['id']}/verify"), ("post", f"/apps/{a['id']}/checks")):
        kw = {"json": {}} if method in ("patch", "post") else {}
        assert getattr(client, method)(path, headers=other.h, **kw).status_code == 404
        assert getattr(client, method)(path, **kw).status_code == 401
    assert client.get(f"/apps/{uuid.uuid4()}", headers=u.h).status_code == 404
    assert client.get("/apps/garbage", headers=u.h).status_code == 404
    assert client.get(f"/workspaces/{u.wid}/apps", headers=other.h).status_code == 404


def test_patch_app(client):
    u = sign_in(client, "owner@example.com")
    a, _ = verified_app(client, u)
    r = client.patch(f"/apps/{a['id']}", json={"client_label": "Client A", "badge_public": True}, headers=u.h)
    assert r.status_code == 200 and r.json()["client_label"] == "Client A" and r.json()["badge_public"] is True
    assert client.patch(f"/apps/{a['id']}", json={"schedule": "weekly"}, headers=u.h).status_code == 403
    r = client.patch(f"/apps/{a['id']}", json={"schedule": "off"}, headers=u.h)
    assert r.json()["schedule"] == "off" and r.json()["next_check_at"] is None
    client.patch(f"/admin/workspaces/{u.wid}", json={"plan": "maker"}, headers=A)
    r = client.patch(f"/apps/{a['id']}", json={"schedule": "weekly"}, headers=u.h)
    assert r.json()["schedule"] == "weekly" and r.json()["next_check_at"] is not None
    r = client.patch(f"/apps/{a['id']}", json={"client_label": None}, headers=u.h)
    assert r.json()["client_label"] is None and r.json()["badge_public"] is True
    assert client.patch(f"/apps/{a['id']}", json={"schedule": "hourly"}, headers=u.h).status_code == 422


def test_schedule_on_unverified_app_has_no_next_check(client):
    u = sign_in(client, "owner@example.com")
    client.patch(f"/admin/workspaces/{u.wid}", json={"plan": "maker"}, headers=A)
    a = create_app(client, u)
    assert client.patch(f"/apps/{a['id']}", json={"schedule": "weekly"}, headers=u.h).json()["next_check_at"] is None


def test_run_now(client):
    u = sign_in(client, "owner@example.com")
    a = create_app(client, u)
    r = client.post(f"/apps/{a['id']}/checks", headers=u.h)
    assert r.status_code == 409 and "Verify" in r.json()["detail"]
    verify(client, u, a)
    r = client.post(f"/apps/{a['id']}/checks", headers=u.h)
    assert r.status_code == 409 and "already" in r.json()["detail"]
    cid = claim(client)["id"]
    assert client.post(f"/apps/{a['id']}/checks", headers=u.h).status_code == 409  # running counts as open
    finish(client, cid, "no_leaks")
    r = client.post(f"/apps/{a['id']}/checks", headers=u.h)
    assert r.status_code == 201 and r.json()["status"] == "queued"
    assert sql("SELECT trigger FROM checks WHERE id = %s", (r.json()["check_id"],))[0]["trigger"] == "manual"


def test_monthly_run_limit(client):
    u = sign_in(client, "owner@example.com")
    a, cid = verified_app(client, u)
    claim(client)
    finish(client, cid, "no_leaks")
    for _ in range(4):  # free: 4 manual runs a month (the first verify check doesn't count)
        r = client.post(f"/apps/{a['id']}/checks", headers=u.h)
        assert r.status_code == 201, r.text
        finish(client, claim(client)["id"], "no_leaks")
    r = client.post(f"/apps/{a['id']}/checks", headers=u.h)
    assert r.status_code == 429 and "4 runs" in r.json()["detail"]
    assert client.get(f"/workspaces/{u.wid}", headers=u.h).json()["usage"]["runs_this_month"] == 4
    # last month's runs don't count
    sql("UPDATE usage_events SET created_at = now() - interval '40 days'")
    assert client.post(f"/apps/{a['id']}/checks", headers=u.h).status_code == 201


def test_delete_app_cascades(client):
    u = sign_in(client, "owner@example.com")
    a, cid = verified_app(client, u)
    assert client.delete(f"/apps/{a['id']}", headers=u.h).json() == {"ok": True}
    assert sql("SELECT count(*) AS n FROM checks")[0]["n"] == 0
    assert sql("SELECT count(*) AS n FROM check_events")[0]["n"] == 0
    assert client.get(f"/apps/{a['id']}", headers=u.h).status_code == 404
    assert client.get(f"/checks/{cid}").status_code == 404


def test_members_can_see_app_checks_via_public_check_endpoint(client):
    u = sign_in(client, "owner@example.com")
    a, cid = verified_app(client, u)
    g = client.get(f"/checks/{cid}").json()
    assert g["status"] == "queued" and g["app_id"] == a["id"] and "verify" not in g
