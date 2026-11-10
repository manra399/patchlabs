"""CI endpoints authenticated with a workspace API key."""
import uuid

from helpers import claim, finish, sign_in, verified_app


def key_for(client, u):
    return {"X-API-Key": client.post(f"/workspaces/{u.wid}/api-keys", json={"name": "CI"}, headers=u.h).json()["key"]}


def test_ci_run_and_poll(client):
    u = sign_in(client, "owner@example.com")
    a, cid = verified_app(client, u)
    k = key_for(client, u)
    r = client.post(f"/v1/apps/{a['id']}/checks", headers=k)
    assert r.status_code == 409  # the first check is still queued
    claim(client)
    finish(client, cid, "done", ["profiles"])
    r = client.post(f"/v1/apps/{a['id']}/checks", headers=k)
    assert r.status_code == 201
    new = r.json()["check_id"]
    g = client.get(f"/v1/checks/{new}", headers=k).json()
    assert g["status"] == "queued" and g["trigger"] == "api" and g["finished"] is False and g["summary"] is None
    claim(client)
    finish(client, new, "done", ["profiles"])
    g = client.get(f"/v1/checks/{new}", headers=k).json()
    assert g["finished"] and g["leaks_found"] and g["tables_leaking"] == ["profiles"] and g["lab_proof_passed"] is True
    assert g["url"] == f"https://patchlabs.test/check?id={new}"
    assert "cost" not in str(g).lower() and "run_dir" not in g["summary"]
    keys = client.get(f"/workspaces/{u.wid}/api-keys", headers=u.h).json()["api_keys"]
    assert keys[0]["last_used_at"] is not None


def test_ci_auth_failures(client):
    u = sign_in(client, "owner@example.com")
    a, cid = verified_app(client, u)
    assert client.post(f"/v1/apps/{a['id']}/checks").status_code == 401
    assert client.post(f"/v1/apps/{a['id']}/checks", headers={"X-API-Key": "pl_live_wrong"}).status_code == 401
    assert client.post(f"/v1/apps/{a['id']}/checks", headers={"X-API-Key": "nope"}).status_code == 401
    assert client.post(f"/v1/apps/{a['id']}/checks", headers=u.h).status_code == 401  # a session isn't an API key
    other = sign_in(client, "other@example.com")
    ok = key_for(client, other)
    assert client.post(f"/v1/apps/{a['id']}/checks", headers=ok).status_code == 403
    assert client.get(f"/v1/checks/{cid}", headers=ok).status_code == 403
    assert client.get(f"/v1/checks/{uuid.uuid4()}", headers=ok).status_code == 404
    assert client.post(f"/v1/apps/{uuid.uuid4()}/checks", headers=ok).status_code == 404
    k = key_for(client, u)
    kid = client.get(f"/workspaces/{u.wid}/api-keys", headers=u.h).json()["api_keys"][0]["id"]
    assert client.get(f"/v1/checks/{cid}", headers=k).status_code == 200
    client.delete(f"/workspaces/{u.wid}/api-keys/{kid}", headers=u.h)
    assert client.get(f"/v1/checks/{cid}", headers=k).status_code == 401


def test_ci_anonymous_checks_not_visible(client):
    from helpers import add_repo
    add_repo("acme/anon")
    anon = client.post("/checks", json={"email": "x@example.com", "repo": "acme/anon"}).json()["id"]
    u = sign_in(client, "owner@example.com")
    assert client.get(f"/v1/checks/{anon}", headers=key_for(client, u)).status_code == 404


def test_ci_respects_run_limit(client):
    u = sign_in(client, "owner@example.com")
    a, cid = verified_app(client, u)
    finish(client, claim(client)["id"], "no_leaks")
    k = key_for(client, u)
    for _ in range(4):
        assert client.post(f"/v1/apps/{a['id']}/checks", headers=k).status_code == 201
        finish(client, claim(client)["id"], "no_leaks")
    assert client.post(f"/v1/apps/{a['id']}/checks", headers=k).status_code == 429
