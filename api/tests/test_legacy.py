"""The endpoints the live site uses today must keep working exactly as before."""
import uuid

from helpers import A, STATE, W, add_repo, claim, finish, outbox, sql


def new_check(client, email="owner@example.com", repo="acme/shop", ip="1.1.1.1"):
    add_repo(repo)
    r = client.post("/checks", json={"email": email, "repo": f"https://github.com/{repo}"}, headers={"X-Forwarded-For": ip})
    assert r.status_code == 201, r.text
    return r.json()


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"ok": True, "db": "ok", "worker_last_seen": None, "queued": 0}


def test_anonymous_check_full_flow(client):
    d = new_check(client)
    assert d["status"] == "awaiting_verification" and d["repo"] == "acme/shop"
    assert d["link"] == f"https://patchlabs.test/check?id={d['id']}"
    mails = outbox("owner@example.com")
    assert len(mails) == 1 and "patchlabs-verify.txt" in mails[0]["text"]
    assert mails[0]["content_type"] == "multipart/alternative" and "<html>" in mails[0]["html"]

    g = client.get(f"/checks/{d['id']}").json()
    assert g["status"] == "awaiting_verification"
    assert g["verify"]["file"] == "patchlabs-verify.txt" and g["verify"]["add_url"].startswith("https://github.com/acme/shop/new/main?")
    assert set(g) == {"id", "repo", "branch", "status", "created_at", "verified_at", "finished_at", "verify", "events", "decisions", "answers",
                      "suppressed_tables", "new_leaks"}
    assert g["branch"] == "main"

    r = client.post(f"/checks/{d['id']}/verify")
    assert r.status_code == 409 and "patchlabs-verify.txt" in r.json()["detail"]

    STATE.files["acme/shop"] = g["verify"]["code"]
    assert client.post(f"/checks/{d['id']}/verify").json() == {"status": "queued"}
    assert client.post(f"/checks/{d['id']}/verify").json() == {"status": "queued"}
    assert client.get("/health").json()["queued"] == 1

    job = claim(client)
    assert job == {"id": d["id"], "repo": "acme/shop"}
    assert claim(client) is None
    assert client.get("/health").json()["worker_last_seen"] is not None

    finish(client, d["id"], "done", ["profiles"])
    g = client.get(f"/checks/{d['id']}").json()
    assert g["status"] == "done" and g["report_md"] == "# Report" and g["fix_sql"]
    assert g["summary"]["tables_leaking"] == ["profiles"]
    assert "cost" not in str(g).lower() and "run_dir" not in g["summary"] and "/Users/" not in str(g)
    assert [e["kind"] for e in g["events"]] == ["requested", "verified", "started", "done"]
    done = outbox("owner@example.com")[-1]
    assert done["subject"] == "Your PatchLabs leak check for acme/shop is ready"
    assert f"https://patchlabs.test/check?id={d['id']}" in done["text"] and f'href="https://patchlabs.test/check?id={d["id"]}"' in done["html"]
    assert f"https://patchlabs.test/check?id={d['id']}" in mails[0]["text"]
    assert not [m for m in outbox() if "check.html" in m["text"] + m["html"]]


def test_verify_falls_back_to_raw_when_rate_limited(client):
    d = new_check(client)
    code = client.get(f"/checks/{d['id']}").json()["verify"]["code"]
    STATE.files["acme/shop"], STATE.contents_status = code, 403
    assert client.post(f"/checks/{d['id']}/verify").json() == {"status": "queued"}


def test_failed_check_sends_no_email_and_hides_error(client):
    d = new_check(client)
    sql("UPDATE checks SET status = 'queued', verified_at = now() WHERE id = %s", (d["id"],))
    claim(client)
    finish(client, d["id"], "failed")
    g = client.get(f"/checks/{d['id']}").json()
    assert g["status"] == "failed" and g["error"].startswith("The check could not finish")
    assert "boom" not in str(g)
    assert len(outbox("owner@example.com")) == 1


def test_check_validation_and_not_found(client):
    assert client.post("/checks", json={"email": "nope", "repo": "a/b"}).status_code == 422
    r = client.post("/checks", json={"email": "a@b.co", "repo": "not a repo"})
    assert r.status_code == 422 and "GitHub repo" in r.json()["detail"]
    r = client.post("/checks", json={"email": "a@b.co", "repo": "acme/missing"})
    assert r.status_code == 422 and "couldn't find" in r.json()["detail"]
    assert client.get("/checks/not-a-uuid").status_code == 404
    assert client.get(f"/checks/{uuid.uuid4()}").status_code == 404
    assert client.post(f"/checks/{uuid.uuid4()}/verify").status_code == 404


def test_open_checks_per_email_limit(client):
    for i in range(3):
        new_check(client, repo=f"acme/r{i}", ip=f"2.2.2.{i}")
    add_repo("acme/r9")
    r = client.post("/checks", json={"email": "owner@example.com", "repo": "acme/r9"}, headers={"X-Forwarded-For": "2.2.2.9"})
    assert r.status_code == 429


def test_per_ip_daily_limit(client):
    for i in range(10):
        new_check(client, email=f"u{i}@example.com", repo=f"acme/r{i}", ip="3.3.3.3")
    add_repo("acme/rx")
    r = client.post("/checks", json={"email": "x@example.com", "repo": "acme/rx"}, headers={"X-Forwarded-For": "3.3.3.3"})
    assert r.status_code == 429


def test_worker_and_admin_auth(client):
    for path in ("/worker/claim", "/worker/heartbeat", f"/worker/checks/{uuid.uuid4()}/result"):
        assert client.post(path, json={"status": "done"}).status_code == 401
        assert client.post(path, json={"status": "done"}, headers=A).status_code == 401
    assert client.post("/worker/heartbeat", headers=W).json() == {"ok": True}
    assert client.get("/admin/checks").status_code == 401
    assert client.get("/admin/checks", headers=W).status_code == 401
    d = new_check(client)
    sql("UPDATE checks SET status = 'queued', verified_at = now() WHERE id = %s", (d["id"],))
    claim(client)
    finish(client, d["id"], "no_leaks")
    rows = client.get("/admin/checks", headers=A).json()["checks"]
    assert rows[0]["id"] == d["id"] and float(rows[0]["cost_usd"]) == 0.42


def test_result_validation(client):
    d = new_check(client)
    assert client.post(f"/worker/checks/{d['id']}/result", json={"status": "weird"}, headers=W).status_code == 422


def test_stale_running_check_is_requeued(client):
    d = new_check(client)
    sql("UPDATE checks SET status = 'running', verified_at = now(), claimed_at = now() - interval '3 hours' WHERE id = %s", (d["id"],))
    assert claim(client)["id"] == d["id"]


def test_cors_preflight_allows_new_methods_and_headers(client):
    r = client.options("/me", headers={"Origin": "https://patchlabs.dev", "Access-Control-Request-Method": "PATCH",
                                       "Access-Control-Request-Headers": "authorization,x-api-key,x-workspace,content-type"})
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == "https://patchlabs.dev"
    for m in ("GET", "POST", "PATCH", "DELETE"):
        assert m in r.headers["access-control-allow-methods"]
    allowed = r.headers["access-control-allow-headers"].lower()
    for h in ("authorization", "x-api-key", "x-workspace", "content-type"):
        assert h in allowed
    r = client.options("/me", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert r.status_code == 400
