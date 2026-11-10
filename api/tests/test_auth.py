"""Magic-link sign-in, sessions, the signed-in user, and linking earlier anonymous checks."""
from helpers import add_repo, link_param, outbox, sign_in, sql, start


def test_start_sends_magic_link_and_finish_creates_user_and_workspace(client):
    msg = start(client, "Alice@Example.com", next="/app/app?id=1")
    assert msg["to"] == "alice@example.com" and msg["subject"] == "Your PatchLabs sign-in link"
    assert msg["content_type"] == "multipart/alternative" and "PatchLabs" in msg["html"] and "<a href=" in msg["html"]
    tok = link_param(msg, "token")
    assert link_param(msg, "next") == "/app/app?id=1"
    assert len(tok) >= 40
    assert sql("SELECT count(*) AS n FROM login_tokens WHERE token_hash = %s", (tok,))[0]["n"] == 0  # stored hashed only

    r = client.post("/auth/finish", json={"token": tok})
    assert r.status_code == 200
    d = r.json()
    assert d["user"]["email"] == "alice@example.com" and d["next"] == "/app/app?id=1" and d["invite"] is None
    me = client.get("/me", headers={"Authorization": f"Bearer {d['session']}"}).json()
    assert me["user"]["id"] == d["user"]["id"]
    assert len(me["workspaces"]) == 1 and me["workspaces"][0]["role"] == "owner" and me["workspaces"][0]["plan"] == "free"
    assert sql("SELECT count(*) AS n FROM sessions WHERE token_hash = %s", (d["session"],))[0]["n"] == 0


def test_token_is_single_use(client):
    tok = link_param(start(client, "a@example.com"), "token")
    assert client.post("/auth/finish", json={"token": tok}).status_code == 200
    r = client.post("/auth/finish", json={"token": tok})
    assert r.status_code == 400 and "expired" in r.json()["detail"]


def test_expired_token_rejected(client):
    tok = link_param(start(client, "a@example.com"), "token")
    sql("UPDATE login_tokens SET expires_at = now() - interval '1 second'")
    assert client.post("/auth/finish", json={"token": tok}).status_code == 400
    assert client.post("/auth/finish", json={"token": "garbage"}).status_code == 400


def test_second_sign_in_reuses_user_and_workspace(client):
    a = sign_in(client, "a@example.com")
    b = sign_in(client, "A@example.com")
    assert a.user["id"] == b.user["id"] and a.wid == b.wid and a.session != b.session
    assert sql("SELECT count(*) AS n FROM workspaces")[0]["n"] == 1


def test_rate_limit_five_per_email_per_hour_always_202(client):
    for _ in range(5):
        start(client, "spam@example.com")
    r = client.post("/auth/start", json={"email": "spam@example.com"})
    assert r.status_code == 202
    assert len(outbox("spam@example.com")) == 5


def test_unsafe_next_is_dropped(client):
    for bad in ("https://evil.example", "//evil.example", "/\\evil"):
        msg = start(client, f"u{len(bad)}@example.com", next=bad)
        assert "next=" not in msg["text"]


def test_start_validation(client):
    assert client.post("/auth/start", json={"email": "not-an-email"}).status_code == 422
    assert client.post("/auth/start", json={}).status_code == 422


def test_me_requires_valid_session(client):
    assert client.get("/me").status_code == 401
    assert client.get("/me", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.get("/me", headers={"Authorization": "Basic abc"}).status_code == 401
    u = sign_in(client, "a@example.com")
    sql("UPDATE sessions SET expires_at = now() - interval '1 second'")
    assert client.get("/me", headers=u.h).status_code == 401


def test_logout_revokes_session(client):
    u = sign_in(client, "a@example.com")
    assert client.get("/me", headers=u.h).status_code == 200
    assert client.post("/auth/logout", headers=u.h).json() == {"ok": True}
    assert client.get("/me", headers=u.h).status_code == 401
    assert client.post("/auth/logout").json() == {"ok": True}


def test_patch_me(client):
    u = sign_in(client, "a@example.com")
    r = client.patch("/me", json={"name": "  Alice  "}, headers=u.h)
    assert r.status_code == 200 and r.json()["user"]["name"] == "Alice"
    assert client.patch("/me", json={"name": "x" * 101}, headers=u.h).status_code == 422
    assert client.patch("/me", json={"name": "B"}).status_code == 401


def test_anonymous_checks_link_on_sign_in(client):
    add_repo("acme/old")
    r = client.post("/checks", json={"email": "Alice@Example.com", "repo": "acme/old"})
    cid = r.json()["id"]
    client.post("/checks", json={"email": "other@example.com", "repo": "acme/old"})
    u = sign_in(client, "alice@example.com")
    assert sql("SELECT user_id FROM checks WHERE id = %s", (cid,))[0]["user_id"] == __import__("uuid").UUID(u.user["id"])
    checks = client.get("/me/checks", headers=u.h).json()["checks"]
    assert [c["id"] for c in checks] == [cid] and set(checks[0]) == {"id", "repo", "status", "created_at"}
    # a check made after sign-in with the same email shows up too
    client.post("/checks", json={"email": "alice@example.com", "repo": "acme/old"}, headers={"X-Forwarded-For": "9.9.9.9"})
    assert len(client.get("/me/checks", headers=u.h).json()["checks"]) == 2
    assert client.get("/me/checks").status_code == 401
