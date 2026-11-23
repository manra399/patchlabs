"""Magic-link sign-in, sessions, the signed-in user, and linking earlier anonymous checks."""
from helpers import add_repo, link_param, outbox, sign_in, solve, sql, start


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
    r = client.post("/auth/start", json={"email": "spam@example.com", **solve(client)})
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


# ---- sign-in form abuse (Nov 2026: a bot mailed our sign-in link to ~45 strangers) ----------------------------------

import accounts  # noqa: E402


def test_start_needs_a_solved_challenge(client):
    assert client.post("/auth/start", json={"email": "a@example.com"}).status_code == 400
    ch = client.get("/auth/challenge").json()
    assert ch["bits"] == 6 and ch["challenge"].count(".") == 2
    bad = {"challenge": ch["challenge"], "nonce": next(str(n) for n in range(10**6) if not accounts.pow_ok(ch["challenge"], str(n), 6))}
    assert client.post("/auth/start", json={"email": "a@example.com", **bad}).status_code == 400
    forged = solve(client)
    forged["challenge"] = forged["challenge"][:-4] + "0000"
    assert client.post("/auth/start", json={"email": "a@example.com", **forged}).status_code == 400
    assert outbox("a@example.com") == []


def test_challenge_is_single_use(client):
    body = {"email": "b@example.com", **solve(client)}
    assert client.post("/auth/start", json=body).status_code == 202
    r = client.post("/auth/start", json=body)
    assert r.status_code == 400 and "already used" in r.json()["detail"]
    assert len(outbox("b@example.com")) == 1


def test_challenge_too_fast_or_expired(client, monkeypatch):
    monkeypatch.setattr(accounts, "AUTH_MIN_WAIT_S", 60)
    r = client.post("/auth/start", json={"email": "c@example.com", **solve(client)})
    assert r.status_code == 400 and "too fast" in r.json()["detail"]
    monkeypatch.setattr(accounts, "AUTH_MIN_WAIT_S", 0)
    monkeypatch.setattr(accounts, "AUTH_CHALLENGE_TTL_S", -1)
    r = client.post("/auth/start", json={"email": "c@example.com", **solve(client)})
    assert r.status_code == 400 and "expired" in r.json()["detail"]
    assert outbox("c@example.com") == []


def test_honeypot_answers_202_and_sends_nothing(client):
    r = client.post("/auth/start", json={"email": "d@example.com", "website": "http://spam.example", **solve(client)})
    assert r.status_code == 202 and outbox("d@example.com") == []


def test_links_to_new_addresses_are_capped_but_members_still_get_theirs(client, monkeypatch):
    sign_in(client, "member@example.com")
    monkeypatch.setattr(accounts, "AUTH_NEW_EMAILS_PER_HOUR", 3)
    for i in range(6):
        start_code = client.post("/auth/start", json={"email": f"stranger{i}@example.com", **solve(client)}).status_code
        assert start_code == 202
    assert sum(len(outbox(f"stranger{i}@example.com")) for i in range(6)) == 3
    start(client, "member@example.com")  # an existing account is never blocked by the cap
    start(client, "stranger0@example.com")  # nor is a second link to an address already sent one this hour
