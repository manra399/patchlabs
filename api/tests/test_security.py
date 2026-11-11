"""Regression tests for the Nov 2026 security review: one section per finding."""
import json, os, subprocess, sys, threading, time

import pytest

import accounts, core, rls
from helpers import A, API_DIR, STATE, W, add_repo, claim, create_app, finish, link_param, outbox, sign_in, sql, verified_app, verify

MB2 = 2_000_000


# ---- 1. RLS scanner: linear time, statement/name caps, isolated with a hard timeout -----------------------------

ADVERSARIAL = {
    "drop_ws": lambda n: "drop table " + " " * n + "x;",
    "drop_dots": lambda n: "drop table " + "a." * (n // 2) + "a;",
    "dollar_tags": lambda n: "create function f() returns void as " + "".join(f"$t{i}$ " for i in range(n // 7)) + ";",
    "bucket_tuples": lambda n: "insert into storage.buckets (id, public) values " + ",".join("('b',f)" for _ in range(n // 7)) + ";",
    "dollars": lambda n: "$a" * (n // 2),
    "quotes": lambda n: "'" + "''" * (n // 2),
    "comments": lambda n: "/*" + "-- /* ' $x$ " * (n // 12),
    "policy_to": lambda n: "create table t (email text); alter table t enable row level security; create policy p on t for select to "
                           + "anon, " * (n // 6) + "x using (true);",
    "alter_ws": lambda n: "create table t (id int); alter table t enable" + " " * n + "x;",
}


def chunks(gen, total, size=49_000):
    """The same pattern as many statements just under the 50 KB cap."""
    one = gen(size)
    one = one if one.rstrip().endswith(";") else one + ";"
    return "\n".join([one] * max(1, total // len(one)))


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_adversarial_2mb_input_is_fast(name):
    gen = ADVERSARIAL[name]
    for text in (gen(MB2), chunks(gen, MB2)):
        assert len(text) >= MB2 * 0.9
        t = time.time()
        rls.analyze([("supabase/migrations/001.sql", text)])
        assert time.time() - t < 2, f"{name} took {time.time() - t:.2f}s"


def test_norm_and_long_drop_names():
    assert rls.norm('public . "My.Table"') == ("public", "My.Table")
    assert rls.norm("Storage.Buckets") == ("storage", "buckets")
    assert rls.norm("profiles") == ("public", "profiles")
    tables, _ = rls.analyze([("m.sql", "create table keep (id int); drop table " + "k" * 300 + ", missing;")])
    assert [t["name"] for t in tables] == ["keep"]
    tables, _ = rls.analyze([("m.sql", "create table big (id int, email text " + "x" * 60_000 + "); create table small (id int);")])
    assert [t["name"] for t in tables] == ["small"]  # statements over 50 KB are skipped


def test_isolated_runs_in_child_with_hard_timeout():
    assert rls.isolated(sum, ([1, 2, 3],), 5) == 6
    t = time.time()
    with pytest.raises(TimeoutError):
        rls.isolated(time.sleep, (30,), 0.5)
    assert time.time() - t < 3
    with pytest.raises(RuntimeError):
        rls.isolated(int, ("not a number",), 5)


def test_rls_endpoint_times_out_cleanly(client, monkeypatch):
    add_repo("acme/shop")
    STATE.migrations["acme/shop"] = {"001.sql": "create table a (email text);"}
    monkeypatch.setattr(rls, "ANALYZE_TIMEOUT", 0.0001)
    r = client.post("/tools/rls-check", json={"repo": "acme/shop"})
    assert r.status_code == 422 and "full check" in r.json()["detail"]


def test_rls_scan_does_not_freeze_api(client):
    add_repo("evil/app")
    STATE.migrations["evil/app"] = {"001.sql": ADVERSARIAL["dollar_tags"](160_000), "002.sql": ADVERSARIAL["drop_dots"](160_000)}
    res = {}
    th = threading.Thread(target=lambda: res.update(scan=client.post("/tools/rls-check", json={"repo": "evil/app"}).status_code))
    th.start()
    worst = 0.0
    while th.is_alive():
        t = time.time()
        client.get("/health")
        worst = max(worst, time.time() - t)
        time.sleep(0.05)
    th.join()
    assert res["scan"] == 200 and worst < 1.5


def test_total_fetch_is_capped_at_1mb():
    assert rls.MAX_BYTES == 1_000_000


# ---- 2. rate limits use the rightmost X-Forwarded-For; verification needs the exact code -------------------------

def new_check(client, email, xff, repo="acme/shop"):
    add_repo(repo)
    return client.post("/checks", json={"email": email, "repo": repo}, headers={"X-Forwarded-For": xff})


def test_spoofed_xff_does_not_bypass_ip_limit(client):
    codes = [new_check(client, f"u{i}@example.com", f"10.0.0.{i}, 203.0.113.7").status_code for i in range(12)]
    assert codes[:10] == [201] * 10 and codes[10:] == [429, 429]
    assert new_check(client, "z@example.com", "10.9.9.9, 203.0.113.8").status_code == 201  # a different real client


def test_auth_start_ip_limit_uses_rightmost_entry(client, monkeypatch):
    monkeypatch.setattr(accounts, "AUTH_PER_IP_PER_HOUR", 30)
    for i in range(40):
        client.post("/auth/start", json={"email": f"victim{i % 8}@example.com"}, headers={"X-Forwarded-For": f"1.1.1.{i}, 198.51.100.1"})
    assert len(outbox()) == 30


def test_client_ip_helper():
    class R:
        def __init__(self, xff, peer="172.16.0.9"):
            self.headers = {"x-forwarded-for": xff} if xff is not None else {}
            self.client = type("C", (), {"host": peer})()
    assert core.client_ip(R("6.6.6.6, 7.7.7.7")) == "7.7.7.7"
    assert core.client_ip(R(" 8.8.8.8 ")) == "8.8.8.8"
    assert core.client_ip(R(None)) == "172.16.0.9"
    assert core.client_ip(R("")) == "172.16.0.9"
    assert core.ip_hash(R("1.1.1.1, 2.2.2.2")) == core.ip_hash(R("9.9.9.9, 2.2.2.2"))


def test_verification_needs_exactly_the_code(client):
    u = sign_in(client, "owner@example.com")
    a = create_app(client, u)
    code = a["verify"]["code"]
    for content in (f"patchlabs-aaaa\n{code}\n", f"{code} {code}", f"x{code}", f"# codes\n{code}"):
        STATE.files["acme/shop"] = content
        assert client.post(f"/apps/{a['id']}/verify", headers=u.h).status_code == 409, content
    STATE.files["acme/shop"] = f"  {code}\r\n\n"
    assert client.post(f"/apps/{a['id']}/verify", headers=u.h).status_code == 200


# ---- 3. API keys die with their creator's membership -------------------------------------------------------------

def team(client):
    u = sign_in(client, "owner@example.com")
    client.patch(f"/admin/workspaces/{u.wid}", json={"plan": "maker"}, headers=A)
    client.post(f"/workspaces/{u.wid}/invites", json={"email": "bob@example.com"}, headers=u.h)
    bob = sign_in(client, "bob@example.com", invite=link_param(outbox("bob@example.com")[-1], "invite"))
    return u, bob


def test_removed_member_loses_api_keys(client):
    u, bob = team(client)
    a, cid = verified_app(client, u, wid=u.wid)
    key = client.post(f"/workspaces/{u.wid}/api-keys", json={"name": "ci"}, headers=bob.h).json()["key"]
    mine = client.post(f"/workspaces/{u.wid}/api-keys", json={"name": "mine"}, headers=u.h).json()["key"]
    keys = client.get(f"/workspaces/{u.wid}/api-keys", headers=u.h).json()["api_keys"]
    assert {k["name"]: k["created_by_email"] for k in keys} == {"ci": "bob@example.com", "mine": "owner@example.com"}
    assert all(k["created_by"] for k in keys)
    assert client.get(f"/v1/checks/{cid}", headers={"X-API-Key": key}).status_code == 200
    assert client.delete(f"/workspaces/{u.wid}/members/{bob.user['id']}", headers=u.h).status_code == 200
    assert client.get(f"/v1/checks/{cid}", headers={"X-API-Key": key}).status_code == 401
    assert client.post(f"/v1/apps/{a['id']}/checks", headers={"X-API-Key": key}).status_code == 401
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_apps", "arguments": {}}},
                    headers={"X-API-Key": key})
    assert r.json()["result"]["isError"] is True
    assert client.get(f"/v1/checks/{cid}", headers={"X-API-Key": mine}).status_code == 200
    assert [k["name"] for k in client.get(f"/workspaces/{u.wid}/api-keys", headers=u.h).json()["api_keys"]] == ["mine"]


def test_deleted_account_loses_api_keys(client):
    u, bob = team(client)
    a, cid = verified_app(client, u, wid=u.wid)
    key = client.post(f"/workspaces/{u.wid}/api-keys", json={"name": "ci"}, headers=bob.h).json()["key"]
    client.delete("/me", headers=bob.h)
    assert client.get(f"/v1/checks/{cid}", headers={"X-API-Key": key}).status_code == 401


# ---- 4. only recent unverified requests count towards the per-email limit --------------------------------------------

def test_old_unverified_checks_do_not_lock_out(client):
    for i in range(3):
        assert new_check(client, "victim@example.com", f"5.5.5.{i}").status_code == 201
    assert new_check(client, "victim@example.com", "8.8.8.8", repo="victim/real").status_code == 429
    sql("UPDATE checks SET created_at = now() - interval '25 hours'")
    assert new_check(client, "victim@example.com", "8.8.8.8", repo="victim/real").status_code == 201


# ---- 5. email HTML escaping, own-links only, invite and upgrade rate limits ------------------------------------------

def test_html_email_escapes_and_links_only_our_urls():
    out = core.html_email('Note: https://evil.example/x"style="position:fixed\n\nhttps://evil.example/login\n\n'
                          'https://patchlabs.test/check?id=1&x=2\n\nName <b>bold</b> "q"')
    assert 'style="position' not in out and "&quot;style=&quot;" in out
    assert 'href="https://evil.example' not in out
    assert '<a href="https://patchlabs.test/check?id=1&amp;x=2"' in out
    assert "<b>bold</b>" not in out and "&lt;b&gt;" in out and "&quot;q&quot;" in out
    assert 'href="https://patchlabs.test/x"' not in core.html_email('see https://patchlabs.test/x" onclick="y')


def test_invites_are_rate_limited(client):
    u = sign_in(client, "owner@example.com")
    client.patch(f"/admin/workspaces/{u.wid}", json={"plan": "enterprise", "seat_limit": 1000}, headers=A)
    client.patch(f"/workspaces/{u.wid}", json={"name": "Account locked - verify at https://evil.example/login"}, headers=u.h)
    codes = [client.post(f"/workspaces/{u.wid}/invites", json={"email": "stranger@example.com"}, headers=u.h).status_code for _ in range(6)]
    assert codes == [201, 201, 201, 429, 429, 429]
    msgs = outbox("stranger@example.com")
    assert len(msgs) == 3 and 'href="https://evil.example/login"' not in msgs[-1]["html"]
    for i in range(17):
        assert client.post(f"/workspaces/{u.wid}/invites", json={"email": f"p{i}@example.com"}, headers=u.h).status_code == 201
    r = client.post(f"/workspaces/{u.wid}/invites", json={"email": "one-more@example.com"}, headers=u.h)
    assert r.status_code == 429 and "20 invites" in r.json()["detail"]
    sql("UPDATE usage_events SET created_at = now() - interval '25 hours'")
    assert client.post(f"/workspaces/{u.wid}/invites", json={"email": "one-more@example.com"}, headers=u.h).status_code == 201


def test_upgrade_requests_are_rate_limited(client):
    u = sign_in(client, "owner@example.com")
    codes = [client.post(f"/workspaces/{u.wid}/upgrade-request", json={"plan": "maker"}, headers=u.h).status_code for _ in range(5)]
    assert codes == [201, 201, 201, 429, 429]
    assert len(outbox("manraj@patchlabs.dev")) == 3


# ---- 6. no run_dir or local paths in public or exported summaries -----------------------------------------------------

def test_run_dir_and_local_paths_never_leave(client):
    u = sign_in(client, "owner@example.com")
    a, cid = verified_app(client, u)
    claim(client)
    body = {"status": "done", "summary": {"tables_leaking": ["profiles"], "run_dir": "/Users/manraj/runs/x", "lab_proof_passed": True,
            "log": "/home/runner/out.txt", "nested": {"path": "/private/tmp/x", "keep": "orders"}, "files": ["/tmp/a", "public.sql"]},
            "report_md": "r", "fix_sql": "f"}
    client.post(f"/worker/checks/{cid}/result", json=body, headers=W)
    for text in (client.get(f"/checks/{cid}").text, client.get(f"/v1/checks/{cid}", headers={"X-API-Key": client.post(
            f"/workspaces/{u.wid}/api-keys", json={"name": "k"}, headers=u.h).json()["key"]}).text):
        assert "run_dir" not in text and "/Users/" not in text and "/home/" not in text and "/tmp/" not in text
    s = client.get(f"/checks/{cid}").json()["summary"]
    assert s["nested"] == {"keep": "orders"} and s["files"] == ["public.sql"] and s["tables_leaking"] == ["profiles"]
    add_repo("acme/anon")
    anon = client.post("/checks", json={"email": "owner@example.com", "repo": "acme/anon"}).json()["id"]
    sql("UPDATE checks SET status = 'done', summary = %s WHERE id = %s", (json.dumps({"run_dir": "/Users/m/r", "tables_leaking": []}), anon))
    exp = client.get("/me/export", headers=u.h).text
    assert "run_dir" not in exp and "/Users/" not in exp


# ---- 7. monthly runs survive deleting and re-adding an app -----------------------------------------------------------

def test_run_limit_not_reset_by_delete_and_readd(client):
    u = sign_in(client, "owner@example.com")
    a, cid = verified_app(client, u)
    finish(client, claim(client)["id"], "no_leaks")
    for _ in range(4):
        r = client.post(f"/apps/{a['id']}/checks", headers=u.h)
        assert r.status_code == 201
        finish(client, claim(client)["id"], "no_leaks")
    assert client.post(f"/apps/{a['id']}/checks", headers=u.h).status_code == 429
    client.delete(f"/apps/{a['id']}", headers=u.h)
    assert client.get(f"/workspaces/{u.wid}", headers=u.h).json()["usage"]["runs_this_month"] == 4
    a2 = create_app(client, u)
    v = verify(client, u, a2)
    assert v["verified"] is True and v["check_id"] is None and "used up" in v["detail"]
    assert claim(client) is None
    assert client.post(f"/apps/{a2['id']}/checks", headers=u.h).status_code == 429


def test_readded_app_first_check_counts_as_a_run(client):
    u = sign_in(client, "owner@example.com")
    a, cid = verified_app(client, u)
    finish(client, claim(client)["id"], "no_leaks")
    assert client.get(f"/workspaces/{u.wid}", headers=u.h).json()["usage"]["runs_this_month"] == 0  # first ever add is free
    client.delete(f"/apps/{a['id']}", headers=u.h)
    a2, cid2 = verified_app(client, u)
    assert cid2 and client.get(f"/workspaces/{u.wid}", headers=u.h).json()["usage"]["runs_this_month"] == 1


# ---- 8. MCP transport hardening --------------------------------------------------------------------------------------

LIST = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'


def test_mcp_requires_json_and_allowed_origin(client):
    r = client.post("/mcp", content=LIST, headers={"Content-Type": "text/plain"})
    assert r.status_code == 415
    r = client.post("/mcp", content=LIST, headers={"Content-Type": "application/json", "Origin": "https://evil.example"})
    assert r.status_code == 403
    r = client.post("/mcp", content=LIST, headers={"Content-Type": "application/json; charset=utf-8", "Origin": "https://patchlabs.dev"})
    assert r.status_code == 200 and r.json()["result"]["tools"]
    assert client.post("/mcp", content=LIST, headers={"Content-Type": "application/json"}).status_code == 200  # no Origin: CLI clients


def test_mcp_body_and_batch_caps(client):
    big = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"pad": "x" * 300_000}}).encode()
    assert client.post("/mcp", content=big, headers={"Content-Type": "application/json"}).status_code == 413
    batch = json.dumps([{"jsonrpc": "2.0", "id": i, "method": "ping"} for i in range(21)])
    r = client.post("/mcp", content=batch, headers={"Content-Type": "application/json"}).json()
    assert r["error"]["code"] == -32600 and "20" in r["error"]["message"]
    ok = json.dumps([{"jsonrpc": "2.0", "id": i, "method": "ping"} for i in range(20)])
    assert len(client.post("/mcp", content=ok, headers={"Content-Type": "application/json"}).json()) == 20


# ---- 9. safe_next ------------------------------------------------------------------------------------------------------

def test_safe_next():
    for bad in ("//evil.example", "/\\evil.example", "/", "evil", "https://evil.example", "/\t/evil", "/app\x00", "/a\nb", "/a\\b", "", None):
        assert accounts.safe_next(bad) is None, repr(bad)
    for good in ("/app", "/app/app?id=1", "/app/settings#keys"):
        assert accounts.safe_next(good) == good


# ---- 10. webhook address blocklist -------------------------------------------------------------------------------------

def test_ip_blocklist_extras():
    for ip in ("::7f00:1", "::a9fe:a9fe", "64:ff9b::a9fe:a9fe", "64:ff9b:1::1", "2002:a9fe:a9fe::1", "2001:0:4136:e378::1",
               "100.64.0.1", "100.127.255.254", "168.63.129.16", "169.254.169.254", "::ffff:a9fe:a9fe", "::", "0.0.0.0"):
        assert not core.ip_allowed(ip), ip
    assert core.ip_allowed("1.1.1.1") and core.ip_allowed("2606:4700:4700::1111")


# ---- 11. control characters stripped from names and labels -----------------------------------------------------------

def test_control_characters_stripped(client):
    u = sign_in(client, "owner@example.com")
    w = client.patch(f"/workspaces/{u.wid}", json={"name": "Acme\r\nBcc: x@y.z‮  Ltd"}, headers=u.h).json()
    assert w["name"] == "Acme Bcc: x@y.z Ltd"
    assert client.patch("/me", json={"name": "Olive\n\x00Owner "}, headers=u.h).json()["user"]["name"] == "Olive Owner"
    a = create_app(client, u, client_label="Client\nA\t")
    assert a["client_label"] == "Client A"
    assert client.patch(f"/apps/{a['id']}", json={"client_label": "B\x1bC"}, headers=u.h).json()["client_label"] == "B C"
    client.patch(f"/admin/workspaces/{u.wid}", json={"plan": "maker"}, headers=A)
    client.post(f"/workspaces/{u.wid}/invites", json={"email": "bob@example.com"}, headers=u.h)
    assert "\n" not in outbox("bob@example.com")[-1]["subject"]


# ---- 12. receipts need a real key unless PATCHLABS_DEV=1 --------------------------------------------------------------

def test_receipt_key_required_outside_dev():
    env = {k: v for k, v in os.environ.items() if k not in ("RECEIPT_PRIVATE_KEY", "PATCHLABS_DEV")}
    r = subprocess.run([sys.executable, "-c", "import receipts"], cwd=API_DIR, env=env, capture_output=True, text=True)
    assert r.returncode != 0 and "RECEIPT_PRIVATE_KEY is not set" in r.stderr
    r = subprocess.run([sys.executable, "-c", "import receipts"], cwd=API_DIR, env={**env, "PATCHLABS_DEV": "1"}, capture_output=True, text=True)
    assert r.returncode == 0 and "WARNING" in r.stdout


# ---- decisions and answers don't expose teammates' emails publicly -----------------------------------------------------

QUESTION = "Should sellers' emails be public?"


def test_public_views_mask_emails_members_see_them(client):
    u, bob = team(client)
    client.patch(f"/workspaces/{u.wid}/members/{bob.user['id']}", json={"role": "approver"}, headers=u.h)  # approvers decide
    a, cid = verified_app(client, u, wid=u.wid)
    claim(client)
    client.post(f"/worker/checks/{cid}/result", headers=W, json={"status": "done", "fix_sql": "x", "summary": {
        "tables_leaking": ["sellers"], "lab_proof_passed": True, "questions_for_owner": [QUESTION]}})
    r = client.post(f"/checks/{cid}/decision", json={"action": "approve", "accept_charge_gbp": 29}, headers=bob.h).json()
    assert r["decisions"][0]["by_email"] == "bob@example.com" and r["decisions"][0]["by_user_id"] == bob.user["id"]
    client.patch("/me", json={"name": "Olive"}, headers=u.h)
    client.post(f"/checks/{cid}/answers", json={"answers": [{"question": QUESTION, "answer": "No"}]}, headers=u.h)
    for text in (client.get(f"/checks/{cid}").text, client.get(f"/receipts/{cid}").text):
        assert "bob@example.com" not in text and "owner@example.com" not in text
        assert "b\\u2022\\u2022\\u2022@example.com" in text or "b•••@example.com" in text
        assert "Olive" in text and "by_email" not in text and "by_user_id" not in text
    m = client.get(f"/checks/{cid}/decisions", headers=u.h).json()
    assert m["decisions"][0]["by_email"] == "bob@example.com" and m["answers"][0]["by_email"] == "owner@example.com"
    stranger = sign_in(client, "stranger@example.com")
    assert client.get(f"/checks/{cid}/decisions", headers=stranger.h).status_code == 403
    assert client.get(f"/checks/{cid}/decisions").status_code == 401


# ---- frontend end-to-end findings ----------------------------------------------------------------------------------

def test_check_view_has_branch_for_commit_button(client):
    STATE.repos["acme/dev"] = {"full_name": "acme/dev", "default_branch": "develop"}
    cid = client.post("/checks", json={"email": "a@example.com", "repo": "acme/dev"}).json()["id"]
    g = client.get(f"/checks/{cid}").json()
    assert g["branch"] == "develop" and g["verify"]["add_url"].startswith("https://github.com/acme/dev/new/develop?")
    u = sign_in(client, "owner@example.com")
    STATE.repos["acme/app"] = {"full_name": "acme/app", "default_branch": "trunk"}
    a = client.post(f"/workspaces/{u.wid}/apps", json={"repo": "acme/app"}, headers=u.h).json()
    cid = verify(client, u, a)["check_id"]
    assert client.get(f"/checks/{cid}").json()["branch"] == "trunk"


def test_run_limit_message_is_pluralised(client):
    u = sign_in(client, "owner@example.com")
    a, cid = verified_app(client, u)
    finish(client, claim(client)["id"], "no_leaks")
    client.patch(f"/admin/workspaces/{u.wid}", json={"run_limit": 1}, headers=A)
    assert client.post(f"/apps/{a['id']}/checks", headers=u.h).status_code == 201
    finish(client, claim(client)["id"], "no_leaks")
    d = client.post(f"/apps/{a['id']}/checks", headers=u.h).json()["detail"]
    assert d.startswith("You've used your 1 run this month") and "1 runs" not in d
    client.patch(f"/admin/workspaces/{u.wid}", json={"run_limit": 0}, headers=A)
    assert "all 0 runs" in client.post(f"/apps/{a['id']}/checks", headers=u.h).json()["detail"]


def test_every_response_carries_security_headers_and_no_schema(client):
    for path in ("/health", "/nope"):
        h = client.get(path).headers
        assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in h["content-security-policy"] and h["referrer-policy"] == "no-referrer"
        assert h["strict-transport-security"].startswith("max-age=")
    assert client.get("/openapi.json").status_code == 404   # route list (admin, worker) not published
