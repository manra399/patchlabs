"""Signed webhooks, suppressed_tables / new_leaks on check views, report cost stripping, worker run-folder retention."""
import hashlib, hmac, importlib.util, json, os, time

import pytest

from helpers import A, ROOT, STATE, W, add_repo, claim, finish, link_param, outbox, sign_in, sql, verified_app


def verify_sig(hook, secret, tolerance=300):
    """The docs' verification recipe."""
    ts, sig = hook["headers"]["X-PatchLabs-Timestamp"], hook["headers"]["X-PatchLabs-Signature"]
    assert abs(time.time() - int(ts)) <= tolerance
    expected = "v1=" + hmac.new(secret.encode(), f"{ts}.".encode() + hook["raw"], hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)


def team(client):
    u = sign_in(client, "owner@example.com")
    client.patch(f"/admin/workspaces/{u.wid}", json={"plan": "maker"}, headers=A)
    client.post(f"/workspaces/{u.wid}/invites", json={"email": "bob@example.com"}, headers=u.h)
    bob = sign_in(client, "bob@example.com", invite=link_param(outbox("bob@example.com")[-1], "invite"))
    return u, bob


# ---- 1. signed webhooks ----------------------------------------------------------------------------------------------

def test_secret_created_with_first_url_and_owner_only(client, local_webhooks):
    u, bob = team(client)
    assert client.get(f"/workspaces/{u.wid}", headers=u.h).json()["webhook_secret"] is None
    w = client.patch(f"/workspaces/{u.wid}", json={"webhook_url": local_webhooks}, headers=u.h).json()
    secret = w["webhook_secret"]
    assert secret.startswith("whsec_") and len(secret) == len("whsec_") + 43
    assert client.get(f"/workspaces/{u.wid}", headers=bob.h).json()["webhook_secret"] is None  # members never see it
    assert client.patch(f"/workspaces/{u.wid}", json={"webhook_url": local_webhooks + "?x=1"}, headers=u.h).json()["webhook_secret"] == secret
    assert client.patch(f"/workspaces/{u.wid}", json={"webhook_url": None}, headers=u.h).json()["webhook_secret"] == secret
    assert "whsec_" not in client.get("/admin/workspaces", headers=A).text
    assert "whsec_" not in client.get("/me/export", headers=u.h).text


def test_rotate_secret(client, local_webhooks):
    u, bob = team(client)
    old = client.patch(f"/workspaces/{u.wid}", json={"webhook_url": local_webhooks}, headers=u.h).json()["webhook_secret"]
    assert client.post(f"/workspaces/{u.wid}/webhook/rotate-secret", headers=bob.h).status_code == 403
    assert client.post(f"/workspaces/{u.wid}/webhook/rotate-secret").status_code == 401
    other = sign_in(client, "other@example.com")
    assert client.post(f"/workspaces/{u.wid}/webhook/rotate-secret", headers=other.h).status_code == 404
    r = client.post(f"/workspaces/{u.wid}/webhook/rotate-secret", headers=u.h)
    new = r.json()["webhook_secret"]
    assert r.status_code == 200 and new.startswith("whsec_") and new != old
    assert client.get(f"/workspaces/{u.wid}", headers=u.h).json()["webhook_secret"] == new
    client.post(f"/workspaces/{u.wid}/webhook/test", headers=u.h)
    assert verify_sig(STATE.hooks[-1], new) and not verify_sig(STATE.hooks[-1], old)


def test_test_and_finished_events_are_signed(client, local_webhooks):
    u = sign_in(client, "owner@example.com")
    secret = client.patch(f"/workspaces/{u.wid}", json={"webhook_url": local_webhooks}, headers=u.h).json()["webhook_secret"]
    assert client.post(f"/workspaces/{u.wid}/webhook/test", headers=u.h).json()["ok"]
    a, cid = verified_app(client, u)
    claim(client)
    finish(client, cid, "done", ["profiles"])
    test_hook, done_hook = STATE.hooks[-2], STATE.hooks[-1]
    assert test_hook["body"]["event"] == "test" and done_hook["body"]["event"] == "check.finished"
    for hook in (test_hook, done_hook):
        assert hook["headers"]["X-PatchLabs-Signature"].startswith("v1=") and verify_sig(hook, secret)
        tampered = dict(hook, raw=hook["raw"].replace(b"profiles", b"nothing!") if b"profiles" in hook["raw"] else hook["raw"] + b" ")
        assert not verify_sig(tampered, secret)


def test_webhook_saved_before_signing_gets_a_secret_on_delivery(client, local_webhooks):
    u = sign_in(client, "owner@example.com")
    client.patch(f"/workspaces/{u.wid}", json={"webhook_url": local_webhooks}, headers=u.h)
    sql("UPDATE workspaces SET webhook_secret = NULL")
    a, cid = verified_app(client, u)
    claim(client)
    finish(client, cid, "no_leaks")
    secret = sql("SELECT webhook_secret FROM workspaces")[0]["webhook_secret"]
    assert secret and verify_sig(STATE.hooks[-1], secret)


# ---- 2. suppressed_tables and new_leaks on the check views -------------------------------------------------------------

def test_check_views_carry_suppressed_and_new_leaks(client):
    u = sign_in(client, "owner@example.com")
    key = {"X-API-Key": client.post(f"/workspaces/{u.wid}/api-keys", json={"name": "ci"}, headers=u.h).json()["key"]}
    a, c1 = verified_app(client, u)
    claim(client)
    finish(client, c1, "done", ["profiles", "sellers"])
    for g in (client.get(f"/checks/{c1}").json(), client.get(f"/v1/checks/{c1}", headers=key).json()):
        assert g["suppressed_tables"] == [] and g["new_leaks"] == ["profiles", "sellers"]
    client.post(f"/checks/{c1}/decision", json={"action": "reject", "tables": ["sellers"]}, headers=u.h)
    c2 = client.post(f"/apps/{a['id']}/checks", headers=u.h).json()["check_id"]
    assert client.get(f"/checks/{c2}").json()["suppressed_tables"] == []  # not finished yet
    claim(client)
    finish(client, c2, "done", ["profiles", "sellers", "messages"])
    for g in (client.get(f"/checks/{c2}").json(), client.get(f"/v1/checks/{c2}", headers=key).json()):
        assert g["suppressed_tables"] == ["sellers"] and g["new_leaks"] == ["messages"]
    assert client.get(f"/checks/{c1}").json()["suppressed_tables"] == ["sellers"]  # the team's current call applies
    add_repo("acme/anon")
    anon = client.post("/checks", json={"email": "x@example.com", "repo": "acme/anon"}).json()["id"]
    sql("UPDATE checks SET status = 'done', finished_at = now(), summary = '{\"tables_leaking\": [\"t\"]}' WHERE id = %s", (anon,))
    g = client.get(f"/checks/{anon}").json()
    assert g["suppressed_tables"] == [] and g["new_leaks"] == []


# ---- 3. model cost stripped from stored reports --------------------------------------------------------------------------

def test_report_md_cost_stripped_outside_admin(client):
    add_repo("acme/anon")
    cid = client.post("/checks", json={"email": "owner@example.com", "repo": "acme/anon"}).json()["id"]
    md = "# Report\n\nFixed by haiku in 3.5 min, model cost $0.46. Proof passed.\nRetry: sonnet, Model cost $12, then done."
    sql("UPDATE checks SET status = 'done', finished_at = now(), report_md = %s, summary = '{}' WHERE id = %s", (md, cid))
    r = client.get(f"/checks/{cid}").json()["report_md"]
    assert r == "# Report\n\nFixed by haiku in 3.5 min. Proof passed.\nRetry: sonnet, then done."
    u = sign_in(client, "owner@example.com")
    exp = client.get("/me/export", headers=u.h).json()
    assert exp["anonymous_checks"][0]["report_md"] == r and "$0.46" not in json.dumps(exp)
    tool = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "get_check", "arguments": {"check_id": cid}}})
    assert "model cost" not in tool.text.lower()


# ---- 4. worker run-folder retention --------------------------------------------------------------------------------------

@pytest.fixture
def worker(tmp_path, monkeypatch):
    pipeline = tmp_path / "leakcheck" / "run.py"
    pipeline.parent.mkdir()
    pipeline.write_text("")
    env = tmp_path / "worker.env"
    env.write_text(f"API_URL=http://127.0.0.1:9\nWORKER_TOKEN=x\nPIPELINE={pipeline}\n")
    monkeypatch.setenv("PATCHLABS_ENV", str(env))
    spec = importlib.util.spec_from_file_location("plworker", os.path.join(ROOT, "worker", "worker.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod, pipeline


def test_worker_retention_selects_only_old_run_folders(worker, tmp_path):
    mod, pipeline = worker
    runs = pipeline.parent / "runs"
    assert mod.runs_dir(str(pipeline)) == str(runs)
    runs.mkdir()
    now = time.time()
    stamp = lambda days: time.strftime("%Y%m%d-%H%M%S", time.localtime(now - days * 86400))
    old, older, recent = stamp(31), stamp(400), stamp(29)
    for name in (old, older, recent, "permtest", "20261399-000000", stamp(31) + "-x", "notes"):
        (runs / name).mkdir(exist_ok=True)
    (runs / old / "repo").mkdir()
    (runs / old / "repo" / "f.sql").write_text("x")
    (runs / "20200101-000000.txt").write_text("a file named like a run")
    outside = tmp_path / "precious"
    outside.mkdir()
    (runs / "20200102-000000").symlink_to(outside)
    chosen = sorted(os.path.basename(p) for p in mod.expired_runs(str(runs), now=now))
    assert chosen == sorted([old, older])
    assert mod.expired_runs(str(tmp_path / "missing"), now=now) == []

    logs = []
    mod.log = logs.append
    assert mod.cleanup_runs() == 2
    assert sorted(os.listdir(runs)) == sorted([recent, "permtest", "20261399-000000", stamp(31) + "-x", "notes",
                                               "20200101-000000.txt", "20200102-000000"])
    assert outside.exists() and "removed 2 run folders older than 30 days" in logs[-1]
    assert mod.cleanup_runs() == 0 and "removed 0 run folders" in logs[-1]


def test_docs_snippet_verifies_a_real_delivery(client, local_webhooks):
    import html, re
    page = open(os.path.join(ROOT, "site", "pages", "docs", "webhooks.html")).read()
    code = html.unescape(re.sub(r"<[^>]+>", "", re.search(r"<pre><code>(import hashlib, hmac, time.*?)</code></pre>", page, re.S).group(1)))
    assert len(code.strip().splitlines()) <= 10
    ns = {}
    exec(code, ns)
    u = sign_in(client, "owner@example.com")
    secret = client.patch(f"/workspaces/{u.wid}", json={"webhook_url": local_webhooks}, headers=u.h).json()["webhook_secret"]
    client.post(f"/workspaces/{u.wid}/webhook/test", headers=u.h)
    hook = STATE.hooks[-1]
    assert ns["verify"](secret, hook["headers"], hook["raw"]) is True
    assert ns["verify"]("whsec_wrong", hook["headers"], hook["raw"]) is False
    assert ns["verify"](secret, hook["headers"], hook["raw"] + b" ") is False
    stale = dict(hook["headers"], **{"X-PatchLabs-Timestamp": str(int(hook["headers"]["X-PatchLabs-Timestamp"]) - 301)})
    assert ns["verify"](secret, stale, hook["raw"]) is False
