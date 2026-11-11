"""Owner decisions and answers on finished checks, suppressions in diffs and alerts, and Ed25519-signed receipts."""
import base64, hashlib, json

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from helpers import STATE, W, add_repo, claim, finish_with, outbox, sign_in, sql, verified_app

QUESTIONS = ["Should sellers' emails be public?", "Is the newsletter table meant to be readable?"]


def finish_q(client, cid, status="done", tables=("profiles", "sellers")):
    body = {"status": status, "summary": {"tables_leaking": list(tables), "lab_proof_passed": True, "questions_for_owner":
            [QUESTIONS[0], {"question": QUESTIONS[1], "recommended": "no"}]}, "report_md": "# r", "fix_sql": "ALTER TABLE x;", "cost_usd": 1}
    assert client.post(f"/worker/checks/{cid}/result", json=body, headers=W).status_code == 200


@pytest.fixture
def setup(client):
    u = sign_in(client, "owner@example.com")
    a, cid = verified_app(client, u)
    return u, a, cid


def test_decisions_need_a_finished_app_check_and_membership(client, setup):
    u, a, cid = setup
    assert client.post(f"/checks/{cid}/decision", json={"action": "approve"}, headers=u.h).status_code == 409
    claim(client)
    finish_q(client, cid)
    assert client.post(f"/checks/{cid}/decision", json={"action": "approve"}).status_code == 401
    other = sign_in(client, "other@example.com")
    assert client.post(f"/checks/{cid}/decision", json={"action": "approve"}, headers=other.h).status_code == 403
    assert client.post(f"/checks/{cid}/answers", json={"answers": [{"question": QUESTIONS[0], "answer": "y"}]}, headers=other.h).status_code == 403
    assert client.post("/checks/00000000-0000-0000-0000-000000000000/decision", json={"action": "approve"}, headers=u.h).status_code == 404
    assert client.post(f"/checks/{cid}/decision", json={"action": "maybe"}, headers=u.h).status_code == 422
    assert client.post(f"/checks/{cid}/decision", json={"action": "reject", "tables": ["nope"]}, headers=u.h).status_code == 422
    add_repo("acme/anon")
    anon = client.post("/checks", json={"email": "owner@example.com", "repo": "acme/anon"}).json()["id"]
    assert client.post(f"/checks/{anon}/decision", json={"action": "approve"}, headers=u.h).status_code == 403


def test_reject_suppresses_tables_in_diff_and_alerts(client, setup, local_webhooks):
    u, a, cid = setup
    client.patch(f"/workspaces/{u.wid}", json={"webhook_url": local_webhooks}, headers=u.h)
    claim(client)
    finish_q(client, cid)
    r = client.post(f"/checks/{cid}/decision", json={"action": "reject", "tables": ["sellers"], "reason": "Public seller contact"},
                    headers=u.h)
    assert r.status_code == 201
    d = r.json()["decisions"]
    assert d[0]["action"] == "reject" and d[0]["tables"] == ["sellers"] and d[0]["by"] == "o\u2022\u2022\u2022@example.com" and d[0]["at"]
    g = client.get(f"/checks/{cid}").json()
    assert g["decisions"][0]["reason"] == "Public seller contact" and g["answers"] == []
    app = client.get(f"/apps/{a['id']}", headers=u.h).json()
    assert app["suppressed_tables"] == ["sellers"]
    assert app["diff"]["new_leaks"] == ["profiles"] and app["diff"]["suppressed"] == ["sellers"]

    # next check: sellers still readable (suppressed: no alert), a new table appears
    nxt = client.post(f"/apps/{a['id']}/checks", headers=u.h).json()["check_id"]
    claim(client)
    finish_q(client, nxt, tables=("profiles", "sellers", "messages"))
    m = outbox("owner@example.com")[-1]
    assert m["subject"].startswith("New leak found") and "New leaks since the last check: messages" in m["text"]
    assert "Marked as intended by your team (no alert): sellers" in m["text"]
    hook = STATE.hooks[-1]["body"]["check"]
    assert hook["new_leaks"] == ["messages"] and hook["suppressed"] == ["sellers"]

    # only suppressed tables new: no "new leak" alert
    client.post(f"/checks/{nxt}/decision", json={"action": "reject", "tables": ["messages"]}, headers=u.h)
    third = client.post(f"/apps/{a['id']}/checks", headers=u.h).json()["check_id"]
    claim(client)
    finish_q(client, third, tables=("profiles", "sellers", "messages"))
    assert outbox("owner@example.com")[-1]["subject"] == "PatchLabs check finished for acme/shop"

    # approving un-suppresses
    client.post(f"/checks/{third}/decision", json={"action": "approve", "tables": ["sellers"], "accept_charge_gbp": 29}, headers=u.h)
    assert client.get(f"/apps/{a['id']}", headers=u.h).json()["suppressed_tables"] == ["messages"]


def test_answers(client, setup):
    u, a, cid = setup
    claim(client)
    finish_q(client, cid)
    assert client.post(f"/checks/{cid}/answers", json={"answers": []}, headers=u.h).status_code == 422
    assert client.post(f"/checks/{cid}/answers", json={"answers": [{"question": "made up?", "answer": "x"}]}, headers=u.h).status_code == 422
    r = client.post(f"/checks/{cid}/answers", json={"answers": [{"question": QUESTIONS[0], "answer": "No, keep them private"},
                                                                {"question": QUESTIONS[1], "answer": "No"}]}, headers=u.h)
    assert r.status_code == 200 and len(r.json()["answers"]) == 2
    r = client.post(f"/checks/{cid}/answers", json={"answers": [{"question": QUESTIONS[1], "answer": "Yes actually"}]}, headers=u.h)
    assert {x["question"]: x["answer"] for x in r.json()["answers"]}[QUESTIONS[1]] == "Yes actually"
    assert len(client.get(f"/checks/{cid}").json()["answers"]) == 2


def test_answers_without_questions(client, setup):
    from helpers import finish
    u, a, cid = setup
    claim(client)
    finish(client, cid, "no_leaks")
    assert client.post(f"/checks/{cid}/answers", json={"answers": [{"question": "q", "answer": "a"}]}, headers=u.h).status_code == 409


def test_signed_receipt_verifies_with_published_key(client, setup):
    u, a, cid = setup
    assert client.get(f"/receipts/{cid}").status_code == 409
    assert client.get("/receipts/00000000-0000-0000-0000-000000000000").status_code == 404
    assert client.get("/receipts/xyz").status_code == 404
    claim(client)
    finish_q(client, cid)
    client.patch("/me", json={"name": "Olive Owner"}, headers=u.h)
    client.post(f"/checks/{cid}/decision", json={"action": "approve", "reason": "Ship it", "accept_charge_gbp": 29}, headers=u.h)
    client.post(f"/checks/{cid}/answers", json={"answers": [{"question": QUESTIONS[0], "answer": "No"}]}, headers=u.h)

    r = client.get(f"/receipts/{cid}").json()
    rec = r["receipt"]
    assert rec["check_id"] == str(cid) and rec["repo"] == "acme/shop" and rec["status"] == "done"
    assert rec["tables_leaking"] == ["profiles", "sellers"] and rec["lab_proof_passed"] is True
    assert rec["fix_sha256"] == hashlib.sha256(b"ALTER TABLE x;").hexdigest() and rec["finished_at"]
    assert rec["decisions"][0]["action"] == "approve" and rec["decisions"][0]["by"] == "Olive Owner"
    assert rec["answers"][0]["answer"] == "No"
    assert "cost" not in json.dumps(r).lower()

    key = client.get("/.well-known/patchlabs-receipt-key").json()
    assert key["key_id"] == r["key_id"] and key["algorithm"] == "Ed25519" and key["pem"].startswith("-----BEGIN PUBLIC KEY-----")
    # the fixed test seed (bytes 0..31) gives this exact public key
    assert base64.b64decode(key["public_key"]) == Ed25519PrivateKey.from_private_bytes(bytes(range(32))).public_key().public_bytes_raw()

    # the README's verification steps
    msg = json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(key["public_key"]))
    pub.verify(base64.b64decode(r["signature"]), msg)
    load_pem_public_key(key["pem"].encode()).verify(base64.b64decode(r["signature"]), msg)
    tampered = dict(rec, status="no_leaks")
    with pytest.raises(InvalidSignature):
        pub.verify(base64.b64decode(r["signature"]), json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode())


def test_receipt_for_anonymous_check(client):
    add_repo("acme/anon")
    cid = client.post("/checks", json={"email": "x@example.com", "repo": "acme/anon"}).json()["id"]
    sql("UPDATE checks SET status = 'queued', verified_at = now() WHERE id = %s", (cid,))
    claim(client)
    from helpers import finish
    finish(client, cid, "no_leaks")
    r = client.get(f"/receipts/{cid}").json()
    assert r["receipt"]["decisions"] == [] and r["receipt"]["fix_sha256"] is None and r["receipt"]["status"] == "no_leaks"


def test_deleted_member_decisions_are_relabelled(client, setup):
    from helpers import A, link_param
    u, a, cid = setup
    client.patch(f"/admin/workspaces/{u.wid}", json={"plan": "maker"}, headers=A)
    client.post(f"/workspaces/{u.wid}/invites", json={"email": "bob@example.com", "role": "approver"}, headers=u.h)
    bob = sign_in(client, "bob@example.com", invite=link_param(outbox("bob@example.com")[-1], "invite"))
    claim(client)
    finish_q(client, cid)
    client.post(f"/checks/{cid}/decision", json={"action": "approve", "accept_charge_gbp": 29}, headers=bob.h)
    client.post(f"/checks/{cid}/answers", json={"answers": [{"question": QUESTIONS[0], "answer": "No"}]}, headers=bob.h)
    assert client.get(f"/receipts/{cid}").json()["receipt"]["decisions"][0]["by"] == "b\u2022\u2022\u2022@example.com"
    client.delete("/me", headers=bob.h)
    r = client.get(f"/receipts/{cid}").json()["receipt"]
    assert r["decisions"][0]["by"] == "a former member" and r["answers"][0]["by"] == "a former member"
    assert "bob@example.com" not in json.dumps(client.get(f"/checks/{cid}").json())


def test_receipt_lists_v3_findings_by_id_only(client, setup):
    u, a, cid = setup
    claim(client)
    finish_with(client, cid, [{"id": "PL-001", "line": "lab", "severity": "critical", "object": "public.profiles", "evidence": "email",
                               "proven": True, "fixed_in_lab": True},
                              {"id": "PL-021", "line": "code", "severity": "high", "object": "supabase/functions/pay/index.ts",
                               "evidence": "JSON.parse(body)", "proven": False, "fixed_in_lab": False}], tables=["profiles"])
    rec = client.get(f"/receipts/{cid}").json()["receipt"]
    assert rec["findings"] == [{"id": "PL-001", "line": "lab", "severity": "critical", "proven": True, "fixed_in_lab": True},
                               {"id": "PL-021", "line": "code", "severity": "high", "proven": False, "fixed_in_lab": False}]
    assert "supabase/functions" not in json.dumps(rec) and "JSON.parse" not in json.dumps(rec)


def test_free_plan_approval_needs_the_per_fix_charge_agreed(client, setup):
    u, a, cid = setup
    claim(client)
    finish_q(client, cid)
    r = client.post(f"/checks/{cid}/decision", json={"action": "approve"}, headers=u.h)
    assert r.status_code == 402 and "£29" in r.json()["detail"]
    assert client.post(f"/checks/{cid}/decision", json={"action": "approve", "accept_charge_gbp": 5}, headers=u.h).status_code == 402
    assert client.post(f"/checks/{cid}/decision", json={"action": "approve", "tables": []}, headers=u.h).status_code == 422  # no free approvals
    assert client.post(f"/checks/{cid}/decision", json={"action": "reject", "tables": ["sellers"], "reason": "public"}, headers=u.h).status_code == 201
    r = client.post(f"/checks/{cid}/decision", json={"action": "approve", "accept_charge_gbp": 29}, headers=u.h)
    assert r.status_code == 201
    log = client.get(f"/workspaces/{u.wid}/audit", headers=u.h).json()
    made = [e for e in log["events"] if e["action"] == "decision.made" and e["detail"].get("action") == "approve"]
    assert made and made[0]["detail"]["charge_gbp"] == 29
