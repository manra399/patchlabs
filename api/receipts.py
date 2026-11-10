"""Signed receipts for finished checks, and the owner's decisions and answers that go into them."""
import base64, hashlib, json, os, uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import audit
from core import FINISHED, as_uuid, current_user, db, event, leaking, mask_email, may_see_app, require

router = APIRouter()


def load_key():
    seed = os.environ.get("RECEIPT_PRIVATE_KEY", "").strip()
    if seed:
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(seed))
    if os.environ.get("PATCHLABS_DEV") != "1":
        raise RuntimeError("RECEIPT_PRIVATE_KEY is not set. Set it (base64 of a 32-byte Ed25519 seed), or PATCHLABS_DEV=1 for local dev.")
    print("WARNING: RECEIPT_PRIVATE_KEY is not set (PATCHLABS_DEV=1); receipts use a temporary key that changes on restart.", flush=True)
    return Ed25519PrivateKey.generate()


KEY = load_key()
PUBLIC_RAW = KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
PUBLIC_PEM = KEY.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
KEY_ID = "ed25519:" + hashlib.sha256(PUBLIC_RAW).hexdigest()[:16]


def canonical(obj):
    """The exact bytes that are signed: JSON with sorted keys and no spaces."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def iso(t):
    return t.isoformat() if t else None


def by_label(user):
    """What public pages and receipts show: the member's name, or a masked email (m\u2022\u2022\u2022@domain)."""
    return user["name"] or mask_email(user["email"])


def decisions(c, cid, members=False):
    """Public view by default; members=True adds by_user_id and the full email (signed-in workspace members only)."""
    return [{"action": r["action"], "tables": list(r["tables"]), "reason": r["reason"], "by": r["by_label"], "at": iso(r["created_at"]),
             **({"by_user_id": r["user_id"], "by_email": r["email"]} if members else {})}
            for r in c.execute("SELECT d.action, d.tables, d.reason, d.by_label, d.created_at, d.user_id, u.email FROM decisions d "
                               "LEFT JOIN users u ON u.id = d.user_id WHERE d.check_id = %s ORDER BY d.created_at, d.id", (cid,)).fetchall()]


def answers(c, cid, members=False):
    return [{"question": r["question"], "answer": r["answer"], "by": r["by_label"], "at": iso(r["created_at"]),
             **({"by_user_id": r["user_id"], "by_email": r["email"]} if members else {})}
            for r in c.execute("SELECT a.question, a.answer, a.by_label, a.created_at, a.user_id, u.email FROM check_answers a "
                               "LEFT JOIN users u ON u.id = a.user_id WHERE a.check_id = %s ORDER BY a.created_at, a.question",
                               (cid,)).fetchall()]


def questions(summary):
    qs = summary.get("questions_for_owner") if isinstance(summary, dict) else None
    return [q if isinstance(q, str) else str(q.get("question", "")) for q in (qs or []) if isinstance(q, (str, dict))]


def check_for_member(c, user, cid, perm="view"):
    """A finished app check the user may see (clients: only apps shared with them), with a role that allows `perm`."""
    k = c.execute("SELECT k.*, a.workspace_id, a.repo AS app_repo FROM checks k LEFT JOIN apps a ON a.id = k.app_id WHERE k.id = %s",
                  (as_uuid(cid, "Check not found."),)).fetchone()
    if not k:
        raise HTTPException(404, "Check not found.")
    m = c.execute("SELECT role FROM workspace_members WHERE workspace_id = %s AND user_id = %s",
                  (k["workspace_id"], user["id"])).fetchone() if k["app_id"] else None
    if not m or not may_see_app(c, m["role"], k["workspace_id"], user["id"], k["app_id"]):
        raise HTTPException(403, "Only members of the app's workspace can do that.")
    require(m["role"], perm)
    if k["status"] not in FINISHED:
        raise HTTPException(409, "Wait until the check has finished.")
    return k


class Decision(BaseModel):
    action: str = Field(pattern=r"^(approve|reject)$")
    reason: str | None = Field(default=None, max_length=2000)
    tables: list[str] | None = Field(default=None, max_length=500)


class Answer(BaseModel):
    question: str = Field(max_length=2000)
    answer: str = Field(min_length=1, max_length=4000)


class Answers(BaseModel):
    answers: list[Answer] = Field(min_length=1, max_length=50)


@router.post("/checks/{cid}/decision", status_code=201)
def decide(cid: str, body: Decision, user=Depends(current_user), c=Depends(db)):
    k = check_for_member(c, user, cid, "decide")
    found = leaking(k["summary"])
    tables = found if body.tables is None else list(dict.fromkeys(body.tables))
    unknown = [t for t in tables if t not in found]
    if unknown:
        raise HTTPException(422, "This check didn't flag " + ", ".join(unknown) + ".")
    did = uuid.uuid4()
    c.execute("INSERT INTO decisions (id, check_id, user_id, by_label, action, tables, reason) VALUES (%s, %s, %s, %s, %s, %s, %s)",
              (did, k["id"], user["id"], by_label(user), body.action, tables, (body.reason or "").strip() or None))
    target = {"type": "check", "id": k["id"], "label": k["app_repo"]}
    audit.log(c, k["workspace_id"], "decision.made", user, target=target,
              detail={"action": body.action, "tables": tables, "app_id": k["app_id"], "decision_id": did})
    if body.action == "reject":
        for t in tables:
            new = c.execute("INSERT INTO finding_suppressions (app_id, table_name, decision_id) VALUES (%s, %s, %s) "
                            "ON CONFLICT (app_id, table_name) DO UPDATE SET decision_id = EXCLUDED.decision_id, created_at = now() "
                            "RETURNING (xmax = 0) AS inserted", (k["app_id"], t, did)).fetchone()["inserted"]
            if new:
                audit.log(c, k["workspace_id"], "suppression.added", user, target=target, detail={"table": t, "app_id": k["app_id"]})
    elif tables:
        for r in c.execute("DELETE FROM finding_suppressions WHERE app_id = %s AND table_name = ANY(%s) RETURNING table_name",
                           (k["app_id"], tables)).fetchall():
            audit.log(c, k["workspace_id"], "suppression.removed", user, target=target, detail={"table": r["table_name"], "app_id": k["app_id"]})
    event(c, k["id"], f"decision_{body.action}", ", ".join(tables) or None)
    return {"decisions": decisions(c, k["id"], members=True)}


@router.post("/checks/{cid}/answers")
def answer(cid: str, body: Answers, user=Depends(current_user), c=Depends(db)):
    k = check_for_member(c, user, cid, "decide")
    qs = questions(k["summary"])
    if not qs:
        raise HTTPException(409, "This check has no questions for the owner.")
    for a in body.answers:
        if a.question not in qs:
            raise HTTPException(422, f"That isn't one of this check's questions: {a.question[:200]}")
    for a in body.answers:
        c.execute("INSERT INTO check_answers (check_id, question, answer, user_id, by_label) VALUES (%s, %s, %s, %s, %s) "
                  "ON CONFLICT (check_id, question) DO UPDATE SET answer = EXCLUDED.answer, user_id = EXCLUDED.user_id, "
                  "by_label = EXCLUDED.by_label, created_at = now()", (k["id"], a.question, a.answer.strip(), user["id"], by_label(user)))
    event(c, k["id"], "answers_saved")
    audit.log(c, k["workspace_id"], "check.answered", user, target={"type": "check", "id": k["id"], "label": k["app_repo"]},
              detail={"questions": len(body.answers)})
    return {"answers": answers(c, k["id"], members=True)}


@router.get("/checks/{cid}/decisions")
def member_decisions(cid: str, user=Depends(current_user), c=Depends(db)):
    k = check_for_member(c, user, cid)
    return {"decisions": decisions(c, k["id"], members=True), "answers": answers(c, k["id"], members=True)}


@router.get("/receipts/{cid}")
def receipt(cid: str, c=Depends(db)):
    k = c.execute("SELECT id, repo, status, summary, fix_sql, finished_at FROM checks WHERE id = %s",
                  (as_uuid(cid, "Check not found."),)).fetchone()
    if not k:
        raise HTTPException(404, "Check not found.")
    if k["status"] not in FINISHED:
        raise HTTPException(409, "Receipts are issued once a check has finished.")
    s = k["summary"] if isinstance(k["summary"], dict) else {}
    r = {"check_id": str(k["id"]), "repo": k["repo"], "status": k["status"], "tables_leaking": leaking(s),
         "lab_proof_passed": bool(s.get("lab_proof_passed")), "finished_at": iso(k["finished_at"]),
         "fix_sha256": hashlib.sha256(k["fix_sql"].encode()).hexdigest() if k["fix_sql"] else None,
         "decisions": decisions(c, k["id"]), "answers": answers(c, k["id"])}
    if isinstance(s.get("findings"), list):  # v3 checks: every finding, by ID only (no paths or evidence on a public receipt)
        r["findings"] = [{x: f.get(x) for x in ("id", "line", "severity", "proven", "fixed_in_lab")} for f in s["findings"] if isinstance(f, dict)]
    return {"receipt": r, "signature": base64.b64encode(KEY.sign(canonical(r))).decode(), "key_id": KEY_ID, "algorithm": "Ed25519"}


@router.get("/.well-known/patchlabs-receipt-key")
def receipt_key():
    return {"key_id": KEY_ID, "algorithm": "Ed25519", "public_key": base64.b64encode(PUBLIC_RAW).decode(), "pem": PUBLIC_PEM,
            "signed_bytes": "JSON of `receipt` with sorted keys and separators (',', ':')"}
