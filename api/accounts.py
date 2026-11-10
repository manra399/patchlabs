"""Accounts: magic-link sign-in, the signed-in user, workspaces with members, invites, API keys and upgrade requests, plus admin."""
import hashlib, re, secrets, uuid
from datetime import datetime, timezone
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from core import (ADMIN_TOKEN, AUTH_PER_IP_PER_HOUR, EMAIL_RE, FOUNDER_EMAIL, SITE_URL, as_uuid, bearer, clean_report, clean_text,
                  current_user, db, ip_hash, limits, mail, membership, new_webhook_secret, recent, record, scrub, send_webhook,
                  token_hash, usage, webhook_secret, webhook_target)

router = APIRouter()
MAX_LOGINS_PER_EMAIL_PER_HOUR = 5
INVITES_PER_WORKSPACE_PER_DAY, INVITES_PER_ADDRESS_PER_DAY, UPGRADES_PER_WORKSPACE_PER_DAY = 20, 3, 3
ROLE = r"^(member|owner)$"


def user_view(u):
    return {k: u[k] for k in ("id", "email", "name", "created_at")}


def safe_next(n):
    """Only a same-site path: one "/" then a character that isn't "/" or "\\", and no control characters anywhere."""
    return n if n and re.match(r"^/[^/\\]", n) and not re.search(r"[\x00-\x1f\x7f\\]", n) else None


# ---- auth --------------------------------------------------------------------------------------------------------

class AuthStart(BaseModel):
    email: str = Field(max_length=254, pattern=EMAIL_RE)
    next: str | None = Field(default=None, max_length=500)


class AuthFinish(BaseModel):
    token: str = Field(max_length=200)
    invite: str | None = Field(default=None, max_length=200)


class InviteToken(BaseModel):
    invite: str = Field(max_length=200)


@router.post("/auth/start", status_code=202)
def auth_start(body: AuthStart, request: Request, c=Depends(db)):
    email, nxt, iph = body.email.strip().lower(), safe_next(body.next), ip_hash(request)
    n = c.execute("SELECT (SELECT count(*) FROM login_tokens WHERE lower(email) = %s AND created_at > now() - interval '1 hour') AS e, "
                  "(SELECT count(*) FROM login_tokens WHERE ip_hash = %s AND created_at > now() - interval '1 hour') AS i",
                  (email, iph)).fetchone()
    if n["e"] < MAX_LOGINS_PER_EMAIL_PER_HOUR and n["i"] < AUTH_PER_IP_PER_HOUR:  # always 202: no account enumeration
        tok = secrets.token_urlsafe(32)
        c.execute("INSERT INTO login_tokens (token_hash, email, next, ip_hash, expires_at) VALUES (%s, %s, %s, %s, now() + interval '20 minutes')",
                  (token_hash(tok), email, nxt, iph))
        link = f"{SITE_URL}/app/login?" + urlencode({"token": tok, **({"next": nxt} if nxt else {})})
        mail(email, "Your PatchLabs sign-in link",
             f"Here is your link to sign in to PatchLabs:\n{link}\n\nIt works once and expires in 20 minutes.\n\n"
             "If you didn't ask for it, ignore this email: nobody can sign in without it.\n\nPatchLabs")
    return {"ok": True, "detail": "If that address can sign in, a link is on its way. It expires in 20 minutes."}


def accept_invite(c, user, tok):
    inv = c.execute("SELECT i.*, w.name AS workspace_name FROM invites i JOIN workspaces w ON w.id = i.workspace_id "
                    "WHERE i.token_hash = %s AND i.accepted_at IS NULL AND i.expires_at > now()", (token_hash(tok),)).fetchone()
    if not inv:
        return {"accepted": False, "detail": "This invite has expired or was already used. Ask for a new one."}
    if inv["email"].lower() != user["email"].lower():
        return {"accepted": False, "detail": "This invite was sent to a different email address. Sign in with that address to join."}
    out = {"accepted": True, "workspace_id": inv["workspace_id"], "workspace_name": inv["workspace_name"]}
    if not c.execute("SELECT 1 FROM workspace_members WHERE workspace_id = %s AND user_id = %s", (inv["workspace_id"], user["id"])).fetchone():
        w = c.execute("SELECT * FROM workspaces WHERE id = %s FOR UPDATE", (inv["workspace_id"],)).fetchone()
        if usage(c, w["id"])["members"] >= limits(w)["seats"]:
            return {"accepted": False, "detail": "That workspace has no free seats. Ask its owner to upgrade."}
        c.execute("INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (%s, %s, %s)", (w["id"], user["id"], inv["role"]))
    c.execute("UPDATE invites SET accepted_at = now() WHERE id = %s", (inv["id"],))
    return out


@router.post("/auth/finish")
def auth_finish(body: AuthFinish, c=Depends(db)):
    t = c.execute("UPDATE login_tokens SET used_at = now() WHERE token_hash = %s AND used_at IS NULL AND expires_at > now() "
                  "RETURNING email, next", (token_hash(body.token.strip()),)).fetchone()
    if not t:
        raise HTTPException(400, "This sign-in link has expired or was already used. Ask for a new one.")
    email = t["email"].lower()
    u = c.execute("SELECT * FROM users WHERE lower(email) = %s", (email,)).fetchone()
    if not u:
        u = c.execute("INSERT INTO users (id, email) VALUES (%s, %s) RETURNING *", (uuid.uuid4(), email)).fetchone()
        wid = uuid.uuid4()
        c.execute("INSERT INTO workspaces (id, name) VALUES (%s, %s)", (wid, clean_text(f"{email.split('@')[0]}'s workspace")[:100]))
        c.execute("INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (%s, %s, 'owner')", (wid, u["id"]))
    c.execute("UPDATE users SET last_login_at = now() WHERE id = %s", (u["id"],))
    c.execute("UPDATE checks SET user_id = %s WHERE lower(email) = %s AND app_id IS NULL AND user_id IS NULL", (u["id"], email))
    session = secrets.token_urlsafe(32)
    c.execute("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (%s, %s, now() + interval '30 days')",
              (token_hash(session), u["id"]))
    return {"session": session, "user": user_view(u), "next": t["next"],
            "invite": accept_invite(c, u, body.invite.strip()) if body.invite else None}


@router.post("/invites/accept")
def invite_accept(body: InviteToken, user=Depends(current_user), c=Depends(db)):
    out = accept_invite(c, user, body.invite.strip())
    if not out["accepted"]:
        raise HTTPException(409, out["detail"])
    return out


@router.post("/auth/logout")
def logout(authorization: str = Header(default=""), c=Depends(db)):
    if authorization.startswith("Bearer "):
        c.execute("UPDATE sessions SET revoked_at = now() WHERE token_hash = %s AND revoked_at IS NULL", (token_hash(authorization[7:].strip()),))
    return {"ok": True}


# ---- me ----------------------------------------------------------------------------------------------------------

class MePatch(BaseModel):
    name: str | None = Field(default=None, max_length=100)


def my_workspaces(c, user):
    return c.execute("SELECT w.id, w.name, m.role, w.plan FROM workspace_members m JOIN workspaces w ON w.id = m.workspace_id "
                     "WHERE m.user_id = %s ORDER BY m.created_at, w.created_at", (user["id"],)).fetchall()


@router.get("/me")
def me(user=Depends(current_user), c=Depends(db)):
    return {"user": user_view(user), "workspaces": my_workspaces(c, user)}


@router.patch("/me")
def patch_me(body: MePatch, user=Depends(current_user), c=Depends(db)):
    u = c.execute("UPDATE users SET name = %s WHERE id = %s RETURNING *", (clean_text(body.name) or None, user["id"])).fetchone()
    return {"user": user_view(u), "workspaces": my_workspaces(c, u)}


@router.get("/me/checks")
def my_checks(user=Depends(current_user), c=Depends(db)):
    return {"checks": c.execute("SELECT id, repo, status, created_at FROM checks WHERE app_id IS NULL "
                                "AND (user_id = %s OR lower(email) = lower(%s)) ORDER BY created_at DESC LIMIT 200",
                                (user["id"], user["email"])).fetchall()}


@router.get("/me/export")
def export_me(user=Depends(current_user), c=Depends(db)):
    uid, email = user["id"], user["email"]
    workspaces = []
    for m in my_workspaces(c, user):
        w = workspace_view(c, membership(c, user, m["id"]))
        w.pop("webhook_secret", None)  # a credential, not data about the person
        w["apps"] = c.execute("SELECT id, repo, branch, client_label, verified_at, schedule, next_check_at, badge_public, created_at, "
                              "created_by FROM apps WHERE workspace_id = %s ORDER BY created_at", (m["id"],)).fetchall()
        workspaces.append(w)
    checks = c.execute("SELECT id, created_at, email, repo, branch, status, verified_at, finished_at, ip_hash, summary, report_md, fix_sql "
                       "FROM checks WHERE app_id IS NULL AND (user_id = %s OR lower(email) = lower(%s)) ORDER BY created_at",
                       (uid, email)).fetchall()
    for k in checks:
        k["summary"], k["report_md"] = scrub(k["summary"]), clean_report(k["report_md"])
        k["events"] = c.execute("SELECT at, kind, detail FROM check_events WHERE check_id = %s ORDER BY at", (k["id"],)).fetchall()
    data = {"exported_at": datetime.now(timezone.utc), "user": {k: user[k] for k in ("id", "email", "name", "created_at", "last_login_at")},
            "sessions": c.execute("SELECT created_at, expires_at, revoked_at FROM sessions WHERE user_id = %s ORDER BY created_at", (uid,)).fetchall(),
            "sign_in_requests": c.execute("SELECT created_at, expires_at, used_at FROM login_tokens WHERE lower(email) = %s "
                                          "ORDER BY created_at", (email,)).fetchall(),
            "workspaces": workspaces, "anonymous_checks": checks,
            "api_keys_created": c.execute("SELECT id, workspace_id, name, prefix, created_at, last_used_at FROM api_keys "
                                          "WHERE created_by = %s", (uid,)).fetchall(),
            "invites_received": c.execute("SELECT id, workspace_id, role, created_at, expires_at, accepted_at FROM invites "
                                          "WHERE lower(email) = lower(%s)", (email,)).fetchall(),
            "upgrade_requests": c.execute("SELECT id, workspace_id, plan, note, created_at FROM upgrade_requests WHERE user_id = %s",
                                          (uid,)).fetchall(),
            "decisions": c.execute("SELECT id, check_id, action, tables, reason, created_at FROM decisions WHERE user_id = %s",
                                   (uid,)).fetchall(),
            "answers": c.execute("SELECT check_id, question, answer, created_at FROM check_answers WHERE user_id = %s", (uid,)).fetchall()}
    return JSONResponse(jsonable_encoder(data), headers={"Content-Disposition": 'attachment; filename="patchlabs-export.json"'})


@router.delete("/me")
def delete_me(user=Depends(current_user), c=Depends(db)):
    uid, email, deleted = user["id"], user["email"], 0
    for m in c.execute("SELECT workspace_id FROM workspace_members WHERE user_id = %s AND role = 'owner'", (uid,)).fetchall():
        wid = m["workspace_id"]
        if c.execute("SELECT count(*) AS n FROM workspace_members WHERE workspace_id = %s AND role = 'owner'", (wid,)).fetchone()["n"] > 1:
            continue
        heir = c.execute("SELECT user_id FROM workspace_members WHERE workspace_id = %s AND user_id <> %s ORDER BY created_at LIMIT 1",
                         (wid, uid)).fetchone()
        if heir:  # teammates keep the workspace: the longest-standing member becomes its owner
            c.execute("UPDATE workspace_members SET role = 'owner' WHERE workspace_id = %s AND user_id = %s", (wid, heir["user_id"]))
        else:
            c.execute("DELETE FROM workspaces WHERE id = %s", (wid,))  # apps, their checks, keys and invites go with it
            deleted += 1
    c.execute("DELETE FROM api_keys WHERE created_by = %s", (uid,))  # their keys stop working with them
    c.execute("DELETE FROM checks WHERE app_id IS NULL AND (user_id = %s OR lower(email) = lower(%s))", (uid, email))
    c.execute("UPDATE checks SET email = '' WHERE lower(email) = lower(%s)", (email,))
    c.execute("DELETE FROM login_tokens WHERE lower(email) = lower(%s)", (email,))
    c.execute("DELETE FROM invites WHERE lower(email) = lower(%s)", (email,))
    c.execute("UPDATE decisions SET by_label = 'a former member' WHERE user_id = %s", (uid,))
    c.execute("UPDATE check_answers SET by_label = 'a former member' WHERE user_id = %s", (uid,))
    c.execute("DELETE FROM users WHERE id = %s", (uid,))
    return {"ok": True, "deleted_workspaces": deleted}


# ---- workspaces --------------------------------------------------------------------------------------------------

class WorkspacePatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    webhook_url: str | None = Field(default=None, max_length=1000)


class NewInvite(BaseModel):
    email: str = Field(max_length=254, pattern=EMAIL_RE)
    role: str = Field(default="member", pattern=ROLE)


class RolePatch(BaseModel):
    role: str = Field(pattern=ROLE)


class NewKey(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class Upgrade(BaseModel):
    plan: str = Field(pattern=r"^(maker|agency|enterprise)$")
    note: str | None = Field(default=None, max_length=2000)


def workspace_view(c, w):
    return {"id": w["id"], "name": w["name"], "plan": w["plan"], "role": w.get("role"), "created_at": w["created_at"],
            "limits": limits(w), "usage": usage(c, w["id"]), "webhook_url": w["webhook_url"],
            "webhook_secret": w["webhook_secret"] if w.get("role") == "owner" else None,
            "members": c.execute("SELECT m.user_id, u.email, u.name, m.role, m.created_at AS joined_at FROM workspace_members m "
                                 "JOIN users u ON u.id = m.user_id WHERE m.workspace_id = %s ORDER BY m.created_at", (w["id"],)).fetchall(),
            "invites": c.execute("SELECT id, email, role, created_at, expires_at FROM invites WHERE workspace_id = %s "
                                 "AND accepted_at IS NULL AND expires_at > now() ORDER BY created_at", (w["id"],)).fetchall()}


def owners(c, wid):
    return c.execute("SELECT count(*) AS n FROM workspace_members WHERE workspace_id = %s AND role = 'owner'", (wid,)).fetchone()["n"]


@router.get("/workspaces/{wid}")
def get_workspace(wid: str, user=Depends(current_user), c=Depends(db)):
    return workspace_view(c, membership(c, user, wid))


@router.patch("/workspaces/{wid}")
def patch_workspace(wid: str, body: WorkspacePatch, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid, owner=True)
    if body.name is not None:
        c.execute("UPDATE workspaces SET name = %s WHERE id = %s", (clean_text(body.name) or w["name"], w["id"]))
    if "webhook_url" in body.model_fields_set:
        url = (body.webhook_url or "").strip() or None
        if url:
            try:
                webhook_target(url)
            except ValueError as e:
                raise HTTPException(422, str(e))
        c.execute("UPDATE workspaces SET webhook_url = %s, webhook_secret = coalesce(webhook_secret, %s) WHERE id = %s",
                  (url, new_webhook_secret() if url else None, w["id"]))
    return workspace_view(c, membership(c, user, wid))


@router.post("/workspaces/{wid}/webhook/rotate-secret")
def rotate_webhook_secret(wid: str, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid, owner=True)
    secret = c.execute("UPDATE workspaces SET webhook_secret = %s WHERE id = %s RETURNING webhook_secret",
                       (new_webhook_secret(), w["id"])).fetchone()["webhook_secret"]
    return {"webhook_secret": secret}


@router.post("/workspaces/{wid}/webhook/test")
def test_webhook(wid: str, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid)
    if not w["webhook_url"]:
        raise HTTPException(409, "Add a webhook URL first.")
    try:
        code = send_webhook(w["webhook_url"], {"event": "test", "text": f"PatchLabs: webhooks for {w['name']} are working.",
                                               "workspace": {"id": str(w["id"]), "name": w["name"]}}, webhook_secret(c, w))
        return {"ok": 200 <= code < 300, "status_code": code}
    except Exception as e:
        return {"ok": False, "status_code": None, "detail": str(e)[:300]}


@router.post("/workspaces/{wid}/invites", status_code=201)
def create_invite(wid: str, body: NewInvite, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid, owner=True)
    email = body.email.strip().lower()
    if c.execute("SELECT 1 FROM workspace_members m JOIN users u ON u.id = m.user_id WHERE m.workspace_id = %s AND lower(u.email) = %s",
                 (w["id"], email)).fetchone():
        raise HTTPException(409, f"{email} is already in this workspace.")
    per_address = f"{w['id']}:{hashlib.sha256(email.encode()).hexdigest()[:16]}"
    if recent(c, "invite", w["id"]) >= INVITES_PER_WORKSPACE_PER_DAY:
        raise HTTPException(429, f"That's {INVITES_PER_WORKSPACE_PER_DAY} invites from this workspace today. Try again tomorrow.")
    if recent(c, "invite_address", per_address) >= INVITES_PER_ADDRESS_PER_DAY:
        raise HTTPException(429, f"{email} has been invited {INVITES_PER_ADDRESS_PER_DAY} times today. Try again tomorrow.")
    c.execute("DELETE FROM invites WHERE workspace_id = %s AND lower(email) = %s AND accepted_at IS NULL", (w["id"], email))
    pending = c.execute("SELECT count(*) AS n FROM invites WHERE workspace_id = %s AND accepted_at IS NULL AND expires_at > now()",
                        (w["id"],)).fetchone()["n"]
    seats = limits(w)["seats"]
    if usage(c, w["id"])["members"] + pending >= seats:
        raise HTTPException(403, f"The {w['plan']} plan has {seats} seat{'s' if seats != 1 else ''}, all taken or invited. "
                                 "Request an upgrade for more.")
    tok = secrets.token_urlsafe(32)
    inv = c.execute("INSERT INTO invites (id, workspace_id, email, role, token_hash, invited_by, expires_at) "
                    "VALUES (%s, %s, %s, %s, %s, %s, now() + interval '14 days') RETURNING id, email, role, created_at, expires_at",
                    (uuid.uuid4(), w["id"], email, body.role, token_hash(tok), user["id"])).fetchone()
    record(c, "invite", w["id"])
    record(c, "invite_address", per_address)
    mail(email, f"Join {w['name']} on PatchLabs",
         f"{user['name'] or user['email']} invited you to the {w['name']} workspace on PatchLabs, which finds and fixes "
         f"personal-data leaks in AI-built apps.\n\nJoin here (sign in with this email address):\n"
         f"{SITE_URL}/app/login?{urlencode({'invite': tok})}\n\nThe invite expires in 14 days.\n\nPatchLabs")
    return inv


@router.delete("/workspaces/{wid}/invites/{iid}")
def delete_invite(wid: str, iid: str, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid, owner=True)
    if not c.execute("DELETE FROM invites WHERE id = %s AND workspace_id = %s RETURNING id", (as_uuid(iid), w["id"])).fetchone():
        raise HTTPException(404, "Invite not found.")
    return {"ok": True}


def member_row(c, wid, uid):
    m = c.execute("SELECT * FROM workspace_members WHERE workspace_id = %s AND user_id = %s", (wid, as_uuid(uid, "Member not found."))).fetchone()
    if not m:
        raise HTTPException(404, "Member not found.")
    return m


@router.delete("/workspaces/{wid}/members/{uid}")
def remove_member(wid: str, uid: str, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid)
    m = member_row(c, w["id"], uid)
    if m["user_id"] != user["id"] and w["role"] != "owner":
        raise HTTPException(403, "Only a workspace owner can do that.")
    if m["role"] == "owner" and owners(c, w["id"]) <= 1:
        raise HTTPException(409, "A workspace needs at least one owner. Make someone else an owner first.")
    c.execute("DELETE FROM workspace_members WHERE workspace_id = %s AND user_id = %s", (w["id"], m["user_id"]))
    c.execute("DELETE FROM api_keys WHERE workspace_id = %s AND created_by = %s", (w["id"], m["user_id"]))  # a leaver's keys go too
    return {"ok": True}


@router.patch("/workspaces/{wid}/members/{uid}")
def set_role(wid: str, uid: str, body: RolePatch, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid, owner=True)
    m = member_row(c, w["id"], uid)
    if m["role"] == "owner" and body.role != "owner" and owners(c, w["id"]) <= 1:
        raise HTTPException(409, "A workspace needs at least one owner. Make someone else an owner first.")
    c.execute("UPDATE workspace_members SET role = %s WHERE workspace_id = %s AND user_id = %s", (body.role, w["id"], m["user_id"]))
    return workspace_view(c, membership(c, user, wid))


@router.get("/workspaces/{wid}/api-keys")
def list_keys(wid: str, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid)
    return {"api_keys": c.execute("SELECT k.id, k.name, k.prefix, k.created_at, k.last_used_at, k.created_by, u.email AS created_by_email "
                                  "FROM api_keys k LEFT JOIN users u ON u.id = k.created_by WHERE k.workspace_id = %s "
                                  "ORDER BY k.created_at", (w["id"],)).fetchall()}


@router.post("/workspaces/{wid}/api-keys", status_code=201)
def create_key(wid: str, body: NewKey, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid)
    key = "pl_live_" + secrets.token_urlsafe(24)
    k = c.execute("INSERT INTO api_keys (id, workspace_id, name, prefix, key_hash, created_by) VALUES (%s, %s, %s, %s, %s, %s) "
                  "RETURNING id, name, prefix, created_at, last_used_at, created_by",
                  (uuid.uuid4(), w["id"], clean_text(body.name) or "key", key[:12], token_hash(key), user["id"])).fetchone()
    return {**k, "created_by_email": user["email"], "key": key}


@router.delete("/workspaces/{wid}/api-keys/{kid}")
def delete_key(wid: str, kid: str, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid)
    if not c.execute("DELETE FROM api_keys WHERE id = %s AND workspace_id = %s RETURNING id", (as_uuid(kid), w["id"])).fetchone():
        raise HTTPException(404, "API key not found.")
    return {"ok": True}


@router.post("/workspaces/{wid}/upgrade-request", status_code=201)
def upgrade_request(wid: str, body: Upgrade, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid)
    if recent(c, "upgrade_request", w["id"]) >= UPGRADES_PER_WORKSPACE_PER_DAY:
        raise HTTPException(429, "We already have your upgrade request and will reply within a day.")
    record(c, "upgrade_request", w["id"])
    r = c.execute("INSERT INTO upgrade_requests (id, workspace_id, user_id, plan, note) VALUES (%s, %s, %s, %s, %s) "
                  "RETURNING id, plan, note, created_at", (uuid.uuid4(), w["id"], user["id"], body.plan, body.note)).fetchone()
    mail(FOUNDER_EMAIL, f"Upgrade request: {w['name']} to {body.plan}",
         f"{user['email']} asked to move workspace {w['name']} ({w['id']}) from {w['plan']} to {body.plan}.\n\n"
         f"Note from them:\n{body.note or '(none)'}\n\nSet the plan in the admin page:\n{SITE_URL}/admin")
    return {**r, "detail": "Thanks. We'll reply within a day."}


# ---- admin -------------------------------------------------------------------------------------------------------

class AdminWorkspacePatch(BaseModel):
    plan: str | None = Field(default=None, pattern=r"^(free|maker|agency|enterprise)$")
    app_limit: int | None = Field(default=None, ge=0, le=100_000)
    run_limit: int | None = Field(default=None, ge=0, le=1_000_000)
    seat_limit: int | None = Field(default=None, ge=0, le=100_000)


def admin_view(c, w):
    v = workspace_view(c, w)
    v.update(app_limit=w["app_limit"], run_limit=w["run_limit"], seat_limit=w["seat_limit"])
    return v


@router.get("/admin/workspaces", dependencies=[Depends(bearer(ADMIN_TOKEN))])
def admin_workspaces(c=Depends(db)):
    return {"workspaces": [admin_view(c, w) for w in c.execute("SELECT * FROM workspaces ORDER BY created_at DESC LIMIT 500").fetchall()]}


@router.patch("/admin/workspaces/{wid}", dependencies=[Depends(bearer(ADMIN_TOKEN))])
def admin_patch_workspace(wid: str, body: AdminWorkspacePatch, c=Depends(db)):
    wid = as_uuid(wid, "Workspace not found.")
    if not c.execute("SELECT 1 FROM workspaces WHERE id = %s", (wid,)).fetchone():
        raise HTTPException(404, "Workspace not found.")
    for col in ("plan", "app_limit", "run_limit", "seat_limit"):
        if col in body.model_fields_set and (col != "plan" or body.plan):
            c.execute(f"UPDATE workspaces SET {col} = %s WHERE id = %s", (getattr(body, col), wid))
    return admin_view(c, c.execute("SELECT * FROM workspaces WHERE id = %s", (wid,)).fetchone())


@router.get("/admin/upgrade-requests", dependencies=[Depends(bearer(ADMIN_TOKEN))])
def admin_upgrades(c=Depends(db)):
    return {"upgrade_requests": c.execute(
        "SELECT r.id, r.created_at, r.plan, r.note, r.workspace_id, w.name AS workspace_name, w.plan AS current_plan, u.email "
        "FROM upgrade_requests r JOIN workspaces w ON w.id = r.workspace_id LEFT JOIN users u ON u.id = r.user_id "
        "ORDER BY r.created_at DESC LIMIT 200").fetchall()}
