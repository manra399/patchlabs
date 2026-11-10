"""Accounts: magic-link sign-in, the signed-in user, workspaces with members, invites, API keys and upgrade requests, plus admin."""
import hashlib, re, secrets, uuid
from urllib.parse import urlsplit
from datetime import datetime, timezone
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import alerts, audit, support
from core import (ADMIN_TOKEN, AUTH_PER_IP_PER_HOUR, EMAIL_RE, FOUNDER_EMAIL, PERMS, ROLE_RE, SITE_URL, as_uuid, bearer, can,
                  clean_report, clean_text, client_apps, current_user, db, ip_hash, limits, mail, membership, new_webhook_secret, recent,
                  record, scrub, token_hash, usage, webhook_target)

router = APIRouter()
MAX_LOGINS_PER_EMAIL_PER_HOUR = 5
INVITES_PER_WORKSPACE_PER_DAY, INVITES_PER_ADDRESS_PER_DAY, UPGRADES_PER_WORKSPACE_PER_DAY = 20, 3, 3
ROLE = ROLE_RE
PERMS_ORDER = ("owner", "admin", "approver", "member", "viewer")  # heir order when the only owner deletes their account


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
        if inv["role"] != "client" and usage(c, w["id"])["members"] >= limits(w)["seats"]:  # clients never take a seat
            return {"accepted": False, "detail": "That workspace has no free seats. Ask its owner to upgrade."}
        c.execute("INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (%s, %s, %s)", (w["id"], user["id"], inv["role"]))
        if inv["role"] == "client":  # only apps still in the workspace
            c.execute("INSERT INTO member_app_access (workspace_id, user_id, app_id) SELECT %s, %s, id FROM apps "
                      "WHERE workspace_id = %s AND id = ANY(%s) ON CONFLICT DO NOTHING", (w["id"], user["id"], w["id"], inv["app_ids"] or []))
        audit.log(c, w["id"], "member.joined", user, target={"type": "member", "id": user["id"], "label": user["name"], "email": user["email"]},
                  detail={"role": inv["role"], "invite_id": inv["id"]})
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
    invite = accept_invite(c, u, body.invite.strip()) if body.invite else None
    audit.log_everywhere(c, u, "auth.sign_in")
    return {"session": session, "user": user_view(u), "next": t["next"], "invite": invite}


@router.post("/invites/accept")
def invite_accept(body: InviteToken, user=Depends(current_user), c=Depends(db)):
    out = accept_invite(c, user, body.invite.strip())
    if not out["accepted"]:
        raise HTTPException(409, out["detail"])
    return out


@router.post("/auth/logout")
def logout(authorization: str = Header(default=""), c=Depends(db)):
    if authorization.startswith("Bearer "):
        s = c.execute("UPDATE sessions SET revoked_at = now() WHERE token_hash = %s AND revoked_at IS NULL RETURNING user_id", (token_hash(authorization[7:].strip()),)).fetchone()
        if s:
            audit.log_everywhere(c, c.execute("SELECT * FROM users WHERE id = %s", (s["user_id"],)).fetchone(), "auth.sign_out")
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
        w = workspace_view(c, ws_for(c, user, m["id"]))
        w.pop("webhook_secret", None)  # a credential, not data about the person
        w.pop("webhook_url", None)     # so is a chat webhook URL
        w["apps"] = c.execute("SELECT id, repo, branch, client_label, verified_at, schedule, next_check_at, badge_public, created_at, "
                              "created_by FROM apps WHERE workspace_id = %s AND (%s <> 'client' OR id = ANY(%s)) ORDER BY created_at",
                              (m["id"], m["role"], client_apps(c, m["id"], uid))).fetchall()
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
            "answers": c.execute("SELECT check_id, question, answer, created_at FROM check_answers WHERE user_id = %s", (uid,)).fetchall(),
            "support_tickets": support.export(c, uid)}
    audit.log_everywhere(c, user, "data.exported")
    return JSONResponse(jsonable_encoder(data), headers={"Content-Disposition": 'attachment; filename="patchlabs-export.json"'})


@router.delete("/me")
def delete_me(user=Depends(current_user), c=Depends(db)):
    uid, email, deleted = user["id"], user["email"], 0
    for m in c.execute("SELECT workspace_id, role FROM workspace_members WHERE user_id = %s", (uid,)).fetchall():
        wid = m["workspace_id"]
        left = {"type": "member", "id": uid, "email": email}
        if m["role"] != "owner" or owners(c, wid) > 1:
            audit.log(c, wid, "member.left", user, target=left, detail={"role": m["role"], "account_deleted": True})
            continue
        # teammates keep the workspace: the highest role, then the longest-standing member, becomes its owner. Never a client:
        # a workspace with only clients left goes with the account.
        heir = c.execute("SELECT m.user_id, m.role, u.name, u.email FROM workspace_members m JOIN users u ON u.id = m.user_id "
                         "WHERE m.workspace_id = %s AND m.user_id <> %s AND m.role <> 'client' ORDER BY "
                         "array_position(%s::text[], m.role), m.created_at LIMIT 1", (wid, uid, list(PERMS_ORDER))).fetchone()
        if heir:
            c.execute("UPDATE workspace_members SET role = 'owner' WHERE workspace_id = %s AND user_id = %s", (wid, heir["user_id"]))
            audit.log(c, wid, "member.left", user, target=left, detail={"role": "owner", "account_deleted": True})
            audit.log(c, wid, "member.role_changed", kind="system", target={"type": "member", "id": heir["user_id"], "label": heir["name"],
                      "email": heir["email"]}, detail={"from": heir["role"], "to": "owner", "reason": "the only owner deleted their account"})
        else:
            c.execute("DELETE FROM workspaces WHERE id = %s", (wid,))  # apps, checks, keys, invites and the audit log go with it
            deleted += 1
    c.execute("DELETE FROM api_keys WHERE created_by = %s", (uid,))  # their keys stop working with them
    c.execute("DELETE FROM checks WHERE app_id IS NULL AND (user_id = %s OR lower(email) = lower(%s))", (uid, email))
    c.execute("UPDATE checks SET email = '' WHERE lower(email) = lower(%s)", (email,))
    c.execute("DELETE FROM login_tokens WHERE lower(email) = lower(%s)", (email,))
    c.execute("DELETE FROM invites WHERE lower(email) = lower(%s)", (email,))
    c.execute("UPDATE decisions SET by_label = 'a former member' WHERE user_id = %s", (uid,))
    c.execute("UPDATE check_answers SET by_label = 'a former member' WHERE user_id = %s", (uid,))
    audit.scrub_user(c, uid, email)
    c.execute("DELETE FROM users WHERE id = %s", (uid,))
    return {"ok": True, "deleted_workspaces": deleted}


# ---- workspaces --------------------------------------------------------------------------------------------------

class WorkspacePatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    webhook_url: str | None = Field(default=None, max_length=1000)
    webhook_format: str | None = Field(default=None, pattern=r"^(auto|json|slack|discord|teams)$")


class NewInvite(BaseModel):
    email: str = Field(max_length=254, pattern=EMAIL_RE)
    role: str = Field(default="member", pattern=ROLE)
    app_ids: list[str] | None = Field(default=None, max_length=500)


class RolePatch(BaseModel):
    role: str = Field(pattern=ROLE)
    app_ids: list[str] | None = Field(default=None, max_length=500)


class AppAccess(BaseModel):
    app_ids: list[str] = Field(max_length=500)


class NewKey(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class Upgrade(BaseModel):
    plan: str = Field(pattern=r"^(maker|agency|enterprise)$")
    note: str | None = Field(default=None, max_length=2000)


def webhook_host(url):
    """What the audit log keeps of a webhook: its host, never the URL (a Slack or Discord URL is a credential)."""
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def workspace_view(c, w):
    """What a member sees depends on their role: owners and admins see everything (the webhook secret too); the team sees
    teammates; a client sees only the workspace's name, plan and their own membership."""
    role = w.get("role")
    manage, team = can(role, "manage") if role else True, can(role, "view_team") if role else True
    members = c.execute("SELECT m.user_id, u.email, u.name, m.role, m.created_at AS joined_at FROM workspace_members m "
                        "JOIN users u ON u.id = m.user_id WHERE m.workspace_id = %s ORDER BY m.created_at", (w["id"],)).fetchall()
    for m in members:
        m["app_ids"] = client_apps(c, w["id"], m["user_id"]) if m["role"] == "client" else None
    out = {"id": w["id"], "name": w["name"], "plan": w["plan"], "role": role, "created_at": w["created_at"],
           "limits": limits(w) if team else None, "usage": usage(c, w["id"]) if team else None,
           "webhook_url": w["webhook_url"] if manage else None,
           "webhook_format": w.get("webhook_format", "auto") if manage else None,
           "webhook_kind": alerts.kind(w["webhook_url"], w.get("webhook_format")) if manage and w["webhook_url"] else None,
           "webhook_secret": w["webhook_secret"] if manage and role else None,
           "permissions": sorted(p for p in PERMS if can(role, p)) if role else None,
           "members": members if team else [m for m in members if m["role"] == "client" and w.get("viewer_id") == m["user_id"]],
           "invites": c.execute("SELECT id, email, role, app_ids, created_at, expires_at FROM invites WHERE workspace_id = %s "
                                "AND accepted_at IS NULL AND expires_at > now() ORDER BY created_at", (w["id"],)).fetchall() if manage else []}
    return out


def ws_for(c, user, wid, perm="view"):
    w = membership(c, user, wid, perm=perm)
    w["viewer_id"] = user["id"]
    return w


def owners(c, wid):
    return c.execute("SELECT count(*) AS n FROM workspace_members WHERE workspace_id = %s AND role = 'owner'", (wid,)).fetchone()["n"]


def member_target(m):
    return {"type": "member", "id": m["user_id"], "label": m.get("name"), "email": m.get("email")}


@router.get("/workspaces/{wid}")
def get_workspace(wid: str, user=Depends(current_user), c=Depends(db)):
    return workspace_view(c, ws_for(c, user, wid))


@router.patch("/workspaces/{wid}")
def patch_workspace(wid: str, body: WorkspacePatch, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid, perm="manage")
    if body.name is not None:
        name = clean_text(body.name) or w["name"]
        if name != w["name"]:
            c.execute("UPDATE workspaces SET name = %s WHERE id = %s", (name, w["id"]))
            audit.log(c, w["id"], "workspace.renamed", user, target={"type": "workspace", "id": w["id"], "label": name},
                      detail={"from": w["name"], "to": name})
    fmt_changed = body.webhook_format is not None and body.webhook_format != w["webhook_format"]
    if body.webhook_format is not None:
        c.execute("UPDATE workspaces SET webhook_format = %s WHERE id = %s", (body.webhook_format, w["id"]))
    if "webhook_url" in body.model_fields_set:
        url = (body.webhook_url or "").strip() or None
        if url:
            try:
                webhook_target(url)
            except ValueError as e:
                raise HTTPException(422, str(e))
        c.execute("UPDATE workspaces SET webhook_url = %s, webhook_secret = coalesce(webhook_secret, %s) WHERE id = %s",
                  (url, new_webhook_secret() if url else None, w["id"]))
        fmt = body.webhook_format or w["webhook_format"]
        if url != w["webhook_url"]:
            action = "webhook.created" if not w["webhook_url"] else "webhook.deleted" if not url else "webhook.changed"
            audit.log(c, w["id"], action, user, target={"type": "webhook", "id": w["id"], "label": webhook_host(url or w["webhook_url"])},
                      detail={"host": webhook_host(url or w["webhook_url"]), "kind": alerts.kind(url, fmt) if url else None,
                              **({"previous_host": webhook_host(w["webhook_url"])} if action == "webhook.changed" else {})})
            fmt_changed = False
    if fmt_changed and w["webhook_url"]:
        audit.log(c, w["id"], "webhook.changed", user, target={"type": "webhook", "id": w["id"], "label": webhook_host(w["webhook_url"])},
                  detail={"host": webhook_host(w["webhook_url"]), "format": {"from": w["webhook_format"], "to": body.webhook_format}})
    return workspace_view(c, ws_for(c, user, wid))


@router.post("/workspaces/{wid}/webhook/rotate-secret")
def rotate_webhook_secret(wid: str, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid, perm="manage")
    secret = c.execute("UPDATE workspaces SET webhook_secret = %s WHERE id = %s RETURNING webhook_secret",
                       (new_webhook_secret(), w["id"])).fetchone()["webhook_secret"]
    audit.log(c, w["id"], "webhook.secret_rotated", user, target={"type": "webhook", "id": w["id"], "label": webhook_host(w["webhook_url"])})
    return {"webhook_secret": secret}


@router.post("/workspaces/{wid}/webhook/test")
def test_webhook(wid: str, user=Depends(current_user), c=Depends(db)):
    """Sends a test in the webhook's own format: a chat message for Slack, Discord and Teams, the signed JSON otherwise."""
    w = membership(c, user, wid, perm="manage")
    if not w["webhook_url"]:
        raise HTTPException(409, "Add a webhook URL first.")
    k = alerts.kind(w["webhook_url"], w["webhook_format"])
    try:
        k, code = alerts.deliver(c, w, {"event": "test", "text": f"PatchLabs: webhooks for {w['name']} are working.",
                                        "workspace": {"id": str(w["id"]), "name": w["name"]}}, alerts.test_message(w["name"]))
        out = {"ok": 200 <= code < 300, "status_code": code, "format": k}
    except Exception as e:
        out = {"ok": False, "status_code": None, "format": k, "detail": str(e)[:300]}
    audit.log(c, w["id"], "webhook.tested", user, target={"type": "webhook", "id": w["id"], "label": webhook_host(w["webhook_url"])},
              detail={"ok": out["ok"], "status_code": out["status_code"], "format": k})
    return out


def own_apps(c, w, app_ids):
    """Validates app ids for a client: every one must be an app in this workspace."""
    ids = list(dict.fromkeys(as_uuid(a, "App not found.") for a in (app_ids or [])))
    found = {r["id"] for r in c.execute("SELECT id FROM apps WHERE workspace_id = %s AND id = ANY(%s)", (w["id"], ids)).fetchall()}
    if len(found) != len(ids):
        raise HTTPException(422, "Every app you share with a client must be in this workspace.")
    return ids


def may_assign(w, role):
    """Owners give any role; admins give any role below owner."""
    if role == "owner" and w["role"] != "owner":
        raise HTTPException(403, "Only a workspace owner can make someone an owner.")


@router.post("/workspaces/{wid}/invites", status_code=201)
def create_invite(wid: str, body: NewInvite, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid, perm="manage")
    may_assign(w, body.role)
    if body.app_ids and body.role != "client":
        raise HTTPException(422, "Only clients are limited to chosen apps; other roles see every app.")
    app_ids = own_apps(c, w, body.app_ids) if body.role == "client" else []
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
    pending = c.execute("SELECT count(*) AS n FROM invites WHERE workspace_id = %s AND accepted_at IS NULL AND expires_at > now() "
                        "AND role <> 'client'", (w["id"],)).fetchone()["n"]
    seats = limits(w)["seats"]
    if body.role != "client" and usage(c, w["id"])["members"] + pending >= seats:  # clients never take a seat
        raise HTTPException(403, f"The {w['plan']} plan has {seats} seat{'s' if seats != 1 else ''}, all taken or invited. "
                                 "Request an upgrade for more.")
    tok = secrets.token_urlsafe(32)
    inv = c.execute("INSERT INTO invites (id, workspace_id, email, role, app_ids, token_hash, invited_by, expires_at) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, now() + interval '14 days') RETURNING id, email, role, app_ids, created_at, expires_at",
                    (uuid.uuid4(), w["id"], email, body.role, app_ids, token_hash(tok), user["id"])).fetchone()
    record(c, "invite", w["id"])
    record(c, "invite_address", per_address)
    audit.log(c, w["id"], "member.invited", user, target={"type": "invite", "id": inv["id"], "email": email},
              detail={"role": body.role, **({"apps": len(app_ids)} if body.role == "client" else {})})
    what = ("see the apps shared with you" if body.role == "client" else
            {"viewer": "see its apps and reports", "member": "see its apps and run checks",
             "approver": "run checks and approve or reject fixes"}.get(body.role, "help manage it"))
    mail(email, f"Join {w['name']} on PatchLabs",
         f"{user['name'] or user['email']} invited you to the {w['name']} workspace on PatchLabs, which finds and fixes "
         f"personal-data leaks in AI-built apps. You'll be able to {what}.\n\nJoin here (sign in with this email address):\n"
         f"{SITE_URL}/app/login?{urlencode({'invite': tok})}\n\nThe invite expires in 14 days.\n\nPatchLabs")
    return inv


@router.delete("/workspaces/{wid}/invites/{iid}")
def delete_invite(wid: str, iid: str, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid, perm="manage")
    inv = c.execute("DELETE FROM invites WHERE id = %s AND workspace_id = %s RETURNING id, email, role", (as_uuid(iid), w["id"])).fetchone()
    if not inv:
        raise HTTPException(404, "Invite not found.")
    audit.log(c, w["id"], "member.invite_cancelled", user, target={"type": "invite", "id": inv["id"], "email": inv["email"]},
              detail={"role": inv["role"]})
    return {"ok": True}


def member_row(c, wid, uid):
    m = c.execute("SELECT m.*, u.email, u.name FROM workspace_members m JOIN users u ON u.id = m.user_id "
                  "WHERE m.workspace_id = %s AND m.user_id = %s", (wid, as_uuid(uid, "Member not found."))).fetchone()
    if not m:
        raise HTTPException(404, "Member not found.")
    return m


def drop_keys(c, w, m, actor, reason):
    """A leaver's keys, or the keys of someone who can no longer run checks, stop working."""
    for k in c.execute("DELETE FROM api_keys WHERE workspace_id = %s AND created_by = %s RETURNING id, name, prefix",
                       (w["id"], m["user_id"])).fetchall():
        audit.log(c, w["id"], "api_key.revoked", actor, target={"type": "api_key", "id": k["id"], "label": k["name"]},
                  detail={"prefix": k["prefix"], "reason": reason})


def manage_check(w, user, m):
    """Owners manage anyone; admins manage everyone but owners."""
    if not can(w["role"], "manage"):
        raise HTTPException(403, "Only a workspace owner or admin can do that.")
    if m["role"] == "owner" and w["role"] != "owner":
        raise HTTPException(403, "Only a workspace owner can change or remove an owner.")


@router.delete("/workspaces/{wid}/members/{uid}")
def remove_member(wid: str, uid: str, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid)
    m = member_row(c, w["id"], uid)
    leaving = m["user_id"] == user["id"]
    if not leaving:
        manage_check(w, user, m)
    if m["role"] == "owner" and owners(c, w["id"]) <= 1:
        raise HTTPException(409, "A workspace needs at least one owner. Make someone else an owner first.")
    drop_keys(c, w, m, user, "member left" if leaving else "member removed")
    c.execute("DELETE FROM workspace_members WHERE workspace_id = %s AND user_id = %s", (w["id"], m["user_id"]))
    audit.log(c, w["id"], "member.left" if leaving else "member.removed", user, target=member_target(m), detail={"role": m["role"]})
    return {"ok": True}


@router.patch("/workspaces/{wid}/members/{uid}")
def set_role(wid: str, uid: str, body: RolePatch, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid, perm="manage")
    m = member_row(c, w["id"], uid)
    manage_check(w, user, m)
    may_assign(w, body.role)
    if body.app_ids is not None and body.role != "client":
        raise HTTPException(422, "Only clients are limited to chosen apps; other roles see every app.")
    if m["role"] == "owner" and body.role != "owner" and owners(c, w["id"]) <= 1:
        raise HTTPException(409, "A workspace needs at least one owner. Make someone else an owner first.")
    app_ids = own_apps(c, w, body.app_ids) if body.app_ids is not None else None
    if m["role"] == "client" and body.role != "client":  # a client turning into a teammate needs a free seat
        seats = limits(w)["seats"]
        if usage(c, w["id"])["members"] >= seats:
            raise HTTPException(403, f"The {w['plan']} plan has {seats} seat{'s' if seats != 1 else ''}, all taken. Clients don't use "
                                     "seats, but other roles do. Request an upgrade for more.")
    if body.role != m["role"]:
        c.execute("UPDATE workspace_members SET role = %s WHERE workspace_id = %s AND user_id = %s", (body.role, w["id"], m["user_id"]))
        audit.log(c, w["id"], "member.role_changed", user, target=member_target(m), detail={"from": m["role"], "to": body.role})
        if m["role"] == "client":
            c.execute("DELETE FROM member_app_access WHERE workspace_id = %s AND user_id = %s", (w["id"], m["user_id"]))
        if not can(body.role, "run"):
            drop_keys(c, w, m, user, f"role changed to {body.role}")
    if body.role == "client" and app_ids is not None:
        set_app_access(c, w, m, app_ids, user)
    return workspace_view(c, ws_for(c, user, wid))


def set_app_access(c, w, m, app_ids, user):
    before = set(client_apps(c, w["id"], m["user_id"]))
    c.execute("DELETE FROM member_app_access WHERE workspace_id = %s AND user_id = %s", (w["id"], m["user_id"]))
    for a in app_ids:
        c.execute("INSERT INTO member_app_access (workspace_id, user_id, app_id) VALUES (%s, %s, %s)", (w["id"], m["user_id"], a))
    if before != set(app_ids):
        audit.log(c, w["id"], "member.apps_changed", user, target=member_target(m),
                  detail={"added": [str(a) for a in app_ids if a not in before], "removed": [str(a) for a in before if a not in set(app_ids)]})


@router.put("/workspaces/{wid}/members/{uid}/apps")
def put_app_access(wid: str, uid: str, body: AppAccess, user=Depends(current_user), c=Depends(db)):
    """The apps a client sees (replaces the list). Only for members with the client role."""
    w = membership(c, user, wid, perm="manage")
    m = member_row(c, w["id"], uid)
    if m["role"] != "client":
        raise HTTPException(409, "Only clients are limited to chosen apps; other roles see every app.")
    set_app_access(c, w, m, own_apps(c, w, body.app_ids), user)
    return workspace_view(c, ws_for(c, user, wid))


@router.get("/workspaces/{wid}/api-keys")
def list_keys(wid: str, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid, perm="view_team")
    return {"api_keys": c.execute("SELECT k.id, k.name, k.prefix, k.created_at, k.last_used_at, k.created_by, u.email AS created_by_email "
                                  "FROM api_keys k LEFT JOIN users u ON u.id = k.created_by WHERE k.workspace_id = %s "
                                  "ORDER BY k.created_at", (w["id"],)).fetchall()}


@router.post("/workspaces/{wid}/api-keys", status_code=201)
def create_key(wid: str, body: NewKey, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid, perm="run")
    key = "pl_live_" + secrets.token_urlsafe(24)
    k = c.execute("INSERT INTO api_keys (id, workspace_id, name, prefix, key_hash, created_by) VALUES (%s, %s, %s, %s, %s, %s) "
                  "RETURNING id, name, prefix, created_at, last_used_at, created_by",
                  (uuid.uuid4(), w["id"], clean_text(body.name) or "key", key[:12], token_hash(key), user["id"])).fetchone()
    audit.log(c, w["id"], "api_key.created", user, target={"type": "api_key", "id": k["id"], "label": k["name"]}, detail={"prefix": k["prefix"]})
    return {**k, "created_by_email": user["email"], "key": key}


@router.delete("/workspaces/{wid}/api-keys/{kid}")
def delete_key(wid: str, kid: str, user=Depends(current_user), c=Depends(db)):
    """Owners and admins revoke any key; members and approvers revoke their own."""
    w = membership(c, user, wid, perm="run")
    k = c.execute("SELECT id, name, prefix, created_by FROM api_keys WHERE id = %s AND workspace_id = %s", (as_uuid(kid), w["id"])).fetchone()
    if not k:
        raise HTTPException(404, "API key not found.")
    if k["created_by"] != user["id"] and not can(w["role"], "manage"):
        raise HTTPException(403, "You can revoke your own keys. Ask a workspace owner or admin to revoke this one.")
    c.execute("DELETE FROM api_keys WHERE id = %s", (k["id"],))
    audit.log(c, w["id"], "api_key.revoked", user, target={"type": "api_key", "id": k["id"], "label": k["name"]}, detail={"prefix": k["prefix"]})
    return {"ok": True}


@router.post("/workspaces/{wid}/upgrade-request", status_code=201)
def upgrade_request(wid: str, body: Upgrade, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid, perm="manage")
    if recent(c, "upgrade_request", w["id"]) >= UPGRADES_PER_WORKSPACE_PER_DAY:
        raise HTTPException(429, "We already have your upgrade request and will reply within a day.")
    record(c, "upgrade_request", w["id"])
    r = c.execute("INSERT INTO upgrade_requests (id, workspace_id, user_id, plan, note) VALUES (%s, %s, %s, %s, %s) "
                  "RETURNING id, plan, note, created_at", (uuid.uuid4(), w["id"], user["id"], body.plan, body.note)).fetchone()
    audit.log(c, w["id"], "upgrade.requested", user, target={"type": "workspace", "id": w["id"], "label": w["name"]},
              detail={"from": w["plan"], "to": body.plan})
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
    before = c.execute("SELECT plan, app_limit, run_limit, seat_limit FROM workspaces WHERE id = %s", (wid,)).fetchone()
    changes = {}
    for col in ("plan", "app_limit", "run_limit", "seat_limit"):
        if col in body.model_fields_set and (col != "plan" or body.plan):
            c.execute(f"UPDATE workspaces SET {col} = %s WHERE id = %s", (getattr(body, col), wid))
            if getattr(body, col) != before[col]:
                changes[col] = {"from": before[col], "to": getattr(body, col)}
    if changes:
        audit.log(c, wid, "plan.changed", kind="admin", target={"type": "workspace", "id": wid}, detail=changes)
    return admin_view(c, c.execute("SELECT * FROM workspaces WHERE id = %s", (wid,)).fetchone())


@router.get("/admin/upgrade-requests", dependencies=[Depends(bearer(ADMIN_TOKEN))])
def admin_upgrades(c=Depends(db)):
    return {"upgrade_requests": c.execute(
        "SELECT r.id, r.created_at, r.plan, r.note, r.workspace_id, w.name AS workspace_name, w.plan AS current_plan, u.email "
        "FROM upgrade_requests r JOIN workspaces w ON w.id = r.workspace_id LEFT JOIN users u ON u.id = r.user_id "
        "ORDER BY r.created_at DESC LIMIT 200").fetchall()}
