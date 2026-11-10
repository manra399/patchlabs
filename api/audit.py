"""Account audit log: an append-only record of who did what in a workspace (db trigger audit_log_append_only).

  GET /workspaces/{wid}/audit          owner/admin; newest first, filters action/actor/since/until, cursor pagination
  GET /workspaces/{wid}/audit/export   the same filters as a CSV download (up to 10,000 rows); recorded as audit.exported

Never logs secrets, tokens or full webhook URLs (only the host). Emails are shown in full only while the person is a member
or has a pending invite; otherwise masked (m•••@domain), and "a former member" after they delete their account.
"""
import csv, io, json
from datetime import date, datetime, time, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import Response
from psycopg.types.json import Jsonb

from core import as_uuid, current_user, db, mask_email, membership

router = APIRouter()
FORMER = "a former member"
ACTIONS = (
    "auth.sign_in", "auth.sign_out",
    "member.invited", "member.invite_cancelled", "member.joined", "member.role_changed", "member.apps_changed", "member.removed",
    "member.left",
    "workspace.renamed", "plan.changed", "upgrade.requested",
    "app.added", "app.updated", "app.verified", "app.removed", "app.live_set", "app.live_verified", "app.live_removed", "posture.checked",
    "check.started", "decision.made", "check.answered", "suppression.added", "suppression.removed",
    "api_key.created", "api_key.revoked",
    "webhook.created", "webhook.changed", "webhook.deleted", "webhook.secret_rotated", "webhook.tested",
    "data.exported", "audit.exported", "ticket.raised",
)
SECRETISH = ("secret", "token", "key_hash", "password", "webhook_url", "session")


def _clean(detail):
    """Belt and braces: drop any detail field whose name suggests a credential."""
    return {k: v for k, v in (detail or {}).items() if not any(s in k.lower() for s in SECRETISH)}


def log(c, wid, action, user=None, *, kind="user", name=None, target=None, detail=None):
    """Appends one row. `user` is the acting user (a users row); kind is api_key/admin/system for everything else, with
    `name` as its label (e.g. "API key CI (pl_live_Xy3k)"). target = {type, id, label?, email?}."""
    assert action in ACTIONS, action
    t = target or {}
    if user is not None:
        kind, actor_id, actor_name, actor_email = "user", user["id"], user.get("name"), user.get("email")
    else:
        actor_id, actor_name, actor_email = None, name, None
    c.execute("INSERT INTO audit_log (workspace_id, action, actor_kind, actor_id, actor_name, actor_email, target_type, target_id, "
              "target_label, target_email, detail) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
              (wid, action, kind, actor_id, actor_name, actor_email, t.get("type"), str(t["id"]) if t.get("id") is not None else None,
               t.get("label"), t.get("email"), Jsonb(jsonable_encoder(_clean(detail)))))


def log_everywhere(c, user, action):
    """Account-level events (sign-in, sign-out, data export) go into every workspace the user belongs to."""
    for r in c.execute("SELECT workspace_id FROM workspace_members WHERE user_id = %s", (user["id"],)).fetchall():
        log(c, r["workspace_id"], action, user)


def scrub_user(c, uid, email):
    """Account deletion: the person's name and email leave the log; their rows read 'a former member'."""
    c.execute("UPDATE audit_log SET actor_id = NULL, actor_name = NULL, actor_email = NULL WHERE actor_id = %s", (uid,))
    c.execute("UPDATE audit_log SET target_email = %s, target_label = NULL WHERE lower(target_email) = lower(%s)",
              (mask_email(email), email))


# ---- reading -----------------------------------------------------------------------------------------------------

def _known_emails(c, wid):
    """Emails shown in full: current members and pending invites. Everyone else is masked."""
    rows = c.execute("SELECT lower(u.email) AS e FROM workspace_members m JOIN users u ON u.id = m.user_id WHERE m.workspace_id = %(w)s "
                     "UNION SELECT lower(email) FROM invites WHERE workspace_id = %(w)s AND accepted_at IS NULL AND expires_at > now()",
                     {"w": wid}).fetchall()
    return {r["e"] for r in rows}


def _email(e, known):
    if not e:
        return None
    return e if e.lower() in known or "•" in e else mask_email(e)


def view(r, known):
    if r["actor_kind"] == "user":
        email = _email(r["actor_email"], known)
        label = (r["actor_name"] or email) if r["actor_id"] else FORMER
        actor = {"kind": "user", "id": r["actor_id"], "label": label, "email": email if r["actor_id"] else None}
    else:
        actor = {"kind": r["actor_kind"], "id": None, "label": r["actor_name"] or {"admin": "PatchLabs admin", "system": "PatchLabs"}.get(
            r["actor_kind"], r["actor_kind"]), "email": None}
    temail = _email(r["target_email"], known)
    target = None
    if r["target_type"]:
        target = {"type": r["target_type"], "id": r["target_id"], "label": r["target_label"] or temail, "email": temail}
    return {"id": r["id"], "at": r["at"], "action": r["action"], "actor": actor, "target": target, "detail": r["detail"]}


def _when(s, end=False):
    if not s:
        return None
    try:
        if len(s) == 10:
            d = date.fromisoformat(s)
            return datetime.combine(d + timedelta(days=1) if end else d, time.min, timezone.utc)
        t = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    except ValueError:
        raise HTTPException(422, "Dates look like 2026-11-10 or 2026-11-10T09:30:00Z.")


def query(c, wid, action=None, actor=None, since=None, until=None, before=None, limit=50):
    where, params = ["workspace_id = %s"], [wid]
    if action:
        if "." in action:
            where.append("action = %s")
            params.append(action)
        else:  # a family: "member" matches member.*
            where.append("action LIKE %s")
            params.append(action.replace("%", "").replace("_", "\\_") + ".%")
    if actor:
        if actor in ("api_key", "admin", "system"):
            where.append("actor_kind = %s")
            params.append(actor)
        else:
            where.append("actor_id = %s")
            params.append(as_uuid(actor, "Unknown actor."))
    if since:
        where.append("at >= %s")
        params.append(_when(since))
    if until:
        where.append("at < %s")
        params.append(_when(until, end=True))
    if before:
        where.append("id < %s")
        params.append(before)
    return c.execute("SELECT * FROM audit_log WHERE " + " AND ".join(where) + " ORDER BY id DESC LIMIT %s", params + [limit]).fetchall()


@router.get("/workspaces/{wid}/audit")
def get_audit(wid: str, action: str | None = Query(default=None, max_length=60), actor: str | None = Query(default=None, max_length=60), since: str | None = Query(default=None, max_length=40),
              until: str | None = Query(default=None, max_length=40), before: int | None = Query(default=None, ge=1), limit: int = Query(default=50, ge=1, le=200),
              user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid, perm="manage")
    rows = query(c, w["id"], action, actor, since, until, before, limit + 1)
    known = _known_emails(c, w["id"])
    more = len(rows) > limit
    rows = rows[:limit]
    return {"events": [view(r, known) for r in rows], "next_before": rows[-1]["id"] if more else None, "actions": list(ACTIONS)}


def _cell(v):
    """CSV cells: no formula injection when opened in a spreadsheet."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


@router.get("/workspaces/{wid}/audit/export")
def export_audit(wid: str, action: str | None = Query(default=None, max_length=60), actor: str | None = Query(default=None, max_length=60), since: str | None = Query(default=None, max_length=40),
                 until: str | None = Query(default=None, max_length=40), user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid, perm="manage")
    rows = query(c, w["id"], action, actor, since, until, None, 10_000)
    known = _known_emails(c, w["id"])
    out = io.StringIO()
    wr = csv.writer(out)
    wr.writerow(["id", "at", "action", "actor_kind", "actor", "actor_email", "target_type", "target_id", "target", "target_email", "detail"])
    for r in rows:
        v = view(r, known)
        a, t = v["actor"], v["target"] or {}
        wr.writerow([_cell(x) for x in (v["id"], v["at"].isoformat(), v["action"], a["kind"], a["label"], a["email"], t.get("type"),
                                        t.get("id"), t.get("label"), t.get("email"),
                                        json.dumps(v["detail"], sort_keys=True, ensure_ascii=False))])
    log(c, w["id"], "audit.exported", user, detail={"rows": len(rows), **{k: v for k, v in
                                                     {"action": action, "actor": actor, "since": since, "until": until}.items() if v}})
    return Response(out.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="patchlabs-audit-{w["id"]}.csv"'})
