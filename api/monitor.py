"""Monitored apps: verification, run-now, schedules, diffs between checks, notifications, badges, public status and CI."""
import html, secrets, uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field

import alerts, audit, posture, taxonomy
from core import (FINISHED, NEXT_AT, SITE_URL, VERIFY_FILE, api_key, as_uuid, clean_text, client_apps, current_user, db, event, leaking,
                  limits, may_see_app, membership, notify, parse_repo, recent, record, repo_has_code, repo_lookup, require, scrub, usage,
                  verify_info)

router = APIRouter()
OPEN = ("queued", "running")
SCHEDULE = r"^(off|weekly|monthly)$"


def check_url(cid):
    return f"{SITE_URL}/check?id={cid}"


def app_for(c, user, aid, perm="view"):
    """The app, if the user may see it (a client only sees apps shared with them; to anyone else it doesn't exist), and
    their role allows `perm`."""
    a = c.execute("SELECT a.*, m.role FROM apps a JOIN workspace_members m ON m.workspace_id = a.workspace_id AND m.user_id = %s "
                  "WHERE a.id = %s", (user["id"], as_uuid(aid, "App not found."))).fetchone()
    if not a or not may_see_app(c, a["role"], a["workspace_id"], user["id"], a["id"]):
        raise HTTPException(404, "App not found.")
    require(a["role"], perm)
    return a


def app_target(a):
    return {"type": "app", "id": a["id"], "label": a["repo"] + (f" ({a['client_label']})" if a.get("client_label") else "")}


def key_actor(key):
    return f"API key {key.get('name') or ''} ({key.get('prefix') or 'pl_live_'}…)".replace("  ", " ")


def log_check(c, a, cid, trigger, user=None, key=None):
    audit.log(c, a["workspace_id"], "check.started", user, kind="api_key" if key else "system", name=key_actor(key) if key else None,
              target={"type": "check", "id": cid, "label": a["repo"]}, detail={"trigger": trigger, "app_id": a["id"]})


# ---- freshness ---------------------------------------------------------------------------------------------------
# A result goes stale when the last finished check is older than twice the schedule interval, or 45 days for apps
# without a schedule. Stale results never claim "no known leaks".
INTERVAL_DAYS = {"weekly": 7, "monthly": 30}
MANUAL_STALE_DAYS = 45


def stale_after(schedule):
    return 2 * INTERVAL_DAYS[schedule] if schedule in INTERVAL_DAYS else MANUAL_STALE_DAYS


def freshness(schedule, finished_at, now=None):
    limit = stale_after(schedule)
    if not finished_at:
        return {"stale": False, "days_since_check": None, "stale_after_days": limit}
    age = (now or datetime.now(timezone.utc)) - finished_at
    return {"stale": age > timedelta(days=limit), "days_since_check": max(0, age.days), "stale_after_days": limit}


def workspace_of(c, a):
    return c.execute("SELECT * FROM workspaces WHERE id = %s", (a["workspace_id"],)).fetchone()


def app_view(c, a, full=True):
    last = c.execute("SELECT id, status, finished_at, summary FROM checks WHERE app_id = %s AND finished_at IS NOT NULL "
                     "ORDER BY finished_at DESC LIMIT 1", (a["id"],)).fetchone()
    open_ = c.execute("SELECT id FROM checks WHERE app_id = %s AND status IN ('queued', 'running') LIMIT 1", (a["id"],)).fetchone()
    out = {k: a[k] for k in ("id", "workspace_id", "repo", "branch", "client_label", "schedule", "next_check_at", "badge_public",
                             "created_at", "verified_at")}
    out["verified"] = a["verified_at"] is not None
    out["last_check"] = {"id": last["id"], "status": last["status"], "finished_at": last["finished_at"],
                         "tables_leaking": leaking(last["summary"])} if last else None
    out["open_check_id"] = open_["id"] if open_ else None
    out["suppressed_tables"] = suppressed(c, a["id"])
    fin = c.execute("SELECT max(finished_at) AS at FROM checks WHERE app_id = %s AND status IN ('done', 'no_leaks', 'needs_review')",
                    (a["id"],)).fetchone()["at"]
    out["freshness"] = freshness(a["schedule"], fin)
    if not out["verified"]:
        out["verify"] = verify_info(a["repo"], a["branch"], a["verify_code"])
    out["live"] = posture.live_view(c, a, full)
    return out


def suppressed(c, aid):
    return [r["table_name"] for r in c.execute("SELECT table_name FROM finding_suppressions WHERE app_id = %s ORDER BY table_name",
                                               (aid,)).fetchall()]


def diff(c, aid):
    rows = c.execute("SELECT id, summary FROM checks WHERE app_id = %s AND status IN ('done', 'no_leaks', 'needs_review') "
                     "ORDER BY finished_at DESC LIMIT 2", (aid,)).fetchall()
    cur = leaking(rows[0]["summary"]) if rows else []
    prev = leaking(rows[1]["summary"]) if len(rows) > 1 else []
    sup = suppressed(c, aid)
    return {"new_leaks": [t for t in cur if t not in prev and t not in sup], "fixed": [t for t in prev if t not in cur],
            "still_leaking": [t for t in cur if t in prev and t not in sup], "suppressed": [t for t in cur if t in sup],
            "to_check_id": rows[0]["id"] if rows else None, "from_check_id": rows[1]["id"] if len(rows) > 1 else None}


def check_extras(c, k):
    """For one check: its tables the app's team marked as intended, and its new leaks versus the app's previous finished
    check (suppressed tables left out). Both are empty for anonymous and unfinished checks."""
    if not k.get("app_id") or k["status"] not in FINISHED:
        return {"suppressed_tables": [], "new_leaks": []}
    cur, sup = leaking(k["summary"]), set(suppressed(c, k["app_id"]))
    prev = c.execute("SELECT summary FROM checks WHERE app_id = %s AND id <> %s AND status IN ('done', 'no_leaks', 'needs_review') "
                     "AND finished_at < %s ORDER BY finished_at DESC LIMIT 1", (k["app_id"], k["id"], k["finished_at"])).fetchone()
    before = leaking(prev["summary"]) if prev else []
    return {"suppressed_tables": [t for t in cur if t in sup], "new_leaks": [t for t in cur if t not in before and t not in sup]}


def queue_check(c, a, trigger, email="", user=None, key=None):
    cid = uuid.uuid4()
    c.execute("INSERT INTO checks (id, email, repo, verify_code, branch, status, verified_at, app_id, trigger) "
              "VALUES (%s, %s, %s, %s, %s, 'queued', now(), %s, %s)",
              (cid, email or "", a["repo"], a["verify_code"], a["branch"], a["id"], trigger))
    event(c, cid, "requested", trigger)
    log_check(c, a, cid, trigger, user, key)
    return cid


def run_now(c, a, trigger, email="", user=None, key=None):
    c.execute("SELECT id FROM apps WHERE id = %s FOR UPDATE", (a["id"],))
    if not a["verified_at"]:
        raise HTTPException(409, "Verify the app before running checks.")
    if c.execute("SELECT 1 FROM checks WHERE app_id = %s AND status IN ('queued', 'running')", (a["id"],)).fetchone():
        raise HTTPException(409, "A check is already queued or running for this app.")
    w = workspace_of(c, a)
    lim = limits(w)
    if usage(c, w["id"])["runs_this_month"] >= lim["runs_per_month"]:
        n = lim["runs_per_month"]
        raise HTTPException(429, f"You've used {'your 1 run' if n == 1 else f'all {n} runs'} this month on the {w['plan']} plan. "
                                 "Scheduled re-checks still run; request an upgrade for more.")
    cid = queue_check(c, a, trigger, email, user, key)
    record(c, "run", w["id"])  # counted in a log, so deleting the app doesn't hand the runs back
    return {"check_id": cid, "status": "queued", "url": check_url(cid)}


def schedule_due(c):
    """Queues a 'scheduled' check for every verified app that is due and has no open check."""
    due = c.execute("SELECT a.* FROM apps a WHERE a.verified_at IS NOT NULL AND a.schedule <> 'off' AND a.next_check_at <= now() "
                    "AND NOT EXISTS (SELECT 1 FROM checks k WHERE k.app_id = a.id AND k.status IN ('queued', 'running')) "
                    "FOR UPDATE SKIP LOCKED").fetchall()
    for a in due:
        queue_check(c, a, "scheduled")
        c.execute(f"UPDATE apps SET next_check_at = {NEXT_AT} WHERE id = %s", (a["id"],))
    return len(due)


HEADLINES = {"no_leaks": "no data leaks found", "done": "leaks found and a tested fix is ready",
             "needs_review": "leaks found; a person is reviewing the fix", "failed": "the check could not finish; we have been alerted"}


def recipients(c, wid, aid):
    """Everyone who hears about an app: the team, plus clients the app is shared with."""
    return [m["email"] for m in c.execute(
        "SELECT u.email FROM workspace_members m JOIN users u ON u.id = m.user_id WHERE m.workspace_id = %s "
        "AND (m.role <> 'client' OR EXISTS (SELECT 1 FROM member_app_access x WHERE x.workspace_id = m.workspace_id "
        "AND x.user_id = m.user_id AND x.app_id = %s)) ORDER BY m.created_at", (wid, aid)).fetchall()]


def notify_app_check(c, cid):
    k = c.execute("SELECT k.id, k.status, k.summary, a.id AS app_id, a.repo, a.client_label, a.workspace_id, w.webhook_url, "
                  "w.webhook_secret, w.webhook_format, w.id AS wid "
                  "FROM checks k JOIN apps a ON a.id = k.app_id JOIN workspaces w ON w.id = a.workspace_id WHERE k.id = %s",
                  (cid,)).fetchone()
    if not k:
        return
    name = f"{k['repo']} ({k['client_label']})" if k["client_label"] else k["repo"]
    tables, url, headline = leaking(k["summary"]), check_url(cid), HEADLINES[k["status"]]
    d = diff(c, k["app_id"]) if k["status"] != "failed" else {"new_leaks": [], "fixed": [], "still_leaking": [], "suppressed": []}
    if k["status"] != "failed":
        subject = f"New leak found in {name}" if d["new_leaks"] else f"PatchLabs check finished for {name}"
        lines = [f"Your PatchLabs check of {name} has finished: {headline}."]
        if d["new_leaks"]:
            lines.append("New leaks since the last check: " + ", ".join(d["new_leaks"]))
        if d["fixed"]:
            lines.append("Fixed since the last check: " + ", ".join(d["fixed"]))
        if d["still_leaking"]:
            lines.append("Still leaking: " + ", ".join(d["still_leaking"]))
        if d["suppressed"]:
            lines.append("Marked as intended by your team (no alert): " + ", ".join(d["suppressed"]))
        lines += [f"See the report and the fix:\n{url}", f"Manage this app:\n{SITE_URL}/app/app?id={k['app_id']}", "PatchLabs"]
        for email in recipients(c, k["workspace_id"], k["app_id"]):
            notify(c, cid, email, subject, "\n\n".join(lines))
    if k["webhook_url"]:
        payload = {"event": "check.finished", "text": f"PatchLabs: {name}: {headline}. {url}",
                   "check": {"id": str(cid), "app_id": str(k["app_id"]), "repo": k["repo"], "status": k["status"],
                             "tables_leaking": tables, "url": url, "new_leaks": d["new_leaks"], "fixed": d["fixed"],
                             "suppressed": d["suppressed"]}}
        message = alerts.check_message(name, headline, k["status"], k["summary"], d, url, f"{SITE_URL}/app/app?id={k['app_id']}")
        try:
            w = {"id": k["wid"], "webhook_url": k["webhook_url"], "webhook_secret": k["webhook_secret"], "webhook_format": k["webhook_format"]}
            kind, code = alerts.deliver(c, w, payload, message)
            event(c, cid, "webhook_sent", str(code) if kind == "json" else f"{code} ({kind})")
        except Exception as e:  # a broken webhook must never lose the check
            event(c, cid, "webhook_failed", str(e)[:300])


class NewApp(BaseModel):
    repo: str = Field(max_length=200)
    client_label: str | None = Field(default=None, max_length=100)
    schedule: str | None = Field(default=None, pattern=SCHEDULE)


class AppPatch(BaseModel):
    client_label: str | None = Field(default=None, max_length=100)
    schedule: str | None = Field(default=None, pattern=SCHEDULE)
    badge_public: bool | None = None


def allow_schedule(w, schedule):
    if schedule not in limits(w)["schedules"]:
        raise HTTPException(403, f"The {w['plan']} plan doesn't include {schedule} re-checks. Request an upgrade to use them.")


@router.get("/workspaces/{wid}/apps")
def list_apps(wid: str, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid)
    rows = c.execute("SELECT * FROM apps WHERE workspace_id = %s ORDER BY created_at", (w["id"],)).fetchall()
    if w["role"] == "client":
        mine = set(client_apps(c, w["id"], user["id"]))
        rows = [a for a in rows if a["id"] in mine]
    return {"apps": [app_view(c, a, full=False) for a in rows]}


@router.post("/workspaces/{wid}/apps", status_code=201)
def create_app(wid: str, body: NewApp, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid, perm="manage")
    schedule, lim = body.schedule or "monthly", limits(w)
    allow_schedule(w, schedule)
    if usage(c, w["id"])["apps"] >= lim["apps"]:
        raise HTTPException(403, f"The {w['plan']} plan allows {lim['apps']} app{'s' if lim['apps'] != 1 else ''}. "
                                 "Remove one or request an upgrade.")
    repo, branch = repo_lookup(parse_repo(body.repo))
    if c.execute("SELECT 1 FROM apps WHERE workspace_id = %s AND lower(repo) = lower(%s)", (w["id"], repo)).fetchone():
        raise HTTPException(409, f"{repo} is already in this workspace.")
    aid = uuid.uuid4()
    a = c.execute("INSERT INTO apps (id, workspace_id, repo, branch, client_label, verify_code, schedule, created_by) "
                  "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING *",
                  (aid, w["id"], repo, branch, clean_text(body.client_label) or None, "patchlabs-" + secrets.token_hex(8),
                   schedule, user["id"])).fetchone()
    audit.log(c, w["id"], "app.added", user, target=app_target(a), detail={"repo": repo, "schedule": schedule})
    return app_view(c, a)


@router.post("/apps/{aid}/verify")
def verify_app(aid: str, user=Depends(current_user), c=Depends(db)):
    a = app_for(c, user, aid, "manage")
    if a["verified_at"]:
        return {"verified": True, "check_id": None}
    if not repo_has_code(a["repo"], a["branch"], a["verify_code"]):
        raise HTTPException(409, f"We couldn't find {VERIFY_FILE} with your code on the default branch yet. "
                                 "GitHub can take a minute to update; try again shortly.")
    a = c.execute(f"UPDATE apps SET verified_at = now(), next_check_at = {NEXT_AT} WHERE id = %s RETURNING *", (a["id"],)).fetchone()
    audit.log(c, a["workspace_id"], "app.verified", user, target=app_target(a))
    repo_key = f"{a['workspace_id']}:{a['repo'].lower()}"
    readded = recent(c, "verified_repo", repo_key, "100 years") > 0
    record(c, "verified_repo", repo_key)
    if readded:  # deleted and added again: its first check is a normal run, so it can't reset the monthly limit
        w = workspace_of(c, a)
        if usage(c, w["id"])["runs_this_month"] >= limits(w)["runs_per_month"]:
            return {"verified": True, "check_id": None,
                    "detail": "Verified. This month's runs are used up: run the first check next month, or wait for the scheduled one."}
        record(c, "run", w["id"])
    return {"verified": True, "check_id": queue_check(c, a, "verify", user["email"], user)}


@router.get("/apps/{aid}")
def get_app(aid: str, user=Depends(current_user), c=Depends(db)):
    a = app_for(c, user, aid)
    out = app_view(c, a)
    out["checks"] = [{"id": r["id"], "status": r["status"], "trigger": r["trigger"], "created_at": r["created_at"],
                      "finished_at": r["finished_at"], "tables_leaking": leaking(r["summary"]) if r["status"] in FINISHED else None,
                      "lab_proof_passed": (r["summary"] or {}).get("lab_proof_passed") if isinstance(r["summary"], dict) else None}
                     for r in c.execute("SELECT id, status, trigger, created_at, finished_at, summary FROM checks WHERE app_id = %s "
                                        "ORDER BY created_at DESC LIMIT 50", (a["id"],)).fetchall()]
    out["diff"] = diff(c, a["id"])
    out["findings"] = taxonomy.app_findings(c, a["id"])
    return out


@router.patch("/apps/{aid}")
def patch_app(aid: str, body: AppPatch, user=Depends(current_user), c=Depends(db)):
    a = app_for(c, user, aid, "manage")
    changed = {}
    if "client_label" in body.model_fields_set:
        label = clean_text(body.client_label) or None
        c.execute("UPDATE apps SET client_label = %s WHERE id = %s", (label, a["id"]))
        if label != a["client_label"]:
            changed["client_label"] = {"from": a["client_label"], "to": label}
    if body.schedule and body.schedule != a["schedule"]:
        allow_schedule(workspace_of(c, a), body.schedule)
        c.execute("UPDATE apps SET schedule = %s WHERE id = %s", (body.schedule, a["id"]))
        c.execute(f"UPDATE apps SET next_check_at = CASE WHEN verified_at IS NULL THEN NULL ELSE {NEXT_AT} END WHERE id = %s", (a["id"],))
        changed["schedule"] = {"from": a["schedule"], "to": body.schedule}
    if body.badge_public is not None:
        c.execute("UPDATE apps SET badge_public = %s WHERE id = %s", (body.badge_public, a["id"]))
        if body.badge_public != a["badge_public"]:
            changed["badge_public"] = {"from": a["badge_public"], "to": body.badge_public}
    if changed:
        audit.log(c, a["workspace_id"], "app.updated", user, target=app_target(a), detail=changed)
    return app_view(c, app_for(c, user, aid))


@router.delete("/apps/{aid}")
def delete_app(aid: str, user=Depends(current_user), c=Depends(db)):
    a = app_for(c, user, aid, "manage")
    c.execute("DELETE FROM apps WHERE id = %s", (a["id"],))
    audit.log(c, a["workspace_id"], "app.removed", user, target=app_target(a), detail={"repo": a["repo"]})
    return {"ok": True}


@router.post("/apps/{aid}/checks", status_code=201)
def run_app_check(aid: str, user=Depends(current_user), c=Depends(db)):
    return run_now(c, app_for(c, user, aid, "run"), "manual", user["email"], user)


# ---- public ------------------------------------------------------------------------------------------------------

def public_state(c, a):
    """(state, last finished check time, freshness). A stale result is reported as 'stale', never as its old status."""
    r = c.execute("SELECT status, finished_at FROM checks WHERE app_id = %s AND status IN ('done', 'no_leaks', 'needs_review') "
                  "ORDER BY finished_at DESC LIMIT 1", (a["id"],)).fetchone()
    fresh = freshness(a["schedule"], r["finished_at"] if r else None)
    if not r:
        return "not_checked_yet", None, fresh
    if fresh["stale"]:
        return "stale", r["finished_at"], fresh
    return ("no_known_leaks" if r["status"] == "no_leaks" else "fix_in_progress"), r["finished_at"], fresh


BADGES = {"no_known_leaks": ("no known leaks", "#2ea44f"), "fix_in_progress": ("fix in progress", "#dfb317"),
          "not_checked_yet": ("not checked yet", "#9f9f9f"), "private": ("private", "#9f9f9f"),
          "stale": ("last checked {n} days ago", "#9f9f9f")}


def svg_badge(label, message, color):
    label, message = html.escape(label), html.escape(message)
    lw, mw = int(len(label) * 6.6 + 12), int(len(message) * 6.6 + 12)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{lw + mw}" height="20" role="img" aria-label="{label}: {message}">'
            f'<title>{label}: {message}</title><linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" '
            f'stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient><clipPath id="r"><rect width="{lw + mw}" '
            f'height="20" rx="3" fill="#fff"/></clipPath><g clip-path="url(#r)"><rect width="{lw}" height="20" fill="#1c1917"/>'
            f'<rect x="{lw}" width="{mw}" height="20" fill="{color}"/><rect width="{lw + mw}" height="20" fill="url(#s)"/></g>'
            f'<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
            f'<text x="{lw / 2:.1f}" y="14">{label}</text><text x="{lw + mw / 2:.1f}" y="14">{message}</text></g></svg>')


def public_app(c, aid):
    try:
        aid = uuid.UUID(aid)
    except ValueError:
        return None
    return c.execute("SELECT id, repo, schedule FROM apps WHERE id = %s AND badge_public AND verified_at IS NOT NULL", (aid,)).fetchone()


@router.get("/badge/{aid}.svg")
def badge(aid: str, c=Depends(db)):
    a = public_app(c, aid)
    state, at, fresh = public_state(c, a) if a else ("private", None, None)
    message, color = BADGES[state]
    if state == "stale":
        n = fresh["days_since_check"]
        message = message.format(n=n)  # stale means at least 14 days, so always "days"
    elif at:
        message += f" · {at.day} {at:%b %Y}"
    return Response(svg_badge("PatchLabs", message, color), media_type="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=3600"})


@router.get("/public/apps/{aid}")
def public_status(aid: str, c=Depends(db)):
    a = public_app(c, aid)
    if not a:
        raise HTTPException(404, "This app's status isn't public.")
    state, at, fresh = public_state(c, a)
    return {"repo": a["repo"], "status": state, "last_checked": at, **fresh, "live": posture.public_live(c, str(a["id"]))}


@router.get("/stats")
def stats(c=Depends(db)):
    return c.execute(
        "SELECT (SELECT count(*) FROM checks WHERE status IN ('done', 'no_leaks', 'needs_review')) AS checks_completed, "
        "(SELECT count(*) FROM apps WHERE verified_at IS NOT NULL) AS apps_monitored, "
        "(SELECT coalesce(sum(jsonb_array_length(summary->'tables_leaking')), 0) FROM checks "
        " WHERE status IN ('done', 'needs_review') AND jsonb_typeof(summary->'tables_leaking') = 'array')::int AS leaks_found, "
        "(SELECT count(*) FROM checks WHERE status = 'done' AND summary->>'lab_proof_passed' = 'true') AS fixes_proven").fetchone()


# ---- CI ----------------------------------------------------------------------------------------------------------

@router.post("/v1/apps/{aid}/checks", status_code=201)
def v1_run(aid: str, key=Depends(api_key), c=Depends(db)):
    a = c.execute("SELECT * FROM apps WHERE id = %s", (as_uuid(aid, "App not found."),)).fetchone()
    if not a:
        raise HTTPException(404, "App not found.")
    if a["workspace_id"] != key["workspace_id"]:
        raise HTTPException(403, "This API key belongs to a different workspace.")
    return run_now(c, a, "api", key=key)


@router.get("/v1/checks/{cid}")
def v1_check(cid: str, key=Depends(api_key), c=Depends(db)):
    k = c.execute("SELECT k.*, a.workspace_id FROM checks k JOIN apps a ON a.id = k.app_id WHERE k.id = %s",
                  (as_uuid(cid, "Check not found."),)).fetchone()
    if not k:
        raise HTTPException(404, "Check not found.")
    if k["workspace_id"] != key["workspace_id"]:
        raise HTTPException(403, "This API key belongs to a different workspace.")
    summary = scrub({x: v for x, v in (k["summary"] or {}).items() if x != "run_dir"}) if isinstance(k["summary"], dict) else None
    return {"id": k["id"], "app_id": k["app_id"], "repo": k["repo"], "status": k["status"], "trigger": k["trigger"],
            "created_at": k["created_at"], "finished_at": k["finished_at"], "finished": k["status"] in FINISHED + ("failed",),
            "leaks_found": bool(leaking(k["summary"])), "tables_leaking": leaking(k["summary"]),
            "lab_proof_passed": (summary or {}).get("lab_proof_passed"),
            "summary": taxonomy.enrich_summary(c, summary, k) if summary else summary, "url": check_url(k["id"]),
            **check_extras(c, k)}
