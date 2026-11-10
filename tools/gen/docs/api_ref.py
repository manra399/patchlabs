#!/usr/bin/env python3
"""Writes tools/gen/docs/src/api.html (then run build.py): the REST reference, generated from the endpoint list below so every block has the same shape."""
import html, os, re

HERE = os.path.dirname(os.path.abspath(__file__))
B = "https://api.patchlabs.dev"
SESSION = '-H "Authorization: Bearer $PL_SESSION"'
JSONH = "-H 'Content-Type: application/json'"


def E(s):
    return html.escape(s, quote=False)


def code_hl(s):
    """escape, then dim # comments"""
    out = []
    for line in E(s).split("\n"):
        out.append(f'<span class="c">{line}</span>' if line.lstrip().startswith("# ") else line)
    return "\n".join(out)


GROUPS = []


def group(gid, title, intro=""):
    GROUPS.append({"id": gid, "title": title, "intro": intro, "eps": []})


def ep(method, path, auth, desc, fields=None, curl=None, resp=None, codes=None, extra=""):
    slug = method.lower() + "-" + re.sub(r"[^a-z0-9]+", "-", path.lower()).strip("-")
    GROUPS[-1]["eps"].append(dict(method=method, path=path, auth=auth, desc=desc, fields=fields or [], curl=curl, resp=resp,
                                  codes=codes or [], extra=extra, id=slug))


# ---------------------------------------------------------------------------------------------------------------
group("checks", "Free checks", "A free check is a one-off full check of a public repo. It needs no account, only an email and the one-file verification.")
ep("POST", "/checks", "No auth", "Request a full check. We email the requester a link to the check page with the verification step.",
   [("repo", "string", "Public GitHub repo: <code>owner/name</code> or a github.com URL."), ("email", "string", "Where the report link goes.")],
   f"""curl -s -X POST {B}/checks {JSONH} \\
  -d '{{"repo": "you/your-app", "email": "you@company.com"}}'""",
   """201 Created
{"id": "7c1e2f0a-…", "status": "awaiting_verification", "repo": "you/your-app",
 "link": "https://patchlabs.dev/check.html?id=7c1e2f0a-…"}""",
   [("422", "not a GitHub repo, repo not found or not public, or a bad email"), ("429", "3 checks already open for this email, or 10 requests from this network today")])
ep("GET", "/checks/{id}", "No auth · by link", "The check and, once it has finished, its report. Fields appear as the check moves along.",
   [("verify", "object", "While <code>awaiting_verification</code>: <code>{file, code, add_url}</code>."),
    ("summary", "object", "When finished: <code>tables_leaking</code>, <code>readable_by_anyone</code>, <code>readable_by_signed_in</code>, <code>lab_proof_passed</code>, <code>break_risk</code>, <code>questions_for_owner</code>, <code>models</code>, and <code>findings</code>: each finding carries <code>cwe</code> (list), <code>owasp</code> and <code>owasp_name</code> (OWASP Top 10 2021); on an app’s check also <code>first_seen</code>, <code>days_open</code>, <code>fixed_at</code> (null while open), <code>fixed_in_check_id</code> and <code>regressed</code>."),
    ("report_md, fix_sql", "string", "When finished: the report as Markdown and the fix migration (<code>null</code> when there are no leaks)."),
    ("error", "string", "When <code>failed</code>: a plain-English explanation."),
    ("events", "array", "Timeline: <code>[{at, kind}]</code>."),
    ("decisions, answers", "array", "Always present; see <a href=\"/docs/decisions\">decisions</a>.")],
   f"curl -s {B}/checks/$CHECK_ID",
   """200 OK
{"id": "7c1e…", "repo": "you/your-app", "status": "done",
 "created_at": "…", "verified_at": "…", "finished_at": "…",
 "summary": {"tables_leaking": ["profiles"], "readable_by_anyone": ["profiles"],
             "readable_by_signed_in": [], "lab_proof_passed": true, "break_risk": "low",
             "questions_for_owner": [], "models": [{"model": "haiku", "passed": true, "seconds": 36}]},
 "report_md": "# Leak check: you/your-app …", "fix_sql": "DROP POLICY …",
 "events": [{"at": "…", "kind": "requested"}, {"at": "…", "kind": "verified"}, …],
 "decisions": [], "answers": []}""",
   [("404", "no check with that ID")])
ep("POST", "/checks/{id}/verify", "No auth · by link", "Look for <code>patchlabs-verify.txt</code> with the check’s code on the default branch. On success the check joins the queue. Calling it again after that just returns the current status.",
   None, f"curl -s -X POST {B}/checks/$CHECK_ID/verify", '200 OK\n{"status": "queued"}',
   [("409", "file or code not found on the default branch yet"), ("503", "GitHub unreachable; try again")])

group("decisions", "Decisions and receipts", "Decisions and answers need an owner, admin or approver session in the app’s workspace, and a finished check. Receipts are public by link. Guides: <a href=\"/docs/decisions\">decisions</a>, <a href=\"/docs/receipts\">receipts</a>.")
ep("POST", "/checks/{id}/decision", "Session · approver+", "Approve a fix, or reject tables as intentionally readable (remembered for the app as suppressions).",
   [("action", "approve | reject", "Required."), ("tables", "string[], optional", "Defaults to every table the check flagged; must be a subset of them."),
    ("reason", "string, optional", "Up to 2,000 characters.")],
   f"""curl -s -X POST {B}/checks/$CHECK_ID/decision {SESSION} {JSONH} \\
  -d '{{"action": "reject", "tables": ["shops"], "reason": "Public by design"}}'""",
   '201 Created\n{"decisions": [{"action": "reject", "tables": ["shops"], "reason": "Public by design", "by": "Priya", "at": "…"}]}',
   [("403", "not an app check, not a member, or a member/viewer/client role"), ("409", "check not finished"), ("422", "a named table wasn’t flagged")])
ep("POST", "/checks/{id}/answers", "Session · approver+", "Answer the report’s business questions. Answering a question again replaces the earlier answer.",
   [("answers", "array", "1 to 50 items of <code>{question, answer}</code>; each <code>question</code> must match one in <code>summary.questions_for_owner</code>.")],
   f"""curl -s -X POST {B}/checks/$CHECK_ID/answers {SESSION} {JSONH} \\
  -d '{{"answers": [{{"question": "Should sellers’ emails be public?", "answer": "No"}}]}}'""",
   '200 OK\n{"answers": [{"question": "Should sellers’ emails be public?", "answer": "No", "by": "Priya", "at": "…"}]}',
   [("403", "not an app check, not a member, or a member/viewer/client role"), ("409", "not finished, or the check has no questions"), ("422", "unknown question")])
ep("GET", "/receipts/{id}", "No auth · by link", "The Ed25519-signed receipt for a finished check.",
   None, f"curl -s {B}/receipts/$CHECK_ID",
   """200 OK
{"receipt": {"check_id": "…", "repo": "…", "status": "done", "tables_leaking": ["profiles"],
             "lab_proof_passed": true, "fix_sha256": "…", "finished_at": "…",
             "decisions": [], "answers": []},
 "signature": "base64…", "key_id": "ed25519:…", "algorithm": "Ed25519"}""",
   [("404", "no check with that ID"), ("409", "check not finished")])
ep("GET", "/.well-known/patchlabs-receipt-key", "No auth", "The public key that signs receipts.",
   None, f"curl -s {B}/.well-known/patchlabs-receipt-key",
   '200 OK\n{"key_id": "ed25519:…", "algorithm": "Ed25519", "public_key": "base64 raw 32 bytes",\n "pem": "-----BEGIN PUBLIC KEY-----\\n…", "signed_bytes": "JSON of `receipt` with sorted keys and separators (\',\', \':\')"}',
   extra='TRY:GET:/.well-known/patchlabs-receipt-key')

group("auth", "Sign-in", "Sign-in is by magic link. The site handles these calls for you; they are listed for completeness.")
ep("POST", "/auth/start", "No auth", "Email a sign-in link to <code>{site}/app/login?token=…</code>. Always answers 202, whether or not the address has an account. The link works once and expires in 20 minutes.",
   [("email", "string", "Required."), ("next", "string, optional", "A path on patchlabs.dev to return to after sign-in, such as <code>/app/</code>.")],
   f"""curl -s -X POST {B}/auth/start {JSONH} -d '{{"email": "you@company.com"}}'""",
   '202 Accepted\n{"ok": true, "detail": "If that address can sign in, a link is on its way. It expires in 20 minutes."}')
ep("POST", "/auth/finish", "No auth", "Exchange the link’s token for a session (valid 30 days). Creates the user and a personal workspace on first sign-in, and links earlier free checks with the same email.",
   [("token", "string", "From the sign-in link."), ("invite", "string, optional", "An invite token to accept at the same time.")],
   f"""curl -s -X POST {B}/auth/finish {JSONH} -d '{{"token": "…"}}'""",
   '200 OK\n{"session": "…", "user": {"id": "…", "email": "you@company.com", "name": null, "created_at": "…"},\n "next": "/app/", "invite": null}',
   [("400", "link expired or already used")])
ep("POST", "/auth/logout", "Session", "Revoke the session in the Authorization header.", None,
   f"curl -s -X POST {B}/auth/logout {SESSION}", '200 OK\n{"ok": true}')
ep("POST", "/invites/accept", "Session", "Accept a workspace invite while signed in. The invite must have been sent to your email address.",
   [("invite", "string", "The token from the invite link.")],
   f"""curl -s -X POST {B}/invites/accept {SESSION} {JSONH} -d '{{"invite": "…"}}'""",
   '200 OK\n{"accepted": true, "workspace_id": "…", "workspace_name": "Acme"}',
   [("409", "expired, used, sent to another address, or no free seats")])

group("me", "Your account")
ep("GET", "/me", "Session", "You and the workspaces you belong to. Use a workspace <code>id</code> from here in the workspace and app endpoints.", None,
   f"curl -s {B}/me {SESSION}",
   '200 OK\n{"user": {"id": "…", "email": "you@company.com", "name": "Priya", "created_at": "…"},\n "workspaces": [{"id": "…", "name": "you\'s workspace", "role": "owner", "plan": "free"}]}')
ep("PATCH", "/me", "Session", "Set your display name (shown on decisions and invites).", [("name", "string", "Up to 100 characters; empty clears it.")],
   f"""curl -s -X PATCH {B}/me {SESSION} {JSONH} -d '{{"name": "Priya"}}'""", "200 OK\n{\"user\": {…}, \"workspaces\": […]}")
ep("GET", "/me/checks", "Session", "Free checks linked to you (by account or email), newest first.", None,
   f"curl -s {B}/me/checks {SESSION}", '200 OK\n{"checks": [{"id": "…", "repo": "you/your-app", "status": "done", "created_at": "…"}]}')
ep("GET", "/me/export", "Session", "Everything we hold about you, as a JSON file download (<code>patchlabs-export.json</code>).", None,
   f"curl -s -OJ {B}/me/export {SESSION}")
ep("DELETE", "/me", "Session", "Delete your account. Workspaces you own alone are deleted with their apps, checks and keys; shared ones pass to their longest-standing member.", None,
   f"curl -s -X DELETE {B}/me {SESSION}", '200 OK\n{"ok": true, "deleted_workspaces": 1}')

group("workspaces", "Workspaces", "Every workspace endpoint needs you to be a member, and your role must allow the call. Roles, most to least: <code>owner</code>, <code>admin</code> (everything but making or removing owners), <code>approver</code> (also approves or rejects fixes and answers the owner’s questions), <code>member</code> (views and runs checks), <code>viewer</code> (read-only) and <code>client</code> (read-only, only the apps shared with them, plus support tickets about those apps; clients never use a team seat). “approver+” means owner, admin or approver. Guide: <a href=\"/docs/teams\">teams</a>.")
ep("GET", "/workspaces/{wid}", "Session · any role", "Plan, limits, usage, webhook, members and pending invites. What you get depends on your role: the webhook, its secret and invites only for owners and admins; a client gets only the name, plan, their own membership and <code>permissions</code>.", None,
   f"curl -s {B}/workspaces/$WORKSPACE_ID {SESSION}",
   """200 OK
{"id": "…", "name": "Acme", "plan": "maker", "role": "owner", "created_at": "…",
 "limits": {"apps": 3, "runs_per_month": 30, "seats": 2, "schedules": ["off", "weekly", "monthly"]},
 "usage": {"apps": 2, "runs_this_month": 5, "members": 2},
 "webhook_url": "https://hooks.slack.com/services/…", "webhook_format": "auto", "webhook_kind": "slack",
 "permissions": ["decide", "manage", "owner", "run", "view", "view_team"],
 "members": [{"user_id": "…", "email": "…", "name": "…", "role": "owner", "joined_at": "…", "app_ids": null}],
 "invites": [{"id": "…", "email": "…", "role": "client", "app_ids": ["…"], "created_at": "…", "expires_at": "…"}]}""")
ep("PATCH", "/workspaces/{wid}", "Session · owner/admin", "Rename the workspace or set its webhook. Slack, Discord and Microsoft Teams webhook URLs get native chat messages; any other URL gets the signed JSON event.",
   [("name", "string, optional", "1 to 100 characters."), ("webhook_url", "string | null, optional", "https only, on a public host; <code>null</code> or empty removes it."),
    ("webhook_format", "auto | json | slack | discord | teams, optional", "<code>auto</code> (default) detects <code>hooks.slack.com</code>, <code>discord.com/api/webhooks</code>, <code>*.webhook.office.com</code> and Teams Workflows on <code>*.powerplatform.com</code>. Set <code>teams</code> for a Workflows URL on <code>*.logic.azure.com</code>.")],
   f"""curl -s -X PATCH {B}/workspaces/$WORKSPACE_ID {SESSION} {JSONH} \\
  -d '{{"webhook_url": "https://hooks.slack.com/services/T000/B000/XXXX"}}'""", "200 OK\n{…the workspace…}",
   [("403", "not an owner or admin"), ("422", "webhook URL not https, unresolvable, or private, or an unknown format")])
ep("POST", "/workspaces/{wid}/webhook/test", "Session · owner/admin", "Send a test to the webhook in its own format (a chat message for Slack, Discord and Teams, a <code>test</code> event otherwise) and report what it answered.", None,
   f"curl -s -X POST {B}/workspaces/$WORKSPACE_ID/webhook/test {SESSION}",
   '200 OK\n{"ok": true, "status_code": 200, "format": "slack"}\n# or {"ok": false, "status_code": null, "format": "json", "detail": "…why it failed…"}', [("409", "no webhook URL set")])
ep("POST", "/workspaces/{wid}/invites", "Session · owner/admin", "Email an invite link (valid 14 days). Re-inviting an address replaces its pending invite. Only owners can invite owners.",
   [("email", "string", "Required."), ("role", "owner | admin | approver | member | viewer | client", "Defaults to <code>member</code>."),
    ("app_ids", "string[], optional", "Clients only: the apps they will see. Every id must be an app in this workspace.")],
   f"""curl -s -X POST {B}/workspaces/$WORKSPACE_ID/invites {SESSION} {JSONH} \\
  -d '{{"email": "dev@client.com", "role": "member"}}'""",
   '201 Created\n{"id": "…", "email": "dev@client.com", "role": "member", "created_at": "…", "expires_at": "…"}',
   [("403", "not an owner or admin, an admin inviting an owner, or no free seats (pending invites count)"), ("409", "already a member"), ("422", "app_ids for a non-client role, or an app from elsewhere")])
ep("DELETE", "/workspaces/{wid}/invites/{iid}", "Session · owner/admin", "Cancel a pending invite.", None,
   f"curl -s -X DELETE {B}/workspaces/$WORKSPACE_ID/invites/$INVITE_ID {SESSION}", '200 OK\n{"ok": true}', [("404", "no such invite")])
ep("PATCH", "/workspaces/{wid}/members/{uid}", "Session · owner/admin", "Change a member’s role. Admins can’t change owners or make anyone an owner. Someone who can no longer run checks (viewer, client) loses their API keys.",
   [("role", "owner | admin | approver | member | viewer | client", "Required."), ("app_ids", "string[], optional", "With <code>role: client</code>: the apps they see.")],
   f"""curl -s -X PATCH {B}/workspaces/$WORKSPACE_ID/members/$USER_ID {SESSION} {JSONH} -d '{{"role": "approver"}}'""",
   "200 OK\n{…the workspace…}", [("403", "not an owner or admin, or an admin touching an owner"), ("409", "would leave the workspace with no owner")])
ep("PUT", "/workspaces/{wid}/members/{uid}/apps", "Session · owner/admin", "Set the apps a client sees (replaces the list).",
   [("app_ids", "string[]", "Apps in this workspace; empty means none.")],
   f"""curl -s -X PUT {B}/workspaces/$WORKSPACE_ID/members/$USER_ID/apps {SESSION} {JSONH} -d '{{"app_ids": ["…"]}}'""",
   "200 OK\n{…the workspace…}", [("409", "the member isn’t a client"), ("422", "an app from elsewhere")])
ep("DELETE", "/workspaces/{wid}/members/{uid}", "Session", "Remove a member. Owners can remove anyone, admins anyone but owners; everyone can remove themselves.", None,
   f"curl -s -X DELETE {B}/workspaces/$WORKSPACE_ID/members/$USER_ID {SESSION}", '200 OK\n{"ok": true}',
   [("403", "removing someone else without the right role"), ("409", "the last owner")])
ep("GET", "/workspaces/{wid}/api-keys", "Session · viewer+", "List API keys (never the keys themselves).", None,
   f"curl -s {B}/workspaces/$WORKSPACE_ID/api-keys {SESSION}",
   '200 OK\n{"api_keys": [{"id": "…", "name": "GitHub Actions", "prefix": "pl_live_Xy3k", "created_at": "…", "last_used_at": "…"}]}')
ep("POST", "/workspaces/{wid}/api-keys", "Session · member+", "Create an API key. The full key is in this response <strong>only</strong>; we store a hash.",
   [("name", "string", "1 to 100 characters, so you know where it’s used.")],
   f"""curl -s -X POST {B}/workspaces/$WORKSPACE_ID/api-keys {SESSION} {JSONH} -d '{{"name": "GitHub Actions"}}'""",
   '201 Created\n{"id": "…", "name": "GitHub Actions", "prefix": "pl_live_Xy3k", "created_at": "…",\n "last_used_at": null, "key": "pl_live_Xy3k…32 characters…"}')
ep("DELETE", "/workspaces/{wid}/api-keys/{kid}", "Session · member+", "Revoke an API key. It stops working immediately. Owners and admins revoke any key, others their own.", None,
   f"curl -s -X DELETE {B}/workspaces/$WORKSPACE_ID/api-keys/$KEY_ID {SESSION}", '200 OK\n{"ok": true}', [("403", "someone else’s key"), ("404", "no such key")])
ep("POST", "/workspaces/{wid}/upgrade-request", "Session · owner/admin", "Ask to move to a paid plan. We reply by email within a day and set the plan (card payments aren’t live yet).",
   [("plan", "maker | agency | enterprise", "Required."), ("note", "string, optional", "Anything we should know, up to 2,000 characters.")],
   f"""curl -s -X POST {B}/workspaces/$WORKSPACE_ID/upgrade-request {SESSION} {JSONH} -d '{{"plan": "agency"}}'""",
   '201 Created\n{"id": "…", "plan": "agency", "note": null, "created_at": "…", "detail": "Thanks. We\'ll reply within a day."}')

group("audit", "Audit log", "An append-only record of who did what in the workspace: sign-ins and sign-outs, invites, role changes, removals, apps, checks started, decisions, suppressions, API keys, webhooks, exports, tickets and plan changes. Owners and admins only. Secrets, tokens and webhook URLs are never recorded (only the webhook’s host). Emails show in full only for current members and pending invites; anyone else is masked (<code>b•••@example.com</code>), and “a former member” after deleting their account.")
ep("GET", "/workspaces/{wid}/audit", "Session · owner/admin", "Events, newest first. Page with <code>before</code> = the last page’s <code>next_before</code> (null on the last page).",
   [("action", "query, optional", "An action such as <code>member.role_changed</code>, or a family such as <code>member</code>."),
    ("actor", "query, optional", "A user id, or <code>api_key</code>, <code>admin</code> (PatchLabs admin) or <code>system</code> (scheduler)."),
    ("since, until", "query, optional", "Dates (<code>2026-11-10</code>, both inclusive) or ISO times."),
    ("limit, before", "query, optional", "Page size 1 to 200 (default 50); cursor.")],
   f"curl -s '{B}/workspaces/$WORKSPACE_ID/audit?action=member&limit=50' {SESSION}",
   """200 OK
{"events": [{"id": 812, "at": "…", "action": "member.role_changed",
             "actor": {"kind": "user", "id": "…", "label": "Priya", "email": "priya@agency.com"},
             "target": {"type": "member", "id": "…", "label": null, "email": "dev@client.com"},
             "detail": {"from": "member", "to": "approver"}}],
 "next_before": 811, "actions": ["auth.sign_in", "auth.sign_out", "member.invited", …]}""",
   [("403", "not an owner or admin"), ("422", "a date that can’t be read")])
ep("GET", "/workspaces/{wid}/audit/export", "Session · owner/admin", "The same filters as a CSV download (up to 10,000 rows). The export itself is recorded as <code>audit.exported</code>.", None,
   f"curl -s -OJ '{B}/workspaces/$WORKSPACE_ID/audit/export?since=2026-11-01' {SESSION}",
   '200 OK (text/csv)\nid,at,action,actor_kind,actor,actor_email,target_type,target_id,target,target_email,detail')

group("apps", "Apps", "An app is a monitored repo inside a workspace. Owners and admins add, change and delete apps; members and above run checks; everyone can view them, except that a client sees only the apps shared with them. Guide: <a href=\"/docs/monitoring\">monitoring</a>.")
ep("GET", "/workspaces/{wid}/apps", "Session · any role", "Every app in the workspace (a client: the apps shared with them) with its latest finished check, any open one, and whether the result is stale.", None,
   f"curl -s {B}/workspaces/$WORKSPACE_ID/apps {SESSION}",
   """200 OK
{"apps": [{"id": "…", "workspace_id": "…", "repo": "you/your-app", "branch": "main",
           "client_label": "Acme", "schedule": "weekly", "next_check_at": "…",
           "badge_public": false, "created_at": "…", "verified_at": "…", "verified": true,
           "last_check": {"id": "…", "status": "no_leaks", "finished_at": "…", "tables_leaking": []},
           "open_check_id": null, "suppressed_tables": [],
           "freshness": {"stale": false, "days_since_check": 3, "stale_after_days": 14}}]}""")
ep("POST", "/workspaces/{wid}/apps", "Session · owner/admin", "Add an app. It starts unverified and returns its verification details.",
   [("repo", "string", "Public GitHub repo."), ("client_label", "string, optional", "Up to 100 characters."),
    ("schedule", "off | weekly | monthly, optional", "Defaults to <code>monthly</code>; must be allowed by the plan.")],
   f"""curl -s -X POST {B}/workspaces/$WORKSPACE_ID/apps {SESSION} {JSONH} \\
  -d '{{"repo": "you/your-app", "client_label": "Acme"}}'""",
   '201 Created\n{"id": "…", "repo": "you/your-app", "verified": false, …,\n "verify": {"file": "patchlabs-verify.txt", "code": "patchlabs-…", "add_url": "https://github.com/…"}}',
   [("403", "not an owner or admin, plan’s app limit, or schedule not on the plan"), ("409", "repo already in this workspace"), ("422", "repo not found")])
ep("POST", "/apps/{aid}/verify", "Session · owner/admin", "Check the verification file. On success the app is verified for good and its first check is queued.", None,
   f"curl -s -X POST {B}/apps/$APP_ID/verify {SESSION}", '200 OK\n{"verified": true, "check_id": "…"}',
   [("409", "file or code not found yet"), ("503", "GitHub unreachable")])
ep("GET", "/apps/{aid}", "Session · any role", "The app, its latest 50 checks, its <code>live</code> posture (see <a href=\"#live\">Live posture</a>), the diff between its last two finished checks, and its findings: <code>open</code> (in the latest finished check, worst first) and recently <code>fixed</code>, each with CWE/OWASP tags, <code>first_seen</code>, <code>days_open</code> and, once fixed, <code>fixed_at</code>. A finding is matched across checks by its <code>id</code> and <code>object</code>. Model costs are never included.", None,
   f"curl -s {B}/apps/$APP_ID {SESSION}",
   """200 OK
{"id": "…", "repo": "you/your-app", …,
 "checks": [{"id": "…", "status": "done", "trigger": "scheduled", "created_at": "…",
             "finished_at": "…", "tables_leaking": ["orders"], "lab_proof_passed": true}],
 "diff": {"new_leaks": ["orders"], "fixed": [], "still_leaking": [], "suppressed": [],
          "to_check_id": "…", "from_check_id": "…"},
 "findings": {"open": [{"id": "PL-001", "object": "public.orders", "severity": "critical", "title": "…",
                        "cwe": ["CWE-359", "CWE-863"], "owasp": "A01:2021", "owasp_name": "Broken Access Control",
                        "first_seen": "…", "first_check_id": "…", "days_open": 12, "fixed_at": null, "regressed": false}],
              "fixed": [{"id": "PL-023", "object": "package.json", "days_open": 7, "fixed_at": "…", "fixed_in_check_id": "…", …}]}}""")
ep("PATCH", "/apps/{aid}", "Session · owner/admin", "Change the label, schedule or badge. Changing the schedule restarts its clock.",
   [("client_label", "string | null, optional", ""), ("schedule", "off | weekly | monthly, optional", ""), ("badge_public", "boolean, optional", "")],
   f"""curl -s -X PATCH {B}/apps/$APP_ID {SESSION} {JSONH} -d '{{"schedule": "weekly", "badge_public": true}}'""",
   "200 OK\n{…the app…}", [("403", "schedule not on the plan")])
ep("DELETE", "/apps/{aid}", "Session · owner/admin", "Delete the app <strong>with all its checks, reports and receipts</strong>.", None,
   f"curl -s -X DELETE {B}/apps/$APP_ID {SESSION}", '200 OK\n{"ok": true}')
ep("POST", "/apps/{aid}/checks", "Session · member+", "Run a check now (trigger <code>manual</code>). Verified apps skip verification.", None,
   f"curl -s -X POST {B}/apps/$APP_ID/checks {SESSION}",
   '201 Created\n{"check_id": "…", "status": "queued", "url": "https://patchlabs.dev/check?id=…"}',
   [("409", "not verified, or a check is already queued or running"), ("429", "monthly run limit reached")])

group("live", "Live posture", "Passive checks of the app’s live domain, once the team proves it controls it: one plain <code>http://</code> request (to see the redirect), one <code>https://</code> load of the home page (at most 5 redirects) and that load’s TLS handshake. Nothing else: no other paths, no forms, no API calls, never the database. <code>GET /apps/{aid}</code> carries <code>live</code> (below); <code>GET /workspaces/{wid}/apps</code> carries the same with <code>last</code> cut to <code>{grade, score, checked_at, counts}</code>. Product page: <a href=\"/product/live-posture\">Live posture</a>; finding IDs PL-027 to PL-036.")
ep("PUT", "/apps/{aid}/live", "Session · owner/admin", "Set or change the app’s domain. A new domain gets a new live code (<code>patchlabs-live-</code> plus 16 hex characters, separate from the repo code), starts unverified and drops the old domain’s history. Setting the same domain again changes nothing.",
   [("url", "string", "An <code>https://</code> address with a host name (not an IP address or a private name). Any path is dropped.")],
   f"""curl -s -X PUT {B}/apps/$APP_ID/live {SESSION} {JSONH} -d '{{"url": "https://app.example.com"}}'""",
   """200 OK
{"url": "https://app.example.com", "verified": false, "verified_at": null, "next_check_at": null,
 "verify": {"file": "patchlabs-verify.txt", "file_url": "https://app.example.com/patchlabs-verify.txt",
            "code": "patchlabs-live-3f9c2a17d04be6a1",
            "meta": "<meta name=\"patchlabs-verify\" content=\"patchlabs-live-3f9c2a17d04be6a1\">"},
 "last": null}
# url is null when no domain is set (then verify and last are null); verify is present only while unverified""",
   [("403", "not an owner or admin"), ("422", "a bad address, with a sentence saying why")])
ep("DELETE", "/apps/{aid}/live", "Session · owner/admin", "Remove the domain and its whole posture history. The site itself isn’t touched.", None,
   f"curl -s -X DELETE {B}/apps/$APP_ID/live {SESSION}", '200 OK\n{"ok": true}')
ep("POST", "/apps/{aid}/live/verify", "Session · owner/admin", "Look for the code: a file at <code>https://&lt;domain&gt;/patchlabs-verify.txt</code> whose whole content is the code, or <code>&lt;meta name=\"patchlabs-verify\" content=\"…\"&gt;</code> in the home page’s HTML. Redirects must stay on the same host (or its <code>www</code> twin). On success the first check runs at once; if that page load fails, the domain is still verified and <code>posture</code> is null with a <code>detail</code> sentence.", None,
   f"curl -s -X POST {B}/apps/$APP_ID/live/verify {SESSION}",
   '200 OK\n{"verified": true, "posture": {…posture result, trigger "verify"…}}',
   [("409", "no domain set, or the file and meta tag weren’t found (with a sentence)")])
ep("POST", "/apps/{aid}/live/checks", "Session · member+", "Re-check now (trigger <code>manual</code>). Scheduled re-checks run daily while the app’s schedule isn’t <code>off</code>. An email and the workspace webhook (<code>event: \"posture.changed\"</code>) go out when the grade drops or a finding appears.", None,
   f"curl -s -X POST {B}/apps/$APP_ID/live/checks {SESSION}",
   """201 Created
{"id": "…", "url": "https://app.example.com", "final_url": "https://app.example.com/",
 "grade": "C", "score": 65, "checked_at": "…", "trigger": "manual",
 "counts": {"critical": 0, "high": 0, "medium": 2, "low": 1, "info": 0},
 "findings": [{"id": "PL-030", "line": "live", "severity": "medium", "title": "No Content-Security-Policy",
               "object": "https://app.example.com", "evidence": "The page sends no Content-Security-Policy header or meta tag.",
               "fix": "Send a Content-Security-Policy that lists where scripts may load from (start with default-src 'self').",
               "cwe": ["CWE-693"], "owasp": "A05:2021", "owasp_name": "Security Misconfiguration"}],
 "passed": [{"id": "PL-027", "title": "HTTPS is forced"}, …],
 "facts": {"status": 200, "redirects": ["https://app.example.com/"], "https_redirect": true, "https_preloaded_tld": false,
           "tls": {"version": "TLSv1.3", "issuer": "Let's Encrypt", "expires": "2027-01-05", "days_left": 56},
           "headers": {"strict-transport-security": "max-age=63072000", "content-security-policy": null, …},
           "cookies": [{"name": "sb-session", "secure": true, "httponly": true, "samesite": "Lax"}],
           "server": "cloudflare"}}""",
   [("409", "domain not verified"), ("429", "checked in the last 10 minutes"), ("502", "the page couldn’t be loaded")],
   extra="GRADE")
ep("GET", "/apps/{aid}/live/checks", "Session · any role", "The domain’s posture history, newest first, at most 30.", None,
   f"curl -s {B}/apps/$APP_ID/live/checks {SESSION}",
   """200 OK
{"checks": [{"id": "…", "grade": "C", "score": 65, "counts": {"critical": 0, "high": 0, "medium": 2, "low": 1, "info": 0},
             "trigger": "scheduled", "checked_at": "…"}]}
# trigger: verify | scheduled | manual""")

group("support", "Support tickets", "Tickets belong to a workspace: its team sees them and our replies, nobody else does; viewers read but can’t write. A client sees and writes only tickets about apps shared with them, must give <code>app_id</code> (one of their apps) when raising one, and sees teammates’ emails masked. The app’s <a href=\"/app/support\">support page</a> uses these calls. We reply within a day.")
ep("GET", "/workspaces/{wid}/support/tickets", "Session · any role", "The workspace’s tickets, most recently updated first, with a count per status.",
   [("status", "query, optional", "<code>active</code> (open or waiting on you), <code>open</code>, <code>waiting_on_customer</code>, <code>resolved</code> or <code>closed</code>.")],
   f"curl -s {B}/workspaces/$WORKSPACE_ID/support/tickets {SESSION}",
   """200 OK
{"tickets": [{"id": "…", "number": 12, "subject": "Report says profiles leak", "category": "finding",
              "priority": "normal", "status": "waiting_on_customer", "app": {"id": "…", "repo": "you/your-app"},
              "created_by": "Olive", "message_count": 2, "last_from": "support", "updated_at": "…"}],
 "counts": {"open": 0, "waiting_on_customer": 1, "resolved": 3, "closed": 1}}""")
ep("POST", "/workspaces/{wid}/support/tickets", "Session · member+ or client", "Raise a ticket. We email you a confirmation; the founder is emailed too.",
   [("subject", "string", "Up to 200 characters."), ("category", "billing | finding | fix | account | bug | other", "Required."),
    ("message", "string", "Plain text, up to 10,000 characters. Line breaks are kept; it is never rendered as HTML."),
    ("priority", "normal | urgent", "Optional, default <code>normal</code>. Urgent: personal data is exposed right now, or PatchLabs is unusable."),
    ("app_id", "string, optional", "An app in the same workspace.")],
   f"""curl -s -X POST {B}/workspaces/$WORKSPACE_ID/support/tickets {SESSION} {JSONH} \\
  -d '{{"subject": "Report says profiles leak", "category": "finding", "message": "Is this real?"}}'""",
   """201 Created
{"id": "…", "number": 12, "status": "open", "priority": "normal", "subject": "Report says profiles leak", …,
 "messages": [{"author": "customer", "kind": "message", "by": "Olive", "body": "Is this real?", "created_at": "…"}]}""",
   [("422", "missing or too-long subject or message, unknown category or priority, or an app from another workspace"),
    ("429", "20 tickets from you today")])
ep("GET", "/support/tickets/{tid}", "Session · any role", "One ticket and its thread: your team’s messages, our replies (<code>author: support</code>, <code>by: PatchLabs support</code>) and status changes (<code>kind: status</code>, <code>body</code> is the new status).", None,
   f"curl -s {B}/support/tickets/$TICKET_ID {SESSION}", None, [("404", "no such ticket, or not in a workspace you belong to")])
ep("POST", "/support/tickets/{tid}/messages", "Session · member+ or client", "Reply. The ticket goes back to <code>open</code>, even if it was resolved or closed, and we’re emailed.",
   [("body", "string", "Plain text, up to 10,000 characters.")],
   f"""curl -s -X POST {B}/support/tickets/$TICKET_ID/messages {SESSION} {JSONH} -d '{{"body": "Applied the fix, thanks."}}'""",
   '201 Created\n{"id": "…", "status": "open", "messages": […]}', [("429", "200 replies from you today")])
ep("POST", "/support/tickets/{tid}/close", "Session · member+ or client", "Close the ticket. Replying later opens it again.", None,
   f"curl -s -X POST {B}/support/tickets/$TICKET_ID/close {SESSION}", '200 OK\n{"id": "…", "status": "closed", "closed_at": "…", "messages": […]}')

group("ci", "CI endpoints (API key)", "For scripts and CI. Send a workspace API key as <code>X-API-Key</code>; it works only for that workspace’s apps. The <a href=\"/docs/github-action\">GitHub Action</a> uses these two.")
ep("POST", "/v1/apps/{aid}/checks", "API key", "Run a check now (trigger <code>api</code>). Shares the workspace’s monthly run allowance.", None,
   f"""curl -s -X POST {B}/v1/apps/$APP_ID/checks -H "X-API-Key: $PATCHLABS_API_KEY\"""",
   '201 Created\n{"check_id": "…", "status": "queued", "url": "https://patchlabs.dev/check?id=…"}',
   [("401", "missing, invalid or revoked key"), ("403", "key from another workspace"), ("404", "no such app"), ("409", "not verified, or a check is open"), ("429", "monthly run limit reached")])
ep("GET", "/v1/checks/{cid}", "API key", "Status and summary of a check on one of the workspace’s apps. Poll until <code>finished</code> is true.",
   [("finished", "boolean", "True once the status is <code>done</code>, <code>no_leaks</code>, <code>needs_review</code> or <code>failed</code>."),
    ("leaks_found", "boolean", "True when <code>tables_leaking</code> isn’t empty."),
    ("lab_proof_passed", "boolean | null", "Whether the fix passed the lab proof.")],
   f"""curl -s {B}/v1/checks/$CHECK_ID -H "X-API-Key: $PATCHLABS_API_KEY\"""",
   """200 OK
{"id": "…", "app_id": "…", "repo": "you/your-app", "status": "done", "trigger": "api",
 "created_at": "…", "finished_at": "…", "finished": true, "leaks_found": true,
 "tables_leaking": ["profiles"], "lab_proof_passed": true,
 "summary": {…}, "url": "https://patchlabs.dev/check?id=…"}""",
   [("401", "bad key"), ("403", "key from another workspace"), ("404", "no such check")])

group("public", "Public", "No authentication, safe to call from anywhere.")
ep("GET", "/badge/{aid}.svg", "No auth", "The app’s badge as SVG. Shows the status only when the app’s badge is public, otherwise “private”. When the last finished check is older than twice the app’s schedule (14 days weekly, 60 monthly, 45 without a schedule) it shows a grey “last checked N days ago” instead of a status. Cached for an hour. Guide: <a href=\"/docs/badge\">badge</a>.", None,
   f"curl -s {B}/badge/$APP_ID.svg -o badge.svg")
ep("GET", "/badge/{aid}/live.svg", "No auth", "The app’s Live posture badge: “live posture · B · 10 Nov 2026”, the grade and the day of the last check. It reads “private” unless the app’s badge is public and its domain is verified. Cached for an hour.", None,
   f"curl -s {B}/badge/$APP_ID/live.svg -o live.svg")
ep("GET", "/public/apps/{aid}", "No auth", "Repo, status, last-checked date and freshness, only when the badge is public. A stale result is reported as <code>stale</code>, never as its old status. <code>live</code> is the latest posture grade when the domain is verified, otherwise null.", None,
   f"curl -s {B}/public/apps/$APP_ID",
   '200 OK\n{"repo": "you/your-app", "status": "no_known_leaks", "last_checked": "…",\n "stale": false, "days_since_check": 3, "stale_after_days": 60,\n "live": {"grade": "B", "checked_at": "…"}}\n# status: no_known_leaks | fix_in_progress | not_checked_yet | stale',
   [("404", "badge not public")])
ep("GET", "/taxonomy/findings", "No auth", "The CWE and OWASP Top 10 (2021) tags for every finding ID, with their names.", None,
   f"curl -s {B}/taxonomy/findings",
   '200 OK\n{"findings": {"PL-001": {"cwe": ["CWE-359", "CWE-863"], "owasp": "A01:2021", "owasp_name": "Broken Access Control"}, …},\n "cwe": {"CWE-359": "Exposure of Private Personal Information to an Unauthorized Actor", …},\n "owasp": {"A01:2021": "Broken Access Control", …}}',
   extra="TRY:GET:/taxonomy/findings")
ep("GET", "/stats", "No auth", "Live totals across PatchLabs.", None, f"curl -s {B}/stats",
   '200 OK\n{"checks_completed": <int>, "apps_monitored": <int>, "leaks_found": <int>, "fixes_proven": <int>}')
ep("GET", "/health", "No auth", "Whether the API and database are up, when the lab worker last checked in, and how many checks are queued.", None,
   f"curl -s {B}/health", '200 OK\n{"ok": true, "db": "ok", "worker_last_seen": "…", "queued": <int>}', extra="TRY:GET:/health")

group("tools", "Free tools", "No sign-up. The RLS check reads a repo’s migrations (web version: <a href=\"/tools/rls-check\">/tools/rls-check</a>); the headers check loads one public page (web version: <a href=\"/tools/headers-check\">/tools/headers-check</a>).")
ep("POST", "/tools/rls-check", "No auth", "Reads <code>supabase/migrations/*.sql</code> on the default branch, pinned to its head commit, in filename order (at most 60 files and 2 MB; <code>truncated</code> says when it stopped early). Only tables in the <code>public</code> schema are analysed. Results are cached for 10 minutes per repo and commit.",
   [("repo", "string", "Public GitHub repo.")],
   f"""curl -s -X POST {B}/tools/rls-check {JSONH} -d '{{"repo": "manra399/patchlabs-demo-app"}}'""",
   """200 OK
{"repo": "manra399/patchlabs-demo-app", "branch": "main", "commit": "…",
 "files_scanned": 1, "truncated": false, "cached": false,
 "tables": [{"name": "profiles", "rls_enabled": true, "policies": […],
             "personal_columns": ["email", "phone"], "file": "supabase/migrations/…", "line": 3}],
 "findings": [{"id": "PL-001", "title": "Anyone with the public key can read personal data",
               "table": "profiles", "file": "…", "line": 12, "severity": "critical", "snippet": "…"}],
 "limits": "static analysis only; the full check proves it in the lab"}""",
   [("422", "not a GitHub repo"), ("429", "20 requests an hour from this network (failed lookups count)"), ("503", "GitHub unreachable")],
   extra="TRY:POST:/tools/rls-check:{\"repo\": \"manra399/patchlabs-demo-app\"}|FINDINGS")
ep("POST", "/tools/headers-check", "No auth", "The Live posture check for any public address: one plain <code>http://</code> request, one <code>https://</code> load of the home page (at most 5 redirects) and its TLS handshake. Returns the posture result (as above, without <code>id</code> or <code>trigger</code>). Nothing is stored except the host name and a hashed network address for the hourly limit.",
   [("url", "string", "An <code>https://</code> or <code>http://</code> address with a public host name. Any path is dropped: the home page is what’s checked.")],
   f"""curl -s -X POST {B}/tools/headers-check {JSONH} -d '{{"url": "https://patchlabs.dev"}}'""",
   """200 OK
{"url": "https://patchlabs.dev", "final_url": "https://patchlabs.dev/", "grade": "B", "score": 75, "checked_at": "…",
 "counts": {"critical": 0, "high": 0, "medium": 1, "low": 2, "info": 1},
 "findings": [{"id": "PL-030", "severity": "medium", "title": "No Content-Security-Policy", …}, …],
 "passed": [{"id": "PL-027", "title": "HTTPS is forced"}, …], "facts": {…}}""",
   [("422", "a bad or private address, with a sentence"), ("429", "10 requests an hour from this network"), ("502", "the page couldn’t be loaded, with a sentence")],
   extra="TRY:POST:/tools/headers-check:{\"url\": \"https://patchlabs.dev\"}")

group("mcp", "MCP", "")
ep("POST", "/mcp", "No auth · API key for app tools", "A remote MCP server: JSON-RPC 2.0 over Streamable HTTP, stateless, plain JSON responses. Tools <code>rls_check</code>, <code>start_check</code>, <code>get_check</code>, and with <code>X-API-Key</code>, <code>list_apps</code> and <code>run_check</code>. <code>GET /mcp</code> answers 405. Full guide: <a href=\"/docs/mcp\">MCP server</a>.", None,
   f"""curl -s -X POST {B}/mcp {JSONH} -d '{{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}}'""")

FINDINGS = [("PL-001", "Anyone with the public key can read personal data", "A SELECT or ALL policy for <code>anon</code>/<code>public</code>, not scoped to the user, on a table with email, phone, address, date-of-birth or similar columns"),
            ("PL-002", "Any signed-in user can read all rows", "A policy that only checks the user is signed in"),
            ("PL-003", "Row level security is on but the table has no policies", "Nobody but the service role can read it: often an unfinished table"),
            ("PL-004", "UPDATE policy without WITH CHECK", "Users may be able to change a row into one they shouldn’t own"),
            ("PL-005", "Policy is always true", "<code>USING (true)</code> or <code>WITH CHECK (true)</code>"),
            ("PL-006", "SECURITY DEFINER function exposure", "No <code>search_path</code> set, or granted to <code>anon</code>/<code>public</code>"),
            ("PL-007", "Public storage bucket", "A bucket inserted or updated with <code>public = true</code>"),
            ("PL-008", "Row level security is not enabled", "Every role with table grants can read and write it")]


def try_panel(spec):
    parts = spec.split(":", 3)
    method, path = parts[1], parts[2]
    body = parts[3] if len(parts) > 3 else None
    tid = re.sub(r"[^a-z0-9]+", "-", path.lower()).strip("-")
    h = f'<div class="doc-tool" data-tool="try" data-method="{method}" data-path="{path}"><p class="lab">Try it</p>'
    h += f'<p class="mb-1">Send this request to the live API from your browser.</p>'
    if body:
        h += f'<div class="field needs-js"><label for="try-{tid}">Request body</label><textarea id="try-{tid}" name="body" class="input" rows="2" style="min-height:64px" spellcheck="false">{E(body)}</textarea></div>'
    h += f'<button class="btn secondary small needs-js" type="button" data-send>Send {method} {path}</button>'
    h += '<p class="nojs-note small muted mb-0">Needs JavaScript; use the curl example instead.</p><div class="out" aria-live="polite"></div></div>'
    return h


def render_ep(e):
    m = e["method"]
    cls = {"GET": "get", "POST": "post", "DELETE": "delete"}.get(m, "")
    h = [f'<section class="ep" aria-labelledby="{e["id"]}"><header><h3 id="{e["id"]}"><span class="method {cls}">{m}</span> <code>{E(e["path"])}</code></h3><span class="auth">{e["auth"]}</span></header><div class="body">']
    h.append(f'<p>{e["desc"]}</p>')
    if e["fields"]:
        label = "Body" if m in ("POST", "PATCH") else "Response fields"
        h.append(f'<p class="small muted mb-1">{label}</p><dl class="fields">')
        for n, t, dsc in e["fields"]:
            h.append(f'<dt>{E(n)} <i>{E(t)}</i></dt><dd>{dsc or "&nbsp;"}</dd>')
        h.append("</dl>")
    if e["curl"]:
        h.append(f'<div class="code"><div class="code-bar"><span class="name">Request</span><button class="copy" type="button" data-copy>Copy</button></div><pre><code>{code_hl(e["curl"])}</code></pre></div>')
    if e["resp"]:
        first, _, rest = e["resp"].partition("\n")
        h.append(f'<div class="code"><div class="code-bar"><span class="name">Response · {E(first)}</span></div><pre><code>{code_hl(rest)}</code></pre></div>')
    if e["codes"]:
        h.append('<p class="codes">' + "".join(f"<span><b>{c}</b> {E(t)}</span>" for c, t in e["codes"]) + "</p>")
    extra = e["extra"]
    if extra:
        for piece in extra.split("|"):
            if piece.startswith("TRY:"):
                h.append(try_panel(piece))
            elif piece == "GRADE":
                h.append('<p class="small muted mb-1">Grade: score = 100 − 30 per failed high check − 15 per medium − 5 per low (info is free; a check that fails on several cookies costs its points once), floor 0. A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, else F. An invalid or expired certificate is always F. On HSTS-preloaded top-level domains (such as <code>.app</code> and <code>.dev</code>) PL-027 and PL-029 pass by default.</p>')
            elif piece == "FINDINGS":
                h.append('<p class="small muted mb-1" id="finding-ids">Finding IDs, most severe first</p><div class="table-wrap"><table class="table compact"><thead><tr><th scope="col">ID</th><th scope="col">Title</th><th scope="col">What it matches</th></tr></thead><tbody>')
                h += [f'<tr><th scope="row"><code>{i}</code></th><td>{t}</td><td>{d}</td></tr>' for i, t, d in FINDINGS]
                h.append("</tbody></table></div>")
    h.append("</div></section>")
    return "\n".join(h)


PRE = open(os.path.join(HERE, "api-pre.html")).read()


def main():
    idx = ['<div class="table-wrap"><table class="table compact ep-index"><thead><tr><th scope="col">Method</th><th scope="col">Path</th><th scope="col">Auth</th></tr></thead><tbody>']
    body = []
    for g in GROUPS:
        idx.append(f'<tr><th scope="rowgroup" colspan="3"><a href="#{g["id"]}">{g["title"]}</a></th></tr>')
        body.append(f'<h2 id="{g["id"]}">{g["title"]}</h2>')
        if g["intro"]:
            body.append(f"<p>{g['intro']}</p>")
        for e in g["eps"]:
            cls = {"GET": "get", "POST": "post", "DELETE": "delete"}.get(e["method"], "")
            idx.append(f'<tr><td><span class="method {cls}">{e["method"]}</span></td><td><a href="#{e["id"]}"><code>{E(e["path"])}</code></a></td><td class="small muted">{e["auth"]}</td></tr>')
            body.append(render_ep(e))
    idx.append("</tbody></table></div>")
    out = PRE.replace("{{INDEX}}", "\n".join(idx)) + "\n" + "\n".join(body) + "\n"
    open(os.path.join(HERE, "src", "api.html"), "w").write(out)
    n = sum(len(g["eps"]) for g in GROUPS)
    print("api.html:", n, "endpoints")


main()
