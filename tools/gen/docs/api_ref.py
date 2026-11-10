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
    ("summary", "object", "When finished: <code>tables_leaking</code>, <code>readable_by_anyone</code>, <code>readable_by_signed_in</code>, <code>lab_proof_passed</code>, <code>break_risk</code>, <code>questions_for_owner</code>, <code>models</code>."),
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

group("decisions", "Decisions and receipts", "Decisions and answers need a session that belongs to the app’s workspace, and a finished check. Receipts are public by link. Guides: <a href=\"/docs/decisions\">decisions</a>, <a href=\"/docs/receipts\">receipts</a>.")
ep("POST", "/checks/{id}/decision", "Session · member", "Approve a fix, or reject tables as intentionally readable (remembered for the app as suppressions).",
   [("action", "approve | reject", "Required."), ("tables", "string[], optional", "Defaults to every table the check flagged; must be a subset of them."),
    ("reason", "string, optional", "Up to 2,000 characters.")],
   f"""curl -s -X POST {B}/checks/$CHECK_ID/decision {SESSION} {JSONH} \\
  -d '{{"action": "reject", "tables": ["shops"], "reason": "Public by design"}}'""",
   '201 Created\n{"decisions": [{"action": "reject", "tables": ["shops"], "reason": "Public by design", "by": "Priya", "at": "…"}]}',
   [("403", "not an app check, or not a member"), ("409", "check not finished"), ("422", "a named table wasn’t flagged")])
ep("POST", "/checks/{id}/answers", "Session · member", "Answer the report’s business questions. Answering a question again replaces the earlier answer.",
   [("answers", "array", "1 to 50 items of <code>{question, answer}</code>; each <code>question</code> must match one in <code>summary.questions_for_owner</code>.")],
   f"""curl -s -X POST {B}/checks/$CHECK_ID/answers {SESSION} {JSONH} \\
  -d '{{"answers": [{{"question": "Should sellers’ emails be public?", "answer": "No"}}]}}'""",
   '200 OK\n{"answers": [{"question": "Should sellers’ emails be public?", "answer": "No", "by": "Priya", "at": "…"}]}',
   [("403", "not an app check, or not a member"), ("409", "not finished, or the check has no questions"), ("422", "unknown question")])
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

group("workspaces", "Workspaces", "Every workspace endpoint needs you to be a member; some need the owner role. Guide: <a href=\"/docs/teams\">teams</a>.")
ep("GET", "/workspaces/{wid}", "Session · member", "Plan, limits, usage, webhook, members and pending invites.", None,
   f"curl -s {B}/workspaces/$WORKSPACE_ID {SESSION}",
   """200 OK
{"id": "…", "name": "Acme", "plan": "maker", "role": "owner", "created_at": "…",
 "limits": {"apps": 3, "runs_per_month": 30, "seats": 2, "schedules": ["off", "weekly", "monthly"]},
 "usage": {"apps": 2, "runs_this_month": 5, "members": 2},
 "webhook_url": "https://hooks.slack.com/services/…",
 "members": [{"user_id": "…", "email": "…", "name": "…", "role": "owner", "joined_at": "…"}],
 "invites": [{"id": "…", "email": "…", "role": "member", "created_at": "…", "expires_at": "…"}]}""")
ep("PATCH", "/workspaces/{wid}", "Session · owner", "Rename the workspace or set its webhook.",
   [("name", "string, optional", "1 to 100 characters."), ("webhook_url", "string | null, optional", "https only, on a public host; <code>null</code> or empty removes it.")],
   f"""curl -s -X PATCH {B}/workspaces/$WORKSPACE_ID {SESSION} {JSONH} \\
  -d '{{"webhook_url": "https://hooks.slack.com/services/T000/B000/XXXX"}}'""", "200 OK\n{…the workspace…}",
   [("403", "not an owner"), ("422", "webhook URL not https, unresolvable, or private")])
ep("POST", "/workspaces/{wid}/webhook/test", "Session · member", "Send a <code>test</code> event to the webhook and report what it answered.", None,
   f"curl -s -X POST {B}/workspaces/$WORKSPACE_ID/webhook/test {SESSION}",
   '200 OK\n{"ok": true, "status_code": 200}\n# or {"ok": false, "status_code": null, "detail": "…why it failed…"}', [("409", "no webhook URL set")])
ep("POST", "/workspaces/{wid}/invites", "Session · owner", "Email an invite link (valid 14 days). Re-inviting an address replaces its pending invite.",
   [("email", "string", "Required."), ("role", "member | owner", "Defaults to <code>member</code>.")],
   f"""curl -s -X POST {B}/workspaces/$WORKSPACE_ID/invites {SESSION} {JSONH} \\
  -d '{{"email": "dev@client.com", "role": "member"}}'""",
   '201 Created\n{"id": "…", "email": "dev@client.com", "role": "member", "created_at": "…", "expires_at": "…"}',
   [("403", "not an owner, or no free seats (pending invites count)"), ("409", "already a member")])
ep("DELETE", "/workspaces/{wid}/invites/{iid}", "Session · owner", "Cancel a pending invite.", None,
   f"curl -s -X DELETE {B}/workspaces/$WORKSPACE_ID/invites/$INVITE_ID {SESSION}", '200 OK\n{"ok": true}', [("404", "no such invite")])
ep("PATCH", "/workspaces/{wid}/members/{uid}", "Session · owner", "Change a member’s role.", [("role", "member | owner", "Required.")],
   f"""curl -s -X PATCH {B}/workspaces/$WORKSPACE_ID/members/$USER_ID {SESSION} {JSONH} -d '{{"role": "owner"}}'""",
   "200 OK\n{…the workspace…}", [("409", "would leave the workspace with no owner")])
ep("DELETE", "/workspaces/{wid}/members/{uid}", "Session", "Remove a member. Owners can remove anyone; members can remove themselves.", None,
   f"curl -s -X DELETE {B}/workspaces/$WORKSPACE_ID/members/$USER_ID {SESSION}", '200 OK\n{"ok": true}',
   [("403", "a member removing someone else"), ("409", "the last owner")])
ep("GET", "/workspaces/{wid}/api-keys", "Session · member", "List API keys (never the keys themselves).", None,
   f"curl -s {B}/workspaces/$WORKSPACE_ID/api-keys {SESSION}",
   '200 OK\n{"api_keys": [{"id": "…", "name": "GitHub Actions", "prefix": "pl_live_Xy3k", "created_at": "…", "last_used_at": "…"}]}')
ep("POST", "/workspaces/{wid}/api-keys", "Session · member", "Create an API key. The full key is in this response <strong>only</strong>; we store a hash.",
   [("name", "string", "1 to 100 characters, so you know where it’s used.")],
   f"""curl -s -X POST {B}/workspaces/$WORKSPACE_ID/api-keys {SESSION} {JSONH} -d '{{"name": "GitHub Actions"}}'""",
   '201 Created\n{"id": "…", "name": "GitHub Actions", "prefix": "pl_live_Xy3k", "created_at": "…",\n "last_used_at": null, "key": "pl_live_Xy3k…32 characters…"}')
ep("DELETE", "/workspaces/{wid}/api-keys/{kid}", "Session · member", "Revoke an API key. It stops working immediately.", None,
   f"curl -s -X DELETE {B}/workspaces/$WORKSPACE_ID/api-keys/$KEY_ID {SESSION}", '200 OK\n{"ok": true}', [("404", "no such key")])
ep("POST", "/workspaces/{wid}/upgrade-request", "Session · member", "Ask to move to a paid plan. We reply by email within a day and set the plan (card payments aren’t live yet).",
   [("plan", "maker | agency | enterprise", "Required."), ("note", "string, optional", "Anything we should know, up to 2,000 characters.")],
   f"""curl -s -X POST {B}/workspaces/$WORKSPACE_ID/upgrade-request {SESSION} {JSONH} -d '{{"plan": "agency"}}'""",
   '201 Created\n{"id": "…", "plan": "agency", "note": null, "created_at": "…", "detail": "Thanks. We\'ll reply within a day."}')

group("apps", "Apps", "An app is a monitored repo inside a workspace. Guide: <a href=\"/docs/monitoring\">monitoring</a>.")
ep("GET", "/workspaces/{wid}/apps", "Session · member", "Every app in the workspace with its latest finished check and any open one.", None,
   f"curl -s {B}/workspaces/$WORKSPACE_ID/apps {SESSION}",
   """200 OK
{"apps": [{"id": "…", "workspace_id": "…", "repo": "you/your-app", "branch": "main",
           "client_label": "Acme", "schedule": "weekly", "next_check_at": "…",
           "badge_public": false, "created_at": "…", "verified_at": "…", "verified": true,
           "last_check": {"id": "…", "status": "no_leaks", "finished_at": "…", "tables_leaking": []},
           "open_check_id": null, "suppressed_tables": []}]}""")
ep("POST", "/workspaces/{wid}/apps", "Session · member", "Add an app. It starts unverified and returns its verification details.",
   [("repo", "string", "Public GitHub repo."), ("client_label", "string, optional", "Up to 100 characters."),
    ("schedule", "off | weekly | monthly, optional", "Defaults to <code>monthly</code>; must be allowed by the plan.")],
   f"""curl -s -X POST {B}/workspaces/$WORKSPACE_ID/apps {SESSION} {JSONH} \\
  -d '{{"repo": "you/your-app", "client_label": "Acme"}}'""",
   '201 Created\n{"id": "…", "repo": "you/your-app", "verified": false, …,\n "verify": {"file": "patchlabs-verify.txt", "code": "patchlabs-…", "add_url": "https://github.com/…"}}',
   [("403", "plan’s app limit, or schedule not on the plan"), ("409", "repo already in this workspace"), ("422", "repo not found")])
ep("POST", "/apps/{aid}/verify", "Session · member", "Check the verification file. On success the app is verified for good and its first check is queued.", None,
   f"curl -s -X POST {B}/apps/$APP_ID/verify {SESSION}", '200 OK\n{"verified": true, "check_id": "…"}',
   [("409", "file or code not found yet"), ("503", "GitHub unreachable")])
ep("GET", "/apps/{aid}", "Session · member", "The app, its latest 50 checks and the diff between its last two finished checks. Model costs are never included.", None,
   f"curl -s {B}/apps/$APP_ID {SESSION}",
   """200 OK
{"id": "…", "repo": "you/your-app", …,
 "checks": [{"id": "…", "status": "done", "trigger": "scheduled", "created_at": "…",
             "finished_at": "…", "tables_leaking": ["orders"], "lab_proof_passed": true}],
 "diff": {"new_leaks": ["orders"], "fixed": [], "still_leaking": [], "suppressed": [],
          "to_check_id": "…", "from_check_id": "…"}}""")
ep("PATCH", "/apps/{aid}", "Session · member", "Change the label, schedule or badge. Changing the schedule restarts its clock.",
   [("client_label", "string | null, optional", ""), ("schedule", "off | weekly | monthly, optional", ""), ("badge_public", "boolean, optional", "")],
   f"""curl -s -X PATCH {B}/apps/$APP_ID {SESSION} {JSONH} -d '{{"schedule": "weekly", "badge_public": true}}'""",
   "200 OK\n{…the app…}", [("403", "schedule not on the plan")])
ep("DELETE", "/apps/{aid}", "Session · member", "Delete the app <strong>with all its checks, reports and receipts</strong>.", None,
   f"curl -s -X DELETE {B}/apps/$APP_ID {SESSION}", '200 OK\n{"ok": true}')
ep("POST", "/apps/{aid}/checks", "Session · member", "Run a check now (trigger <code>manual</code>). Verified apps skip verification.", None,
   f"curl -s -X POST {B}/apps/$APP_ID/checks {SESSION}",
   '201 Created\n{"check_id": "…", "status": "queued", "url": "https://patchlabs.dev/check?id=…"}',
   [("409", "not verified, or a check is already queued or running"), ("429", "monthly run limit reached")])

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
ep("GET", "/badge/{aid}.svg", "No auth", "The app’s badge as SVG. Shows the status only when the app’s badge is public, otherwise “private”. Cached for an hour. Guide: <a href=\"/docs/badge\">badge</a>.", None,
   f"curl -s {B}/badge/$APP_ID.svg -o badge.svg")
ep("GET", "/public/apps/{aid}", "No auth", "Repo, status and last-checked date, only when the badge is public.", None,
   f"curl -s {B}/public/apps/$APP_ID",
   '200 OK\n{"repo": "you/your-app", "status": "no_known_leaks", "last_checked": "…"}\n# status: no_known_leaks | fix_in_progress | not_checked_yet',
   [("404", "badge not public")])
ep("GET", "/stats", "No auth", "Live totals across PatchLabs.", None, f"curl -s {B}/stats",
   '200 OK\n{"checks_completed": <int>, "apps_monitored": <int>, "leaks_found": <int>, "fixes_proven": <int>}')
ep("GET", "/health", "No auth", "Whether the API and database are up, when the lab worker last checked in, and how many checks are queued.", None,
   f"curl -s {B}/health", '200 OK\n{"ok": true, "db": "ok", "worker_last_seen": "…", "queued": <int>}', extra="TRY:GET:/health")

group("tools", "Free RLS check", "Static analysis of a repo’s migrations, no sign-up. The web version is at <a href=\"/tools/rls-check\">/tools/rls-check</a>.")
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
