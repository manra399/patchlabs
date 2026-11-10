"""python3 tools/gen/demo_workspace.py  →  writes site/static/demo/workspace.json: the fake demo workspace behind /demo.
Every GET the app makes maps to one key in "routes". Dates are relative to "anchor"; the page shifts them to now.
The first app's latest check starts from the real demo-app run (site/static/sample.json) and adds representative
findings for every finding ID the product ships (PL-001..011, 017..026; PL-012..016 are not shipping yet), all marked demo.
Live posture: demo-app-1 has a verified fake domain (demo-app.patchlabs-demo.example) with a daily history, demo-app-2 a domain
waiting for verification, demo-app-3 none."""
import ast, copy, datetime as dt, json, os, sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sample = json.load(open(os.path.join(ROOT, "site/static/sample.json")))
# the CWE / OWASP map lives in api/taxonomy.py: read its literal dicts rather than importing the API
_tax = {n.targets[0].id: ast.literal_eval(n.value) for n in ast.parse(open(os.path.join(ROOT, "api/taxonomy.py")).read()).body
        if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and n.targets[0].id in ("OWASP", "CWE", "TAGS")}
TAGS = {k: {"cwe": list(v[0]), "owasp": v[1], "owasp_name": _tax["OWASP"].get(v[1])} for k, v in _tax["TAGS"].items()}
ANCHOR = dt.datetime(2026, 11, 10, 9, 0, tzinfo=dt.timezone.utc)
iso = lambda d: d.isoformat().replace("+00:00", "Z")
ago = lambda **k: iso(ANCHOR - dt.timedelta(**k))
ahead = lambda **k: iso(ANCHOR + dt.timedelta(**k))
SEV = ["critical", "high", "medium", "low", "info"]
MIG = "supabase/migrations/20241014120000_init.sql"


def f(id, line, sev, title, obj, file, line_no, evidence, proven, proof, fix, fixed, advisory=None):
    d = {"id": id, "line": line, "severity": sev, "title": title, "object": obj, "file": file, "line_no": line_no,
         "evidence": evidence, "proven": proven, "proof": proof, "fix": fix, "fixed_in_lab": fixed, "demo": True, **TAGS.get(id, {})}
    if advisory:
        d["advisory"] = advisory
    return d


ALL = [
    # Lab: the first one is the real result of the demo-app run (sample.json)
    f("PL-001", "lab", "critical", "Anyone on the internet can read personal data", "public.profiles", MIG, 31,
      "policy \"Profiles are viewable by everyone\" FOR SELECT USING (true); columns: email, phone",
      True, "Anonymous visitor read 2 of 2 seeded rows (email, phone). After the fix: anon 0, stranger 0, owner 1.",
      "Replace the everyone-can-read policy with an owner-only SELECT (auth.uid() = user_id).", True),
    f("PL-002", "lab", "high", "Any signed-in user can read every row", "public.messages", MIG, 58,
      "policy \"Signed in users can read\" FOR SELECT TO authenticated USING (true); columns: sender_email, body",
      True, "Signed-in stranger read 3 messages between two other seeded users. After the fix: stranger 0, owner 2.",
      "Scope SELECT to the sender or the recipient: auth.uid() IN (sender_id, recipient_id).", True),
    f("PL-003", "lab", "low", "Row level security is on but no policies exist", "public.audit_log", MIG, 102,
      "ALTER TABLE public.audit_log ENABLE ROW LEVEL SECURITY; (no CREATE POLICY follows)",
      True, "Owner read 0 of their own 4 seeded rows: nobody but the service role can read this table.",
      "Add an owner-only SELECT policy if the app reads this table; otherwise leave it locked.", False),
    f("PL-004", "lab", "medium", "UPDATE policy has no WITH CHECK", "public.profiles", MIG, 40,
      "CREATE POLICY \"Users update own profile\" FOR UPDATE USING (auth.uid() = user_id); -- no WITH CHECK",
      True, "Owner changed user_id on their own row to another user's id and the update was accepted.",
      "Add WITH CHECK (auth.uid() = user_id) so a row can't be handed to someone else.", True),
    f("PL-005", "lab", "high", "Policy is always true", "public.feedback", MIG, 77,
      "CREATE POLICY \"Anyone can manage feedback\" FOR ALL USING (true) WITH CHECK (true);",
      True, "Anonymous visitor deleted 1 feedback row written by a seeded user.",
      "Split into INSERT for anyone and SELECT/DELETE for the author only.", True),
    f("PL-006", "lab", "high", "SECURITY DEFINER function callable by anyone", "public.get_user_stats()", MIG, 120,
      "CREATE FUNCTION public.get_user_stats() ... SECURITY DEFINER; GRANT EXECUTE ... TO anon;",
      True, "Anonymous visitor called get_user_stats() and received counts for every seeded user.",
      "Revoke EXECUTE from anon, set search_path, and filter by auth.uid() inside the function.", True),
    f("PL-007", "lab", "medium", "Storage bucket is public", "storage.buckets: avatars", "supabase/migrations/20241020090000_storage.sql", 4,
      "INSERT INTO storage.buckets (id, name, public) VALUES ('avatars', 'avatars', true);",
      True, "Anonymous visitor listed and downloaded 2 seeded files from the avatars bucket.",
      "Make the bucket private and serve files with signed URLs, or confirm avatars are meant to be public.", False),
    f("PL-008", "lab", "critical", "Row level security is not enabled", "public.invoices", MIG, 140,
      "CREATE TABLE public.invoices (...); -- no ENABLE ROW LEVEL SECURITY anywhere in the migrations",
      True, "Anonymous visitor read 3 of 3 seeded invoices (billing_email, amount).",
      "Enable row level security and add owner-only policies.", True),
    # Code
    f("PL-009", "code", "high", "AI, payment or database key in the code", "src/lib/ai.ts", "src/lib/ai.ts", 4,
      "const OPENAI_API_KEY = \"sk-proj-\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\" // shipped to the browser bundle", False,
      "", "Move the call behind a server-side function, then rotate the key with the provider.", False),
    f("PL-010", "code", "critical", "Service role key in client code", "src/lib/admin.ts", "src/lib/admin.ts", 3,
      "const SUPABASE_SERVICE_KEY = \"eyJhbGciOiJIUzI1NiIs…[redacted]\"", False,
      "", "Move the call to a server-side function, then rotate the key in the Supabase dashboard.", False),
    f("PL-011", "code", "high", "Key still in git history", "commit 4f2a9c1", ".env", 2,
      "STRIPE_SECRET_KEY=sk_test_•••••••• (added in 4f2a9c1, deleted in 9b17e03)", False,
      "", "Rotate the key. Deleting the file doesn't remove it from history.", False),
    f("PL-017", "code", "high", "Edge function open without sign-in while using the service key", "supabase/functions/send-invite",
      "supabase/functions/send-invite/index.ts", 12,
      "createClient(url, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')) with no Authorization check; verify_jwt = false",
      False, "", "Check the caller's JWT before using the service key, or turn verify_jwt back on.", False),
    f("PL-018", "code", "low", "Sign-ups need no email confirmation", "supabase/config.toml", "supabase/config.toml", 41,
      "[auth.email] enable_confirmations = false", False, "",
      "Turn on email confirmations so nobody can sign up with someone else's address.", False),
    f("PL-019", "code", "critical", "Access decided by user_metadata, which users can edit", "supabase/functions/admin-export",
      "supabase/functions/admin-export/index.ts", 21,
      "if (user.user_metadata.role !== 'admin') return new Response('Forbidden', { status: 403 })", False, "",
      "Decide roles from app_metadata or a roles table the user can't write to.", False),
    f("PL-020", "code", "high", "Admin check only in the browser", "src/pages/Admin.tsx", "src/pages/Admin.tsx", 18,
      "if (user.email !== ADMIN_EMAIL) return <Navigate to=\"/\" /> // data queries below have no server-side check",
      False, "", "Enforce the admin role in a policy or server function, not only in the page.", False),
    f("PL-021", "code", "high", "Payment webhook doesn't verify its signature", "supabase/functions/stripe-webhook",
      "supabase/functions/stripe-webhook/index.ts", 9,
      "const event = await req.json(); // no stripe.webhooks.constructEvent(...)", False, "",
      "Verify the Stripe-Signature header with your webhook secret before trusting the event.", False),
    f("PL-022", "code", "high", "Edge function trusts a user id sent in the request", "supabase/functions/update-profile",
      "supabase/functions/update-profile/index.ts", 15,
      "const { user_id, ...fields } = await req.json(); ... .eq('id', user_id)", False, "",
      "Take the user id from the verified JWT, never from the request body.", False),
    f("PL-023", "code", "critical", "Dependency with a known vulnerability", "next 14.1.0", "package-lock.json", 1804,
      "next@14.1.0: middleware authorisation bypass (fixed in 14.2.25)", False, "",
      "Upgrade next to 14.2.25 or later.", False, advisory="GHSA-f82v-jwr5-mffw"),
    f("PL-024", "code", "medium", "User content rendered as raw HTML", "src/components/Comment.tsx", "src/components/Comment.tsx", 27,
      "<div dangerouslySetInnerHTML={{ __html: comment.body }} />", False, "",
      "Render as text, or sanitise with DOMPurify before inserting HTML.", False),
    f("PL-025", "code", "critical", "Firebase rules allow anyone", "firestore.rules", "firestore.rules", 5,
      "match /{document=**} { allow read, write: if true; }", False, "",
      "Require request.auth and match the document owner in the rules.", False),
    f("PL-026", "code", "medium", "Any website can call a signed-in function", "supabase/functions/_shared/cors.ts",
      "supabase/functions/_shared/cors.ts", 2,
      "'Access-Control-Allow-Origin': '*' with 'Access-Control-Allow-Headers': 'authorization, ...'", False, "",
      "Allow only your own site's origin.", False),
]
BY = {x["id"]: x for x in ALL}


def counts(fs):
    c = {s: 0 for s in SEV}
    for x in fs:
        c[x["severity"]] += 1
    return c


def summary(fs, proof_passed, questions=None):
    if not proof_passed:
        for x in fs:
            x["fixed_in_lab"] = False
    lab = [x for x in fs if x["line"] == "lab"]
    anyone = sorted({x["object"].split(".", 1)[1] for x in lab if x["id"] in ("PL-001", "PL-008") and x["object"].startswith("public.")})
    signed = sorted({x["object"].split(".", 1)[1] for x in lab if x["id"] == "PL-002"} - set(anyone))
    return {"tables_leaking": anyone + signed, "readable_by_anyone": anyone, "readable_by_signed_in": signed,
            "lab_proof_passed": proof_passed, "break_risk": "low", "questions_for_owner": questions or [],
            "findings": fs, "counts": counts(fs), "demo": True}


def pick(ids, **over):
    out = []
    for i in ids:
        x = copy.deepcopy(BY[i])
        x.update(over.get(i, {}))
        out.append(x)
    return out


routes, apps = {}, []
WS = "demo-ws"
FIX = sample["fix_sql"] + ("\n-- Demo data: the rest of this migration is representative, not from a real run.\n"
                           "DROP POLICY \"Signed in users can read\" ON public.messages;\n"
                           "CREATE POLICY \"Sender or recipient can read\" ON public.messages FOR SELECT\n"
                           "  USING (auth.uid() IN (sender_id, recipient_id));\n"
                           "ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;\n"
                           "CREATE POLICY \"Owner reads own invoices\" ON public.invoices FOR SELECT USING (auth.uid() = user_id);\n")
QUESTION = [{"question": "Should people who aren't signed in see avatars?", "recommended": "Yes, if avatars appear on public pages; the files hold no other personal data."}]


def report_md(repo, fs):
    lines = [f"# Leak check: {repo}", "", "_Demo workspace: fake data, shown to illustrate the PatchLabs app._", "",
             "## What we found"]
    lines += [f"- **{x['id']}** ({x['severity']}) {x['title']}: `{x['object']}`" for x in fs] or ["- Nothing the wrong people can read."]
    return "\n".join(lines) + "\n"


STALE_AFTER = {"weekly": 14, "monthly": 60, "off": 45}
parse = lambda t: dt.datetime.fromisoformat(t.replace("Z", "+00:00"))


def history(aid, checks):
    """Like api/taxonomy.py: key = id + object; open from the first check of the current streak, fixed at the first later
    check without it; 'regressed' when it had been fixed before. Adds the fields to each check's findings in place."""
    open_, fixed, ever_fixed = {}, [], set()
    for cid, status, trigger, fin, fs, passed, qs in reversed(checks):   # oldest first
        seen = {}
        for f in fs:
            k = f["id"] + "|" + (f["object"] or f["file"])
            st = open_.get(k) or {"first_seen": fin, "first_check_id": cid, "regressed": k in ever_fixed}
            seen[k] = st
            f.update(first_seen=st["first_seen"], first_check_id=st["first_check_id"], regressed=st["regressed"], fixed_at=None,
                     fixed_in_check_id=None, days_open=(parse(fin) - parse(st["first_seen"])).days)
        for k, st in open_.items():
            if k not in seen:
                ever_fixed.add(k)
                fixed.append(dict(st["last"], fixed_at=fin, fixed_in_check_id=cid, days_open=(parse(fin) - parse(st["first_seen"])).days))
        for f in fs:
            k = f["id"] + "|" + (f["object"] or f["file"])
            seen[k]["last"] = {x: f[x] for x in ("id", "object", "file", "title", "severity", "line", "cwe", "owasp", "owasp_name",
                                                 "first_seen", "first_check_id", "regressed")} | {"last_seen": fin, "last_check_id": cid}
        open_ = seen
    latest = checks[0][4]
    rank = {s: i for i, s in enumerate(SEV)}
    opened = [dict(open_[f["id"] + "|" + (f["object"] or f["file"])]["last"], days_open=(ANCHOR - parse(f["first_seen"])).days,
                   fixed_at=None, fixed_in_check_id=None) for f in latest]
    opened.sort(key=lambda x: (rank[x["severity"]], x["first_seen"]))
    return {"open": opened, "fixed": sorted(fixed, key=lambda x: x["fixed_at"], reverse=True)[:50]}


def add_app(aid, repo, label, schedule, badge, created, checks, diff, next_at):
    """checks: newest first, each (cid, status, trigger, finished_at, findings, proof_passed, questions)"""
    found = history(aid, checks)
    view_checks, last = [], None
    for cid, status, trigger, fin, fs, passed, qs in checks:
        s = summary(fs, passed, qs)
        view_checks.append({"id": cid, "status": status, "trigger": trigger, "created_at": fin, "finished_at": fin,
                            "tables_leaking": s["tables_leaking"], "lab_proof_passed": passed, "counts": s["counts"]})
        routes[f"/checks/{cid}"] = {"id": cid, "repo": repo, "branch": "main", "status": status, "created_at": fin,
                                    "verified_at": fin, "finished_at": fin, "app_id": aid, "summary": s,
                                    "report_md": report_md(repo, fs), "fix_sql": FIX if fs and status != "no_leaks" else None,
                                    "events": [], "decisions": [], "answers": [], "suppressed_tables": [], "new_leaks": diff["new_leaks"] if cid == checks[0][0] else []}
        last = last or {"id": cid, "status": status, "finished_at": fin, "tables_leaking": s["tables_leaking"], "counts": s["counts"]}
    age = (ANCHOR - parse(checks[0][3])).days
    app = {"id": aid, "workspace_id": WS, "repo": repo, "branch": "main", "client_label": label, "schedule": schedule,
           "next_check_at": next_at, "badge_public": badge, "created_at": created, "verified_at": created, "verified": True,
           "last_check": last, "open_check_id": None, "suppressed_tables": [],
           "freshness": {"stale": age > STALE_AFTER[schedule], "days_since_check": age, "stale_after_days": STALE_AFTER[schedule]}}
    apps.append(app)
    detail = dict(app, checks=view_checks, diff=dict(diff, from_check_id=checks[1][0] if len(checks) > 1 else None, to_check_id=checks[0][0]),
                  findings=found)
    routes[f"/apps/{aid}"] = detail


shipped = [x["id"] for x in ALL]
BOOK = {"object": "public.bookings", "line_no": 64,
        "evidence": "policy \"Bookings readable when signed in\" FOR SELECT TO authenticated USING (true); columns: guest_email, phone",
        "proof": "Signed-in stranger read 4 bookings made by two other seeded users. After the fix: stranger 0, owner 2.",
        "fix": "Scope SELECT to the guest and the venue owner: auth.uid() IN (guest_id, owner_id)."}
ORDERS = lambda: dict(copy.deepcopy(BY["PL-002"]), object="public.orders", line_no=88,
                      evidence="policy \"Orders visible to signed in users\" FOR SELECT TO authenticated USING (true); columns: shipping_address, phone",
                      proof="Signed-in stranger read 5 orders placed by other seeded users.",
                      fix="Scope SELECT to the buyer: auth.uid() = buyer_id.")
add_app("demo-app-1", sample["repo"], None, "weekly", True, ago(days=40), [
    ("demo-chk-1-5", "done", "scheduled", ago(hours=3), pick(shipped), True, QUESTION),
    ("demo-chk-1-4", "done", "scheduled", ago(days=7, hours=3), pick(shipped) + [ORDERS()], True, QUESTION),
    ("demo-chk-1-3", "needs_review", "manual", ago(days=13), pick([i for i in shipped if i not in ("PL-023", "PL-026", "PL-024")]) + [ORDERS()], False, []),
    ("demo-chk-1-2", "done", "scheduled", ago(days=21, hours=3), pick(["PL-001", "PL-002", "PL-004", "PL-008", "PL-010", "PL-011", "PL-021", "PL-024"]), True, []),
    ("demo-chk-1-1", "done", "verify", ago(days=40), pick(["PL-001", "PL-002", "PL-008", "PL-010", "PL-011"]), True, []),
], {"new_leaks": [], "fixed": ["orders"], "still_leaking": ["invoices", "profiles", "messages"], "suppressed": []}, ahead(days=6, hours=21))

add_app("demo-app-2", "example-org/booking-portal", "Example client (fake)", "monthly", False, ago(days=75), [
    ("demo-chk-2-3", "needs_review", "scheduled", ago(days=2), pick(["PL-002", "PL-005", "PL-022", "PL-018"], **{"PL-002": BOOK}), False, []),
    ("demo-chk-2-2", "done", "scheduled", ago(days=32), pick(["PL-001", "PL-002", "PL-005", "PL-006", "PL-022", "PL-018"], **{"PL-002": BOOK}), True, []),
    ("demo-chk-2-1", "done", "verify", ago(days=62), pick(["PL-001", "PL-002", "PL-004", "PL-005", "PL-006", "PL-007", "PL-010", "PL-022", "PL-018"], **{"PL-002": BOOK}), True, []),
], {"new_leaks": [], "fixed": ["profiles"], "still_leaking": ["bookings"], "suppressed": []}, ahead(days=28))

add_app("demo-app-3", "example-org/landing-site", None, "off", True, ago(days=90), [
    ("demo-chk-3-2", "no_leaks", "manual", ago(days=50, hours=5), pick(["PL-009", "PL-018"], **{"PL-009": {"object": "src/config.ts", "file": "src/config.ts", "line_no": 7, "evidence": "export const STRIPE_KEY = \"sk_live_\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\"", "title": "AI, payment or database key in the code"}}), False, []),
    ("demo-chk-3-1", "done", "verify", ago(days=85), pick(["PL-007", "PL-018"]), True, []),
], {"new_leaks": [], "fixed": [], "still_leaking": [], "suppressed": []}, None)

# ---- Live posture (LIVE.md): demo-app-1 verified on a fake domain, demo-app-2 waiting for verification, demo-app-3 none.
# The .example domain can't exist on the internet (the API refuses it), so nothing here points at a real site.
LIVE_URL = "https://demo-app.patchlabs-demo.example"


def lf(fid, sev, title, evidence, fix, obj=LIVE_URL):
    return {"id": fid, "line": "live", "severity": sev, "title": title, "object": obj, "evidence": evidence, "fix": fix, **TAGS.get(fid, {})}


CSP = lf("PL-030", "medium", "No Content-Security-Policy", "The page sends no Content-Security-Policy header or meta tag.",
         "Send a Content-Security-Policy that lists where scripts may load from (start with default-src 'self').")
SNIFF = lf("PL-032", "low", "No X-Content-Type-Options: nosniff", "X-Content-Type-Options is missing or isn't nosniff.", "Send X-Content-Type-Options: nosniff")
COOKIE = lf("PL-033", "medium", "Cookie set without Secure, or a session cookie without HttpOnly", "Cookie sb-demo-auth-token is set without HttpOnly.",
            "Set cookies with Secure and SameSite=Lax; add HttpOnly to session cookies.", obj="cookie sb-demo-auth-token")
PASS_TITLES = {"PL-027": "HTTPS is forced", "PL-028": "TLS certificate is valid", "PL-029": "HSTS is on", "PL-030": "Content-Security-Policy is set",
               "PL-031": "Framing is restricted", "PL-032": "X-Content-Type-Options is nosniff", "PL-033": "Cookies carry Secure (and HttpOnly on sessions)",
               "PL-034": "No scripts or styles over plain HTTP", "PL-035": "No software versions in headers", "PL-036": "Referrer-Policy is set"}
PEN = {"high": 30, "medium": 15, "low": 5}


def posture(fs, trigger, at, cookies):
    score = max(0, 100 - sum(PEN.get(x["severity"], 0) for x in {x["id"]: x for x in fs}.values()))
    grade = next(g for g, floor in (("A", 90), ("B", 75), ("C", 60), ("D", 40), ("F", 0)) if score >= floor)
    failed = {x["id"] for x in fs}
    return {"id": f"demo-posture-{at}", "url": LIVE_URL, "final_url": LIVE_URL + "/", "grade": grade, "score": score, "checked_at": at, "trigger": trigger,
            "counts": counts(fs), "findings": fs, "passed": [{"id": k, "title": v} for k, v in PASS_TITLES.items() if k not in failed],
            "facts": {"status": 200, "redirects": [LIVE_URL + "/"], "https_redirect": True, "https_preloaded_tld": False,
                      "tls": {"version": "TLSv1.3", "issuer": "Let's Encrypt", "expires": "2027-01-05", "days_left": 56},
                      "headers": {"strict-transport-security": "max-age=63072000; includeSubDomains", "content-security-policy": None,
                                  "content-security-policy-report-only": None, "x-frame-options": "DENY", "x-content-type-options": None,
                                  "referrer-policy": "strict-origin-when-cross-origin", "permissions-policy": None, "server": "Vercel", "x-powered-by": None},
                      "cookies": cookies, "server": "Vercel"}}


# newest first: the latest daily re-check caught a new session cookie without HttpOnly (B → C)
LIVE_HIST = [posture([CSP, COOKIE, SNIFF], "scheduled", ago(hours=3), [{"name": "sb-demo-auth-token", "secure": True, "httponly": False, "samesite": "Lax"}])]
LIVE_HIST += [posture([CSP, SNIFF], "scheduled", ago(days=d, hours=3), []) for d in range(1, 9)]
LIVE_HIST += [posture([CSP, SNIFF], "verify", ago(days=9, hours=2), [])]
short = lambda x: {k: x[k] for k in ("grade", "score", "checked_at", "counts")}
LIVE_1 = {"url": LIVE_URL, "verified": True, "verified_at": ago(days=9, hours=2), "next_check_at": ahead(hours=21), "verify": None, "last": LIVE_HIST[0]}
CODE_2 = "patchlabs-live-0d3e9a51c7b2f846"
LIVE_2 = {"url": "https://booking-portal.patchlabs-demo.example", "verified": False, "verified_at": None, "next_check_at": None,
          "verify": {"file": "patchlabs-verify.txt", "file_url": "https://booking-portal.patchlabs-demo.example/patchlabs-verify.txt", "code": CODE_2,
                     "meta": f'<meta name="patchlabs-verify" content="{CODE_2}">'}, "last": None}
LIVE_3 = {"url": None, "verified": False, "verified_at": None, "next_check_at": None, "verify": None, "last": None}
for _a in apps:
    _full = {"demo-app-1": LIVE_1, "demo-app-2": LIVE_2}.get(_a["id"], LIVE_3)
    routes[f"/apps/{_a['id']}"]["live"] = _full
    _a["live"] = dict(_full, last=short(_full["last"]) if _full["last"] else None)
routes["/apps/demo-app-1/live/checks"] = {"checks": [{"id": x["id"], "grade": x["grade"], "score": x["score"], "counts": x["counts"],
                                                      "trigger": x["trigger"], "checked_at": x["checked_at"]} for x in LIVE_HIST]}
routes["/apps/demo-app-2/live/checks"] = {"checks": []}
routes["/apps/demo-app-3/live/checks"] = {"checks": []}

routes["/me"] = {"user": {"id": "demo-user", "email": "you@example.test", "name": "Demo user", "created_at": ago(days=75)},
                 "workspaces": [{"id": WS, "name": "Demo workspace", "role": "owner", "plan": "agency"}]}
ME = "demo-user"
MEMBERS = [  # placeholder teammates for the demo; @example.test addresses, no real people
    {"user_id": ME, "email": "you@example.test", "name": "Demo user", "role": "owner", "joined_at": ago(days=75), "app_ids": None},
    {"user_id": "demo-m-admin", "email": "avery@example.test", "name": "Avery", "role": "admin", "joined_at": ago(days=60), "app_ids": None},
    {"user_id": "demo-m-approver", "email": "jordan@example.test", "name": "Jordan", "role": "approver", "joined_at": ago(days=44), "app_ids": None},
    {"user_id": "demo-m-viewer", "email": "riley@example.test", "name": "Riley", "role": "viewer", "joined_at": ago(days=20), "app_ids": None},
    {"user_id": "demo-m-client", "email": "contact@client.example.test", "name": "Client contact", "role": "client", "joined_at": ago(days=12),
     "app_ids": ["demo-app-2"]},
]
routes[f"/workspaces/{WS}"] = {"id": WS, "name": "Demo workspace", "plan": "agency", "role": "owner", "created_at": ago(days=75),
                               "limits": {"apps": 10, "runs_per_month": 200, "seats": 10, "schedules": ["weekly", "monthly", "off"]},
                               "usage": {"apps": len(apps), "runs_this_month": 4, "members": 4, "clients": 1},
                               "permissions": ["decide", "manage", "owner", "run", "support", "view", "view_team"],
                               "webhook_url": "https://hooks.slack.com/services/demo-workspace-example",
                               "webhook_format": "auto", "webhook_kind": "slack", "webhook_secret": None,
                               "members": MEMBERS,
                               "invites": [{"id": "demo-inv-1", "email": "new.teammate@example.test", "role": "viewer", "app_ids": [],
                                            "created_at": ago(days=1), "expires_at": ahead(days=13)}]}
routes[f"/workspaces/{WS}/api-keys"] = {"api_keys": [
    {"id": "demo-key-1", "name": "GitHub Actions", "prefix": "pl_live_Dm0x", "created_at": ago(days=30), "last_used_at": ago(hours=3),
     "created_by": ME, "created_by_email": "you@example.test"}]}
routes["/taxonomy/findings"] = {"findings": TAGS, "cwe": _tax["CWE"], "owasp": _tax["OWASP"]}

ACTIONS = ["auth.sign_in", "auth.sign_out", "member.invited", "member.invite_cancelled", "member.joined", "member.role_changed",
           "member.apps_changed", "member.removed", "member.left", "workspace.renamed", "plan.changed", "upgrade.requested", "app.added",
           "app.updated", "app.verified", "app.removed", "check.started", "decision.made", "check.answered", "suppression.added",
           "suppression.removed", "api_key.created", "api_key.revoked", "webhook.created", "webhook.changed", "webhook.deleted",
           "webhook.secret_rotated", "webhook.tested", "data.exported", "audit.exported", "ticket.raised",
           "app.live_set", "app.live_verified", "app.live_removed", "posture.checked"]
U = {m["user_id"]: m for m in MEMBERS}
def who(uid): return {"kind": "user", "id": uid, "label": U[uid]["name"], "email": U[uid]["email"]}
def mem(uid): return {"type": "member", "id": uid, "label": U[uid]["name"], "email": U[uid]["email"]}
def app_t(aid, repo): return {"type": "app", "id": aid, "label": repo, "email": None}
EVENTS = [  # newest first
    (ago(hours=1), "auth.sign_in", who(ME), None, {}),
    (ago(hours=2, minutes=57), "posture.checked", {"kind": "system", "id": None, "label": "PatchLabs", "email": None}, app_t("demo-app-1", sample["repo"]), {"url": LIVE_URL, "grade": "C", "trigger": "scheduled"}),
    (ago(hours=3), "check.started", {"kind": "system", "id": None, "label": "PatchLabs", "email": None}, app_t("demo-app-1", sample["repo"]), {"trigger": "scheduled", "app_id": "demo-app-1"}),
    (ago(hours=20), "decision.made", who("demo-m-approver"), {"type": "check", "id": "demo-chk-1-4", "label": sample["repo"], "email": None}, {"action": "approve", "tables": ["profiles", "invoices"]}),
    (ago(days=1), "member.invited", who(ME), {"type": "invite", "id": "demo-inv-1", "label": None, "email": "new.teammate@example.test"}, {"role": "viewer"}),
    (ago(days=2), "check.started", {"kind": "api_key", "id": None, "label": "API key GitHub Actions (pl_live_Dm0x)", "email": None}, app_t("demo-app-2", "example-org/booking-portal"), {"trigger": "api", "app_id": "demo-app-2"}),
    (ago(days=3), "webhook.tested", who("demo-m-admin"), {"type": "webhook", "id": WS, "label": "hooks.slack.com", "email": None}, {"ok": True, "status_code": 200, "format": "slack"}),
    (ago(days=3, hours=1), "webhook.changed", who("demo-m-admin"), {"type": "webhook", "id": WS, "label": "hooks.slack.com", "email": None}, {"host": "hooks.slack.com", "kind": "slack", "previous_host": "example.test"}),
    (ago(days=5), "suppression.added", who(ME), app_t("demo-app-1", sample["repo"]), {"table": "audit_log"}),
    (ago(days=5, hours=1), "suppression.removed", who(ME), app_t("demo-app-1", sample["repo"]), {"table": "audit_log"}),
    (ago(days=8), "check.answered", who("demo-m-approver"), {"type": "check", "id": "demo-chk-1-4", "label": sample["repo"], "email": None}, {}),
    (ago(days=9, hours=2), "app.live_verified", who(ME), app_t("demo-app-1", sample["repo"]), {"url": LIVE_URL}),
    (ago(days=9, hours=2, minutes=5), "app.live_set", who(ME), app_t("demo-app-1", sample["repo"]), {"url": LIVE_URL}),
    (ago(days=12), "member.apps_changed", who(ME), mem("demo-m-client"), {"added": ["demo-app-2"], "removed": []}),
    (ago(days=12, hours=1), "member.joined", who("demo-m-client"), mem("demo-m-client"), {"role": "client"}),
    (ago(days=14), "ticket.raised", who("demo-m-approver"), {"type": "ticket", "id": "demo-t-1", "label": "Fix for public.bookings", "email": None}, {"number": 7, "category": "fix", "priority": "normal"}),
    (ago(days=20), "member.role_changed", who(ME), mem("demo-m-viewer"), {"from": "member", "to": "viewer"}),
    (ago(days=20, hours=2), "api_key.revoked", who(ME), {"type": "api_key", "id": "demo-key-0", "label": "Old CI key", "email": None}, {"prefix": "pl_live_Q9aa", "reason": "role changed to viewer"}),
    (ago(days=30), "api_key.created", who(ME), {"type": "api_key", "id": "demo-key-1", "label": "GitHub Actions", "email": None}, {"prefix": "pl_live_Dm0x"}),
    (ago(days=32), "app.updated", who("demo-m-admin"), app_t("demo-app-2", "example-org/booking-portal"), {"schedule": {"from": "weekly", "to": "monthly"}}),
    (ago(days=40), "app.verified", who(ME), app_t("demo-app-1", sample["repo"]), {}),
    (ago(days=40, hours=1), "app.added", who(ME), app_t("demo-app-1", sample["repo"]), {}),
    (ago(days=44), "member.role_changed", who(ME), mem("demo-m-approver"), {"from": "member", "to": "approver"}),
    (ago(days=50), "plan.changed", {"kind": "admin", "id": None, "label": "PatchLabs admin", "email": None}, {"type": "workspace", "id": WS, "label": "Demo workspace", "email": None}, {"plan": {"from": "maker", "to": "agency"}}),
    (ago(days=51), "upgrade.requested", who(ME), {"type": "workspace", "id": WS, "label": "Demo workspace", "email": None}, {"plan": "agency"}),
    (ago(days=60), "workspace.renamed", who(ME), {"type": "workspace", "id": WS, "label": "Demo workspace", "email": None}, {"from": "My workspace", "to": "Demo workspace"}),
    (ago(days=61), "webhook.created", who(ME), {"type": "webhook", "id": WS, "label": "example.test", "email": None}, {"host": "example.test", "kind": "json"}),
    (ago(days=62), "audit.exported", who(ME), None, {"rows": 12}),
    (ago(days=70), "data.exported", who(ME), None, {}),
    (ago(days=75), "auth.sign_in", who(ME), None, {}),
]
routes[f"/workspaces/{WS}/audit"] = {"events": [{"id": 1000 - i, "at": at, "action": a, "actor": actor, "target": t, "detail": d}
                                               for i, (at, a, actor, t, d) in enumerate(EVENTS)], "next_before": None, "actions": ACTIONS}
routes[f"/workspaces/{WS}/apps"] = {"apps": apps}
routes["/me/checks"] = {"checks": [{"id": "sample", "repo": sample["repo"], "status": "done", "created_at": sample["created_at"]}]}

out = {"_about": "PatchLabs demo workspace. Fake data for /demo: no real customers, apps or people. The first app is our own "
                 "demo repo; its findings beyond PL-001 on public.profiles are representative examples, not a real run.",
       "anchor": iso(ANCHOR), "routes": routes}
os.makedirs(os.path.join(ROOT, "site/static/demo"), exist_ok=True)
json.dump(out, open(os.path.join(ROOT, "site/static/demo/workspace.json"), "w"), indent=1, ensure_ascii=False)
print("routes:", len(routes), "findings in latest demo-app check:", len(routes["/checks/demo-chk-1-5"]["summary"]["findings"]))
