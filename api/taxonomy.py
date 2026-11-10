"""Finding enrichment: CWE and OWASP Top 10 (2021) tags per finding ID, and each finding's history across an app's checks.

The map is the one place these tags live. CWE: the most specific weaknesses, primary first. OWASP: the 2021 category the
risk belongs to (A01 Broken Access Control covers privilege escalation, acting without signing in and CORS mistakes; see
https://owasp.org/Top10/A01_2021-Broken_Access_Control/). PL-003 (RLS on, no policies: the app's own users are locked out)
is a misconfiguration with no CWE that fits, so it carries none.

History key: finding id + object (falling back to file). A finding is open from the first finished check of its current
streak; it is fixed at the first later finished check that no longer reports it. Failed checks don't count either way.
"""
from datetime import datetime, timezone

from fastapi import APIRouter

router = APIRouter()

OWASP = {"A01:2021": "Broken Access Control", "A02:2021": "Cryptographic Failures", "A03:2021": "Injection",
         "A04:2021": "Insecure Design", "A05:2021": "Security Misconfiguration", "A06:2021": "Vulnerable and Outdated Components",
         "A07:2021": "Identification and Authentication Failures", "A08:2021": "Software and Data Integrity Failures",
         "A09:2021": "Security Logging and Monitoring Failures", "A10:2021": "Server-Side Request Forgery"}

CWE = {"CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
       "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
       "CWE-250": "Execution with Unnecessary Privileges",
       "CWE-269": "Improper Privilege Management",
       "CWE-284": "Improper Access Control",
       "CWE-287": "Improper Authentication",
       "CWE-295": "Improper Certificate Validation",
       "CWE-306": "Missing Authentication for Critical Function",
       "CWE-319": "Cleartext Transmission of Sensitive Information",
       "CWE-345": "Insufficient Verification of Data Authenticity",
       "CWE-347": "Improper Verification of Cryptographic Signature",
       "CWE-359": "Exposure of Private Personal Information to an Unauthorized Actor",
       "CWE-426": "Untrusted Search Path",
       "CWE-540": "Inclusion of Sensitive Information in Source Code",
       "CWE-552": "Files or Directories Accessible to External Parties",
       "CWE-602": "Client-Side Enforcement of Server-Side Security",
       "CWE-614": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
       "CWE-639": "Authorization Bypass Through User-Controlled Key",
       "CWE-693": "Protection Mechanism Failure",
       "CWE-798": "Use of Hard-coded Credentials",
       "CWE-807": "Reliance on Untrusted Inputs in a Security Decision",
       "CWE-862": "Missing Authorization",
       "CWE-863": "Incorrect Authorization",
       "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
       "CWE-942": "Permissive Cross-domain Policy with Untrusted Domains",
       "CWE-1004": "Sensitive Cookie Without 'HttpOnly' Flag",
       "CWE-1021": "Improper Restriction of Rendered UI Layers or Frames",
       "CWE-1395": "Dependency on Vulnerable Third-Party Component"}

# id: (CWEs, OWASP 2021 category)
TAGS = {
    "PL-001": (["CWE-359", "CWE-863"], "A01:2021"),   # anon can read personal data
    "PL-002": (["CWE-863", "CWE-359"], "A01:2021"),   # any signed-in user reads every row
    "PL-003": ([], "A05:2021"),                       # RLS on, no policies (locked out; misconfiguration)
    "PL-004": (["CWE-863"], "A01:2021"),              # UPDATE policy without WITH CHECK
    "PL-005": (["CWE-862"], "A01:2021"),              # always-true USING / WITH CHECK
    "PL-006": (["CWE-250", "CWE-426"], "A01:2021"),   # SECURITY DEFINER exposed / no search_path
    "PL-007": (["CWE-552"], "A01:2021"),              # public storage bucket
    "PL-008": (["CWE-862"], "A01:2021"),              # RLS never enabled
    "PL-009": (["CWE-798"], "A07:2021"),              # secret key in the current code
    "PL-010": (["CWE-798"], "A07:2021"),              # service role key in client code
    "PL-011": (["CWE-798", "CWE-540"], "A07:2021"),   # key in git history
    "PL-012": (["CWE-639", "CWE-863"], "A01:2021"),   # strangers change or delete others' rows
    "PL-013": (["CWE-269", "CWE-915"], "A01:2021"),   # users make themselves admin
    "PL-014": (["CWE-250", "CWE-863"], "A01:2021"),   # view skips RLS
    "PL-015": (["CWE-552", "CWE-284"], "A01:2021"),   # storage objects readable/writable by anyone
    "PL-016": (["CWE-359", "CWE-200"], "A01:2021"),   # realtime sends private rows
    "PL-017": (["CWE-306"], "A07:2021"),              # edge function open without sign-in, using the service key
    "PL-018": (["CWE-287"], "A07:2021"),              # sign-ups need no email confirmation
    "PL-019": (["CWE-807"], "A01:2021"),              # access decided by user_metadata
    "PL-020": (["CWE-602", "CWE-862"], "A01:2021"),   # admin check only in the browser
    "PL-021": (["CWE-345", "CWE-347"], "A08:2021"),   # payment webhook signature not verified
    "PL-022": (["CWE-639"], "A01:2021"),              # edge function trusts a user id from the request
    "PL-023": (["CWE-1395"], "A06:2021"),             # dependency with a known vulnerability
    "PL-024": (["CWE-79"], "A03:2021"),               # user content rendered as raw HTML
    "PL-025": (["CWE-862"], "A01:2021"),              # Firebase rules allow anyone
    "PL-026": (["CWE-942"], "A05:2021"),              # CORS * with credentials
    # live posture (LIVE.md): read from one public page load of a verified domain
    "PL-027": (["CWE-319"], "A02:2021"),              # site doesn't force HTTPS
    "PL-028": (["CWE-295"], "A02:2021"),              # certificate invalid, expired or expiring
    "PL-029": (["CWE-319"], "A05:2021"),              # no HSTS
    "PL-030": (["CWE-693"], "A05:2021"),              # no Content-Security-Policy
    "PL-031": (["CWE-1021"], "A05:2021"),             # page can be framed by any site
    "PL-032": (["CWE-693"], "A05:2021"),              # no nosniff
    "PL-033": (["CWE-614", "CWE-1004"], "A05:2021"),  # cookie without Secure, or session cookie without HttpOnly
    "PL-034": (["CWE-319"], "A02:2021"),              # scripts or styles over plain HTTP
    "PL-035": (["CWE-200"], "A05:2021"),              # software versions in headers
    "PL-036": (["CWE-200"], "A05:2021"),              # no Referrer-Policy
}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def tags(fid):
    cwe, owasp = TAGS.get(str(fid or "").upper(), ([], None))
    return {"cwe": list(cwe), "owasp": owasp, "owasp_name": OWASP.get(owasp)}


@router.get("/taxonomy/findings")
def taxonomy():
    """The finding-ID → CWE/OWASP map with names, for tooltips and filters. Public."""
    return {"findings": {fid: tags(fid) for fid in TAGS}, "cwe": CWE, "owasp": OWASP}


def findings_of(summary):
    f = summary.get("findings") if isinstance(summary, dict) else None
    return [x for x in f if isinstance(x, dict)] if isinstance(f, list) else []


def key(f):
    return f"{f.get('id') or ''}|{f.get('object') or f.get('file') or ''}"


def _days(a, b):
    return max(0, int((b - a).total_seconds() // 86400))


def history(c, app_id):
    """Walks the app's finished checks oldest first. Returns (streaks by (check_id, key), open streaks by key, closed
    streaks newest first). A streak: {key, first_seen, first_check_id, last_seen, last_check_id, fixed_at,
    fixed_in_check_id, regressed, finding}."""
    rows = c.execute("SELECT id, finished_at, summary FROM checks WHERE app_id = %s AND status IN ('done', 'no_leaks', 'needs_review') "
                     "AND finished_at IS NOT NULL ORDER BY finished_at, id", (app_id,)).fetchall()
    by_check, active, closed, ever = {}, {}, [], set()
    for r in rows:
        present = {}
        for f in findings_of(r["summary"]):
            present.setdefault(key(f), f)
        for k in [k for k in active if k not in present]:
            s = active.pop(k)
            s.update(fixed_at=r["finished_at"], fixed_in_check_id=r["id"])
            closed.append(s)
        for k, f in present.items():
            s = active.get(k)
            if not s:
                s = active[k] = {"key": k, "first_seen": r["finished_at"], "first_check_id": r["id"], "fixed_at": None,
                                 "fixed_in_check_id": None, "regressed": k in ever}
                ever.add(k)
            s.update(last_seen=r["finished_at"], last_check_id=r["id"], finding=f)
            by_check[(r["id"], k)] = s
    return by_check, active, closed[::-1]


def timing(s, now=None):
    end = s["fixed_at"] or now or datetime.now(timezone.utc)
    return {"first_seen": s["first_seen"], "first_check_id": s["first_check_id"], "fixed_at": s["fixed_at"],
            "fixed_in_check_id": s["fixed_in_check_id"], "days_open": _days(s["first_seen"], end), "regressed": s["regressed"]}


def enrich_summary(c, summary, check=None):
    """Adds cwe/owasp to every finding in a (scrubbed) summary; for a finished app check also first_seen, days_open and
    fixed_at (null while still open) from the app's history."""
    fs = findings_of(summary)
    if not fs:
        return summary
    hist = history(c, check["app_id"])[0] if check and check.get("app_id") and check.get("finished_at") else {}
    out = []
    for f in fs:
        g = {**f, **tags(f.get("id"))}
        s = hist.get((check["id"], key(f))) if hist else None
        if s:
            g.update(timing(s))
        out.append(g)
    return {**summary, "findings": out}


def _item(s, now):
    f = s["finding"]
    return {"id": f.get("id"), "object": f.get("object"), "file": f.get("file"), "title": f.get("title"), "severity": f.get("severity"),
            "line": f.get("line"), **tags(f.get("id")), **timing(s, now), "last_seen": s["last_seen"], "last_check_id": s["last_check_id"]}


def app_findings(c, app_id, fixed_limit=50):
    """For GET /apps/{aid}: findings open in the latest finished check (worst first, then oldest) and recently fixed ones."""
    now = datetime.now(timezone.utc)
    _, active, closed = history(c, app_id)
    open_ = sorted((_item(s, now) for s in active.values()),
                   key=lambda x: (SEVERITY_RANK.get(str(x["severity"]).lower(), 9), x["first_seen"]))
    return {"open": open_, "fixed": [_item(s, now) for s in closed[:fixed_limit]]}
