"""Finding enrichment: CWE/OWASP tags per finding ID, and first_seen / days_open / fixed_at across an app's checks."""
import re
from datetime import datetime, timedelta, timezone

import taxonomy
from helpers import add_repo, claim, finish_with, invite_as, sign_in, sql, verified_app, A

PROFILES = {"id": "PL-001", "line": "lab", "severity": "critical", "title": "Anyone can read profiles", "object": "public.profiles"}
LODASH = {"id": "PL-023", "line": "code", "severity": "high", "title": "lodash has a known vulnerability", "object": "package.json"}
XSS = {"id": "PL-024", "line": "code", "severity": "medium", "title": "Raw HTML", "file": "src/Post.tsx"}


def test_every_finding_id_is_tagged_with_known_names():
    ids = [f"PL-{n:03d}" for n in range(1, 27)]
    assert sorted(taxonomy.TAGS) == ids
    for fid, (cwes, owasp) in taxonomy.TAGS.items():
        assert owasp in taxonomy.OWASP, fid
        for cwe in cwes:
            assert re.fullmatch(r"CWE-\d+", cwe) and cwe in taxonomy.CWE, (fid, cwe)
    # spot checks against the published lists
    assert taxonomy.tags("PL-001") == {"cwe": ["CWE-359", "CWE-863"], "owasp": "A01:2021", "owasp_name": "Broken Access Control"}
    assert taxonomy.tags("PL-023")["cwe"] == ["CWE-1395"] and taxonomy.tags("PL-023")["owasp"] == "A06:2021"
    assert taxonomy.tags("PL-024")["cwe"] == ["CWE-79"] and taxonomy.tags("PL-024")["owasp"] == "A03:2021"
    assert taxonomy.tags("PL-010")["cwe"] == ["CWE-798"] and taxonomy.tags("PL-010")["owasp"] == "A07:2021"
    assert taxonomy.tags("pl-017")["cwe"] == ["CWE-306"]
    assert taxonomy.tags("PL-999") == {"cwe": [], "owasp": None, "owasp_name": None}


def test_taxonomy_endpoint(client):
    r = client.get("/taxonomy/findings").json()
    assert r["findings"]["PL-021"] == {"cwe": ["CWE-345", "CWE-347"], "owasp": "A08:2021", "owasp_name": "Software and Data Integrity Failures"}
    assert r["cwe"]["CWE-862"] == "Missing Authorization" and r["owasp"]["A05:2021"] == "Security Misconfiguration"


def run(client, u, a, findings, days_ago):
    cid = client.post(f"/apps/{a['id']}/checks", headers=u.h).json()["check_id"]
    claim(client)
    finish_with(client, cid, findings)
    when = datetime.now(timezone.utc) - timedelta(days=days_ago)
    sql("UPDATE checks SET finished_at = %s WHERE id = %s", (when, cid))
    return str(cid), when


def test_first_seen_days_open_and_fixed_at(client):
    u = sign_in(client, "owner@example.com")
    client.patch(f"/admin/workspaces/{u.wid}", json={"plan": "maker"}, headers=A)
    a, cid0 = verified_app(client, u)
    claim(client)
    finish_with(client, cid0, [PROFILES, LODASH])
    t0 = datetime.now(timezone.utc) - timedelta(days=10)
    sql("UPDATE checks SET finished_at = %s WHERE id = %s", (t0, cid0))
    # a failed check in between doesn't count as "gone"
    bad = client.post(f"/apps/{a['id']}/checks", headers=u.h).json()["check_id"]
    claim(client)
    client.post(f"/worker/checks/{bad}/result", headers={"Authorization": "Bearer worker-test-token"}, json={"status": "failed", "error": "x"})
    cid1, t1 = run(client, u, a, [PROFILES, XSS], 3)       # lodash fixed, xss new
    cid2, t2 = run(client, u, a, [PROFILES, LODASH], 1)    # lodash back (regressed), xss fixed

    app = client.get(f"/apps/{a['id']}", headers=u.h).json()
    open_ = {f["id"]: f for f in app["findings"]["open"]}
    assert [f["id"] for f in app["findings"]["open"]] == ["PL-001", "PL-023"]  # worst first
    p = open_["PL-001"]
    assert p["first_check_id"] == str(cid0) and p["days_open"] == 10 and p["fixed_at"] is None and p["regressed"] is False
    assert p["cwe"] == ["CWE-359", "CWE-863"] and p["owasp"] == "A01:2021" and p["last_check_id"] == cid2
    lod = open_["PL-023"]
    assert lod["first_check_id"] == cid2 and lod["days_open"] == 1 and lod["regressed"] is True
    fixed = [(f["id"], f["fixed_in_check_id"], f["days_open"]) for f in app["findings"]["fixed"]]
    assert fixed == [("PL-024", cid2, 2), ("PL-023", cid1, 7)]  # newest fix first
    assert app["findings"]["fixed"][0]["file"] == "src/Post.tsx"

    # a single check's view: the streak that check belongs to
    first = client.get(f"/checks/{cid0}").json()["summary"]["findings"]
    by = {f["id"]: f for f in first}
    assert by["PL-023"]["fixed_in_check_id"] == cid1 and by["PL-023"]["days_open"] == 7 and by["PL-023"]["cwe"] == ["CWE-1395"]
    assert by["PL-001"]["fixed_at"] is None and by["PL-001"]["days_open"] == 10
    v1 = client.post(f"/workspaces/{u.wid}/api-keys", json={"name": "ci"}, headers=u.h).json()["key"]
    s = client.get(f"/v1/checks/{cid1}", headers={"X-API-Key": v1}).json()["summary"]["findings"]
    assert {f["id"]: f["days_open"] for f in s} == {"PL-001": 10, "PL-024": 2}


def test_anonymous_check_gets_tags_only(client):
    add_repo("acme/anon")
    cid = client.post("/checks", json={"email": "x@example.com", "repo": "acme/anon"}).json()["id"]
    sql("UPDATE checks SET status = 'queued', verified_at = now() WHERE id = %s", (cid,))
    claim(client)
    finish_with(client, cid, [PROFILES, {"id": "PL-999", "title": "unknown"}, "not a dict"])
    fs = client.get(f"/checks/{cid}").json()["summary"]["findings"]
    assert fs[0]["owasp"] == "A01:2021" and "first_seen" not in fs[0]
    assert fs[1]["cwe"] == [] and fs[1]["owasp"] is None
    assert len(fs) == 2  # junk entries are dropped


def test_checks_without_findings_are_unchanged(client):
    u = sign_in(client, "owner@example.com")
    a, cid = verified_app(client, u)
    claim(client)
    finish_with(client, cid, [])
    assert client.get(f"/checks/{cid}").json()["summary"]["findings"] == []
    assert client.get(f"/apps/{a['id']}", headers=u.h).json()["findings"] == {"open": [], "fixed": []}
    v = invite_as  # noqa: F841 (shared helper import)
