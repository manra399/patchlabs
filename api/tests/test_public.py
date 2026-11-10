"""Badges, public app status and live stats."""
import uuid
import xml.etree.ElementTree as ET

from helpers import claim, finish, sign_in, sql, verified_app


def badge(client, aid):
    r = client.get(f"/badge/{aid}.svg")
    assert r.status_code == 200 and r.headers["content-type"].startswith("image/svg+xml")
    assert r.headers["cache-control"] == "public, max-age=3600"
    ET.fromstring(r.text)  # well-formed SVG
    return r.text


def test_badge_states(client):
    u = sign_in(client, "owner@example.com")
    a, cid = verified_app(client, u)
    assert "PatchLabs: private" in badge(client, a["id"])
    client.patch(f"/apps/{a['id']}", json={"badge_public": True}, headers=u.h)
    svg = badge(client, a["id"])
    assert "not checked yet" in svg and "#9f9f9f" in svg
    claim(client)
    finish(client, cid, "done", ["profiles"])
    svg = badge(client, a["id"])
    assert "fix in progress" in svg and "#dfb317" in svg
    sql("UPDATE checks SET finished_at = '2026-11-03T10:00:00Z'")
    assert "3 Nov 2026" in badge(client, a["id"])
    r = client.post(f"/apps/{a['id']}/checks", headers=u.h)
    claim(client)
    finish(client, r.json()["check_id"], "no_leaks")
    svg = badge(client, a["id"])
    assert "no known leaks" in svg and "#2ea44f" in svg
    # a failed check doesn't change the badge
    r = client.post(f"/apps/{a['id']}/checks", headers=u.h)
    claim(client)
    finish(client, r.json()["check_id"], "failed")
    assert "no known leaks" in badge(client, a["id"])
    client.patch(f"/apps/{a['id']}", json={"badge_public": False}, headers=u.h)
    assert "private" in badge(client, a["id"])


def test_badge_unknown_app_is_private(client):
    assert "private" in badge(client, uuid.uuid4())
    assert "private" in badge(client, "not-a-uuid")


def test_public_app_status(client):
    u = sign_in(client, "owner@example.com")
    a, cid = verified_app(client, u)
    assert client.get(f"/public/apps/{a['id']}").status_code == 404
    client.patch(f"/apps/{a['id']}", json={"badge_public": True}, headers=u.h)
    assert client.get(f"/public/apps/{a['id']}").json() == {"repo": "acme/shop", "status": "not_checked_yet", "last_checked": None,
                                                            "stale": False, "days_since_check": None, "stale_after_days": 60, "live": None}
    claim(client)
    finish(client, cid, "no_leaks")
    r = client.get(f"/public/apps/{a['id']}").json()
    assert set(r) == {"repo", "status", "last_checked", "stale", "days_since_check", "stale_after_days", "live"}
    assert r["status"] == "no_known_leaks" and r["last_checked"] and r["stale"] is False and r["days_since_check"] == 0
    assert client.get(f"/public/apps/{uuid.uuid4()}").status_code == 404
    assert client.get("/public/apps/xyz").status_code == 404


def test_stats(client):
    assert client.get("/stats").json() == {"checks_completed": 0, "apps_monitored": 0, "leaks_found": 0, "fixes_proven": 0}
    u = sign_in(client, "owner@example.com")
    a, cid = verified_app(client, u)
    claim(client)
    finish(client, cid, "done", ["profiles", "orders"])
    r = client.post(f"/apps/{a['id']}/checks", headers=u.h)
    claim(client)
    finish(client, r.json()["check_id"], "needs_review", ["orders"], proof=False)
    s = client.get("/stats").json()
    assert s == {"checks_completed": 2, "apps_monitored": 1, "leaks_found": 3, "fixes_proven": 1}
