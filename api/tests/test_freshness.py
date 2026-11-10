"""Badge freshness: stale after 2x the schedule interval (45 days without a schedule); stale never claims "no known leaks"."""
from datetime import datetime, timedelta, timezone

import pytest

import monitor
from helpers import A, claim, finish, sign_in, sql, verified_app


def age(cid, days):
    sql("UPDATE checks SET finished_at = %s WHERE id = %s", (datetime.now(timezone.utc) - timedelta(days=days, minutes=1), cid))


@pytest.mark.parametrize("schedule,limit", [("weekly", 14), ("monthly", 60), ("off", 45)])
def test_stale_thresholds(client, schedule, limit):
    u = sign_in(client, "owner@example.com")
    client.patch(f"/admin/workspaces/{u.wid}", json={"plan": "maker"}, headers=A)
    a, cid = verified_app(client, u, schedule=schedule)
    client.patch(f"/apps/{a['id']}", json={"badge_public": True}, headers=u.h)
    claim(client)
    finish(client, cid, "no_leaks")
    age(cid, limit - 1)
    assert "no known leaks" in client.get(f"/badge/{a['id']}.svg").text
    p = client.get(f"/public/apps/{a['id']}").json()
    assert p["status"] == "no_known_leaks" and p["stale"] is False and p["stale_after_days"] == limit
    age(cid, limit)
    svg = client.get(f"/badge/{a['id']}.svg").text
    assert f"last checked {limit} days ago" in svg and "#9f9f9f" in svg and "no known leaks" not in svg and "#2ea44f" not in svg
    p = client.get(f"/public/apps/{a['id']}").json()
    assert p == {"repo": "acme/shop", "status": "stale", "last_checked": p["last_checked"], "stale": True, "days_since_check": limit,
                 "stale_after_days": limit, "live": None}
    f = client.get(f"/apps/{a['id']}", headers=u.h).json()["freshness"]
    assert f == {"stale": True, "days_since_check": limit, "stale_after_days": limit}


def test_stale_fix_in_progress_and_recovery(client):
    u = sign_in(client, "owner@example.com")
    a, cid = verified_app(client, u)
    client.patch(f"/apps/{a['id']}", json={"badge_public": True}, headers=u.h)
    claim(client)
    finish(client, cid, "done", ["profiles"])
    age(cid, 90)
    assert "last checked 90 days ago" in client.get(f"/badge/{a['id']}.svg").text
    # a failed re-check doesn't refresh it
    r = client.post(f"/apps/{a['id']}/checks", headers=u.h)
    claim(client)
    finish(client, r.json()["check_id"], "failed")
    assert client.get(f"/public/apps/{a['id']}").json()["status"] == "stale"
    # a finished one does
    r = client.post(f"/apps/{a['id']}/checks", headers=u.h)
    claim(client)
    finish(client, r.json()["check_id"], "no_leaks")
    assert "no known leaks" in client.get(f"/badge/{a['id']}.svg").text
    assert client.get(f"/apps/{a['id']}", headers=u.h).json()["freshness"]["stale"] is False


def test_unit_freshness():
    now = datetime(2026, 11, 10, tzinfo=timezone.utc)
    assert monitor.freshness("weekly", now - timedelta(days=14), now)["stale"] is False
    assert monitor.freshness("weekly", now - timedelta(days=14, seconds=1), now)["stale"] is True
    assert monitor.freshness("off", None, now) == {"stale": False, "days_since_check": None, "stale_after_days": 45}
