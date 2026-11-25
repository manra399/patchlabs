"""Daily fix-agent spend cap: over the cap, /worker/claim starts nothing, and the founder gets one email per day."""
import app as appmod
from helpers import A, W, claim, finish, outbox, sign_in, sql, verified_app


def test_claim_pauses_over_daily_budget(client, monkeypatch):
    monkeypatch.setattr(appmod, "DAILY_BUDGET_USD", 5.0)
    u = sign_in(client, "owner@example.com")
    client.patch(f"/admin/workspaces/{u.wid}", json={"plan": "agency"}, headers=A)
    _, cid1 = verified_app(client, u, "acme/one")
    _, cid2 = verified_app(client, u, "acme/two")
    _, cid3 = verified_app(client, u, "acme/three")

    assert claim(client)["id"] == str(cid1)
    finish(client, cid1, "no_leaks", cost=3.0)          # $3 today: under the cap
    assert claim(client)["id"] == str(cid2)
    finish(client, cid2, "no_leaks", cost=2.5)          # $5.50 today: over the cap

    r = client.post("/worker/claim", headers=W).json()
    assert r == {"check": None, "paused": "daily_budget"}
    assert client.post("/worker/claim", headers=W).json()["check"] is None
    alerts = [m for m in outbox() if "daily spend cap" in m["subject"]]
    assert len(alerts) == 1 and "$5.50" in alerts[0]["text"] and "1 check(s) are queued" in alerts[0]["text"]
    assert sql("SELECT status FROM checks WHERE id = %s", (cid3,))[0]["status"] == "queued"

    # spend from yesterday doesn't count: the queue moves again
    sql("UPDATE checks SET finished_at = now() - interval '2 days' WHERE id IN (%s, %s)", (cid1, cid2))
    assert claim(client)["id"] == str(cid3)


def test_budget_zero_turns_cap_off(client, monkeypatch):
    monkeypatch.setattr(appmod, "DAILY_BUDGET_USD", 0.0)
    u = sign_in(client, "owner@example.com")
    client.patch(f"/admin/workspaces/{u.wid}", json={"plan": "agency"}, headers=A)
    _, cid1 = verified_app(client, u, "acme/one")
    _, cid2 = verified_app(client, u, "acme/two")
    claim(client)
    finish(client, cid1, "no_leaks", cost=999.0)
    assert claim(client)["id"] == str(cid2)
