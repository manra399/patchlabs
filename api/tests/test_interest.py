"""Early access: the short form behind every plan button while PatchLabs is pre-launch."""
from helpers import A, outbox, sign_in, sql


def test_early_access_form_is_stored_and_emails_the_founder(client):
    r = client.post("/early-access", json={"email": "ana@example.com", "name": "Ana", "company": "Studio A", "plan": "agency",
                                           "apps": "4-10", "note": "We ship 6 Lovable apps a month", "source": "/pricing"})
    assert r.status_code == 201 and r.json()["ok"]
    assert sql("SELECT email, plan, apps, note FROM interest") == [
        {"email": "ana@example.com", "plan": "agency", "apps": "4-10", "note": "We ship 6 Lovable apps a month"}]
    mails = [m for m in outbox() if "Early access: agency" in m["subject"]]
    assert len(mails) == 1 and "Places used: 1 of 1000" in mails[0]["text"]
    # the same email and plan again the same day: thanked, not stored twice, no second email
    assert client.post("/early-access", json={"email": "ANA@example.com", "plan": "agency"}).status_code == 201
    assert sql("SELECT count(*) AS n FROM interest")[0]["n"] == 1


def test_early_access_validation_honeypot_and_rate_limit(client):
    assert client.post("/early-access", json={"email": "not-an-email", "plan": "maker"}).status_code == 422
    assert client.post("/early-access", json={"email": "a@example.com", "plan": "platinum"}).status_code == 422
    assert client.post("/early-access", json={"email": "a@example.com", "plan": "maker", "apps": "lots"}).status_code == 422
    assert client.post("/early-access", json={"email": "bot@example.com", "plan": "maker", "website": "x"}).status_code == 201
    assert sql("SELECT count(*) AS n FROM interest")[0]["n"] == 0
    for i in range(5):
        assert client.post("/early-access", json={"email": f"p{i}@example.com", "plan": "free"}).status_code == 201
    assert client.post("/early-access", json={"email": "p9@example.com", "plan": "free"}).status_code == 429


def test_places_count_accounts_and_list_once_and_admin_sees_the_list(client):
    sign_in(client, "both@example.com")
    client.post("/early-access", json={"email": "both@example.com", "plan": "maker"})
    client.post("/early-access", json={"email": "new@example.com", "plan": "enterprise", "company": "Big Co"})
    assert client.get("/early-access/places").json() == {"total": 1000, "left": 998}
    assert client.get("/admin/interest").status_code == 401
    j = client.get("/admin/interest", headers=A).json()
    assert j["places_used"] == 2 and [r["plan"] for r in j["interest"]] == ["enterprise", "maker"]
