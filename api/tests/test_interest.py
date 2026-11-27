"""Plan requests: the short form behind every paid-plan button; the founder activates by hand, first month free."""
from helpers import A, outbox, sign_in, sql


def test_early_access_form_is_stored_and_emails_the_founder(client):
    r = client.post("/early-access", json={"email": "ana@example.com", "name": "Ana", "company": "Studio A", "plan": "agency",
                                           "apps": "4-10", "note": "We ship 6 Lovable apps a month", "source": "/pricing",
                                           "site_url": "studio-a.com", "builders": "lovable supabase", "first_repo": "studio-a/shop",
                                           "will_pay": True})
    assert r.status_code == 201 and r.json()["ok"]
    assert sql("SELECT email, plan, apps, note FROM interest") == [
        {"email": "ana@example.com", "plan": "agency", "apps": "4-10", "note": "We ship 6 Lovable apps a month"}]
    assert sql("SELECT site_url, builders, first_repo, will_pay FROM interest") == [
        {"site_url": "studio-a.com", "builders": "lovable supabase", "first_repo": "studio-a/shop", "will_pay": True}]
    mails = [m for m in outbox() if "Plan request: agency" in m["subject"]]
    t = mails[0]["text"]
    assert len(mails) == 1 and "Founding agency places asked for: 1 of 500" in t and "£79/month founding" in t
    assert "Will pay after the free month: yes" in t and "First app to check: studio-a/shop" in t
    # the same email and plan again the same day: thanked, not stored twice, no second email
    assert client.post("/early-access", json={"email": "ANA@example.com", "plan": "agency"}).status_code == 201
    assert sql("SELECT count(*) AS n FROM interest")[0]["n"] == 1


def test_early_access_validation_honeypot_and_rate_limit(client):
    assert client.post("/early-access", json={"email": "not-an-email", "plan": "maker"}).status_code == 422
    assert client.post("/early-access", json={"email": "a@example.com", "plan": "platinum"}).status_code == 422
    assert client.post("/early-access", json={"email": "a@example.com", "plan": "maker", "apps": "lots"}).status_code == 422
    assert client.post("/early-access", json={"email": "a@example.com", "plan": "maker", "builders": "<b>x</b>"}).status_code == 422
    assert client.post("/early-access", json={"email": "bot@example.com", "plan": "maker", "website": "x"}).status_code == 201
    assert sql("SELECT count(*) AS n FROM interest")[0]["n"] == 0
    for i in range(5):
        assert client.post("/early-access", json={"email": f"p{i}@example.com", "plan": "free"}).status_code == 201
    assert client.post("/early-access", json={"email": "p9@example.com", "plan": "free"}).status_code == 429


def test_founding_places_count_agencies_once_and_admin_sees_the_list(client):
    sign_in(client, "someone@example.com")                     # an account alone doesn't use a founding place
    client.post("/early-access", json={"email": "studio@example.com", "plan": "agency"})
    client.post("/early-access", json={"email": "STUDIO@example.com", "plan": "maker"})
    client.post("/early-access", json={"email": "new@example.com", "plan": "enterprise", "company": "Big Co"})
    assert client.get("/early-access/places").json() == {"total": 500, "left": 499}
    assert client.get("/admin/interest").status_code == 401
    j = client.get("/admin/interest", headers=A).json()
    assert j["places_used"] == 1 and [r["plan"] for r in j["interest"]] == ["enterprise", "maker", "agency"]
