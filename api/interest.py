"""Plan requests. Card payments aren't switched on: every paid-plan button opens a short form, the founder activates the
workspace by hand, the first month is free, and after that the customer gets a payment link for their price.
Decided 27 Nov 2026 (replaces "free for the first 1,000 users" from 11 Nov): Free stays free for one app; Maker and
Agency show standard prices plus a founding price kept for as long as the customer stays; the Agency founding price is
for the first 500 agencies.

Public:  POST /early-access, GET /early-access/places
Admin:   GET /admin/interest   (Bearer ADMIN_TOKEN)
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from core import ADMIN_TOKEN, EMAIL_RE, FOUNDER_EMAIL, bearer, db, ip_hash, mail

router = APIRouter()
PER_IP_PER_DAY = 5
FOUNDING_PLACES = 500   # agencies that get the founding Agency price
PRICES = {"maker": "£15/month founding (standard £29)", "agency": "£79/month founding for 10 apps, +£8 per extra app (standard £149, +£12)",
          "free": "free, 1 app", "enterprise": "custom"}


class Interest(BaseModel):
    email: str = Field(pattern=EMAIL_RE, max_length=254)
    name: str | None = Field(default=None, max_length=120)
    company: str | None = Field(default=None, max_length=160)
    plan: str = Field(pattern=r"^(free|maker|agency|enterprise)$")
    apps: str | None = Field(default=None, pattern=r"^(1|2-3|4-10|11-50|50\+)$")
    note: str | None = Field(default=None, max_length=2000)
    source: str | None = Field(default=None, max_length=200)
    site_url: str | None = Field(default=None, max_length=200)
    builders: str | None = Field(default=None, pattern=r"^[a-z ]{0,120}$")
    first_repo: str | None = Field(default=None, max_length=200)
    will_pay: bool | None = None
    website: str | None = Field(default=None, max_length=200)   # honeypot: people never see it, bots fill it


def taken(c):
    """Founding Agency places asked for so far, counted once by email."""
    return c.execute("SELECT count(DISTINCT lower(email)) AS n FROM interest WHERE plan = 'agency'").fetchone()["n"]


@router.post("/early-access", status_code=201)
def early_access(body: Interest, request: Request, c=Depends(db)):
    thanks = {"ok": True, "detail": "Thanks, we've got your request. We'll reply within a day."}
    if body.website:
        return thanks
    iph = ip_hash(request)
    if c.execute("SELECT count(*) AS n FROM interest WHERE ip_hash = %s AND created_at > now() - interval '1 day'",
                 (iph,)).fetchone()["n"] >= PER_IP_PER_DAY:
        raise HTTPException(429, "We've had a few of these from your network today. Try again tomorrow.")
    email = body.email.strip()
    if c.execute("SELECT 1 FROM interest WHERE lower(email) = lower(%s) AND plan = %s AND created_at > now() - interval '1 day'",
                 (email, body.plan)).fetchone():
        return thanks
    clean = lambda s: (s or "").strip() or None
    c.execute("INSERT INTO interest (id, email, name, company, plan, apps, note, source, ip_hash, site_url, builders, first_repo, will_pay) "
              "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
              (uuid.uuid4(), email, clean(body.name), clean(body.company), body.plan, body.apps, clean(body.note),
               clean(body.source), iph, clean(body.site_url), clean(body.builders), clean(body.first_repo), body.will_pay))
    pay = {True: "yes", False: "not sure yet", None: "-"}[body.will_pay]
    mail(FOUNDER_EMAIL, f"Plan request: {body.plan} from {email}",
         f"Plan: {body.plan} ({PRICES[body.plan]})\nEmail: {email}\nName: {clean(body.name) or '-'}\n"
         f"Company: {clean(body.company) or '-'}\nWebsite: {clean(body.site_url) or '-'}\nApps: {body.apps or '-'}\n"
         f"Built with: {clean(body.builders) or '-'}\nFirst app to check: {clean(body.first_repo) or '-'}\n"
         f"Will pay after the free month: {pay}\nFrom page: {clean(body.source) or '-'}\n\n"
         f"What they said:\n{clean(body.note) or '(nothing)'}\n\n"
         f"Founding agency places asked for: {taken(c)} of {FOUNDING_PLACES}.\n\n"
         f"To activate: set the plan on their workspace in /admin once they've signed in, then reply to them.\n")
    return thanks


@router.get("/early-access/places")
def places(c=Depends(db)):
    return {"total": FOUNDING_PLACES, "left": max(0, FOUNDING_PLACES - taken(c))}


@router.get("/admin/interest", dependencies=[Depends(bearer(ADMIN_TOKEN))])
def admin_interest(c=Depends(db)):
    return {"interest": c.execute("SELECT id, created_at, email, name, company, plan, apps, note, source, site_url, builders, "
                                  "first_repo, will_pay FROM interest ORDER BY created_at DESC LIMIT 500").fetchall(),
            "places_used": taken(c), "places": FOUNDING_PLACES}
