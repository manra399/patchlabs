"""Early access: PatchLabs is pre-launch, so paid plans aren't on sale yet. Every plan button on the site opens a short
form; this stores it and emails the founder inbox. Decided 11 Nov 2026: free for the first 1,000 users, founding-member
pricing when paid plans start, enterprises talk to us.

Public:  POST /early-access
Admin:   GET /admin/interest   (Bearer ADMIN_TOKEN)
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from core import ADMIN_TOKEN, EMAIL_RE, FOUNDER_EMAIL, bearer, db, ip_hash, mail

router = APIRouter()
PER_IP_PER_DAY = 5
FREE_PLACES = 1000


class Interest(BaseModel):
    email: str = Field(pattern=EMAIL_RE, max_length=254)
    name: str | None = Field(default=None, max_length=120)
    company: str | None = Field(default=None, max_length=160)
    plan: str = Field(pattern=r"^(free|maker|agency|enterprise)$")
    apps: str | None = Field(default=None, pattern=r"^(1|2-3|4-10|11-50|50\+)$")
    note: str | None = Field(default=None, max_length=2000)
    source: str | None = Field(default=None, max_length=200)
    website: str | None = Field(default=None, max_length=200)   # honeypot: people never see it, bots fill it


def taken(c):
    """Places used so far: everyone with an account plus everyone on the list, counted once by email."""
    return c.execute("SELECT count(*) AS n FROM (SELECT lower(email) FROM users UNION SELECT lower(email) FROM interest) e").fetchone()["n"]


@router.post("/early-access", status_code=201)
def early_access(body: Interest, request: Request, c=Depends(db)):
    thanks = {"ok": True, "detail": "Thanks, you're on the list. We'll email you before anything changes."}
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
    c.execute("INSERT INTO interest (id, email, name, company, plan, apps, note, source, ip_hash) "
              "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
              (uuid.uuid4(), email, clean(body.name), clean(body.company), body.plan, body.apps, clean(body.note),
               clean(body.source), iph))
    n = taken(c)
    mail(FOUNDER_EMAIL, f"Early access: {body.plan} from {email}",
         f"Plan: {body.plan}\nEmail: {email}\nName: {clean(body.name) or '-'}\nCompany: {clean(body.company) or '-'}\n"
         f"Apps: {body.apps or '-'}\nFrom page: {clean(body.source) or '-'}\n\nWhat they said:\n{clean(body.note) or '(nothing)'}\n\n"
         f"Places used: {n} of {FREE_PLACES}.\n")
    return thanks


@router.get("/early-access/places")
def places(c=Depends(db)):
    return {"total": FREE_PLACES, "left": max(0, FREE_PLACES - taken(c))}


@router.get("/admin/interest", dependencies=[Depends(bearer(ADMIN_TOKEN))])
def admin_interest(c=Depends(db)):
    return {"interest": c.execute("SELECT id, created_at, email, name, company, plan, apps, note, source FROM interest "
                                  "ORDER BY created_at DESC LIMIT 500").fetchall(), "places_used": taken(c), "places": FREE_PLACES}
