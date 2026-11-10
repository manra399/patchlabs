"""Support tickets. A ticket belongs to a workspace, so every member sees it; the founder answers them as admin.

Customers (session, workspace member; everyone else gets 404):
  GET|POST /workspaces/{wid}/support/tickets     list (with counts per status) / raise a ticket
  GET      /support/tickets/{tid}                the ticket and its thread (internal notes are never included)
  POST     /support/tickets/{tid}/messages       reply; reopens a ticket that was waiting, resolved or closed
  POST     /support/tickets/{tid}/close          close it
Admin (Bearer ADMIN_TOKEN):
  GET          /admin/support/tickets            every workspace, filters: status, category, priority, workspace_id, q
  GET|PATCH    /admin/support/tickets/{tid}      the full thread with notes / change status or priority
  POST         /admin/support/tickets/{tid}/messages   reply (emails the customer) or add an internal note

Statuses: open → waiting_on_customer (after a support reply) → resolved / closed. A customer reply always reopens.
User text is stored without control characters (newlines kept in messages) and is never rendered as HTML: email HTML
escapes everything (core.html_email) and the pages escape it too.
"""
import re, uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

import audit
from core import (ADMIN_TOKEN, FOUNDER_EMAIL, SITE_URL, as_uuid, bearer, clean_text, client_apps, current_user, db, mail, mask_email,
                  may_see_app, membership, recent, record, require)

router = APIRouter()
ADMIN = [Depends(bearer(ADMIN_TOKEN))]

SUBJECT_MAX, BODY_MAX = 200, 10_000
TICKETS_PER_USER_PER_DAY, REPLIES_PER_USER_PER_DAY = 20, 200
CATEGORIES = {"billing": "Billing", "finding": "A finding", "fix": "A fix", "account": "Account", "bug": "Bug", "other": "Other"}
PRIORITIES = ("normal", "urgent")
STATUSES = ("open", "waiting_on_customer", "resolved", "closed")
SUPPORT_LABEL, FORMER = "PatchLabs support", "a former member"

# Like core.CONTROL, but messages keep their line breaks (\n); tabs become spaces and \r\n becomes \n first.
BODY_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2066-\u2069]")


def clean_body(s):
    s = (s or "").replace("\r\n", "\n").replace("\r", "\n").replace("\t", "    ")
    s = BODY_CONTROL.sub("", s)
    s = re.sub(r"[ \u00a0]+\n", "\n", s)
    return re.sub(r"\n{4,}", "\n\n\n", s).strip()


def subject_of(raw):
    s = clean_text(raw)
    if not s:
        raise HTTPException(422, "Add a subject.")
    if len(s) > SUBJECT_MAX:
        raise HTTPException(422, f"Keep the subject to {SUBJECT_MAX} characters.")
    return s


def body_of(raw):
    b = clean_body(raw)
    if not b:
        raise HTTPException(422, "Write a message first.")
    if len(b) > BODY_MAX:
        raise HTTPException(422, f"Keep each message to {BODY_MAX:,} characters.")
    return b


def pick(value, allowed, sentence):
    if value not in allowed:
        raise HTTPException(422, sentence)
    return value


STATUS_SENTENCE = "Status must be open, waiting_on_customer, resolved or closed."


# ---- reading -----------------------------------------------------------------------------------------------------

TICKET_SQL = ("SELECT t.*, w.name AS workspace_name, w.plan AS workspace_plan, a.repo AS app_repo, u.email AS user_email, "
              "u.name AS user_name FROM support_tickets t JOIN workspaces w ON w.id = t.workspace_id "
              "LEFT JOIN apps a ON a.id = t.app_id LEFT JOIN users u ON u.id = t.user_id")
LIST_SQL = ("SELECT t.id, t.number, t.workspace_id, t.subject, t.category, t.priority, t.status, t.created_at, t.updated_at, "
            "t.closed_at, t.app_id, t.user_id, a.repo AS app_repo, u.name AS user_name, u.email AS user_email, "
            "w.name AS workspace_name, w.plan AS workspace_plan, "
            "(SELECT count(*) FROM support_messages m WHERE m.ticket_id = t.id AND m.kind = 'message') AS message_count, "
            "(SELECT m.author FROM support_messages m WHERE m.ticket_id = t.id AND m.kind = 'message' "
            " ORDER BY m.created_at DESC LIMIT 1) AS last_from "
            "FROM support_tickets t JOIN workspaces w ON w.id = t.workspace_id LEFT JOIN apps a ON a.id = t.app_id "
            "LEFT JOIN users u ON u.id = t.user_id")


def who(user_id, name, email, masked_for=None):
    """A person's label. For a client (masked_for = their user id) teammates' emails are masked, like on public pages."""
    if not user_id:
        return FORMER
    if masked_for and user_id != masked_for:
        return name or mask_email(email)
    return name or email


def ticket_row(c, tid):
    t = c.execute(TICKET_SQL + " WHERE t.id = %s", (as_uuid(tid, "Ticket not found."),)).fetchone()
    if not t:
        raise HTTPException(404, "Ticket not found.")
    return t


def member_ticket(c, user, tid, write=False):
    """Members of the ticket's workspace; a client only for tickets about an app shared with them. To anyone else the ticket
    doesn't exist. Viewers read; members and above, and clients on their tickets, write. Sets t["masked_for"] for clients."""
    t = ticket_row(c, tid)
    m = c.execute("SELECT role FROM workspace_members WHERE workspace_id = %s AND user_id = %s", (t["workspace_id"], user["id"])).fetchone()
    if not m or (m["role"] == "client" and not (t["app_id"] and may_see_app(c, "client", t["workspace_id"], user["id"], t["app_id"]))):
        raise HTTPException(404, "Ticket not found.")
    if write:
        require(m["role"], "support")
    return {**t, "masked_for": user["id"] if m["role"] == "client" else None}


def messages(c, tid, admin=False, masked_for=None):
    rows = c.execute("SELECT m.id, m.author, m.kind, m.body, m.created_at, m.user_id, u.name, u.email FROM support_messages m "
                     "LEFT JOIN users u ON u.id = m.user_id WHERE m.ticket_id = %s" + ("" if admin else " AND m.kind <> 'note'") +
                     " ORDER BY m.created_at, m.id", (tid,)).fetchall()
    out = []
    for r in rows:
        m = {"id": r["id"], "author": r["author"], "kind": r["kind"], "body": r["body"], "created_at": r["created_at"],
             "by": SUPPORT_LABEL if r["author"] == "support" else who(r["user_id"], r["name"], r["email"], masked_for)}
        if admin and r["author"] == "customer":
            m["by_email"] = r["email"]
        out.append(m)
    return out


def summary(t, admin=False, masked_for=None):
    out = {k: t[k] for k in ("id", "number", "workspace_id", "subject", "category", "priority", "status", "created_at", "updated_at",
                             "closed_at")}
    out["app"] = {"id": t["app_id"], "repo": t["app_repo"]} if t["app_id"] else None
    out["created_by"] = who(t["user_id"], t["user_name"], t["user_email"], masked_for)
    out.update(created_by_id=t["user_id"], message_count=t["message_count"], last_from=t["last_from"])
    if admin:
        out.update(workspace_name=t["workspace_name"], workspace_plan=t["workspace_plan"], created_by_email=t["user_email"],
                   needs_reply=t["status"] == "open" and t["last_from"] == "customer")
    return out


def ticket_view(c, t, admin=False, masked_for=None):
    msgs = messages(c, t["id"], admin, masked_for)
    said = [m for m in msgs if m["kind"] == "message"]
    t = {**t, "message_count": len(said), "last_from": said[-1]["author"] if said else None}
    return {**summary(t, admin, masked_for), "messages": msgs}


def status_counts(c, where="", params=()):
    rows = c.execute(f"SELECT status, count(*) AS n FROM support_tickets {where} GROUP BY status", params).fetchall()
    out = {s: 0 for s in STATUSES}
    out.update({r["status"]: r["n"] for r in rows})
    return out


# ---- writing -----------------------------------------------------------------------------------------------------

def add_message(c, tid, author, kind, body, user_id=None):
    # clock_timestamp, not now(): a reply and the status change it causes share a transaction but must stay in order
    c.execute("INSERT INTO support_messages (id, ticket_id, author, kind, user_id, body, created_at) "
              "VALUES (%s, %s, %s, %s, %s, %s, clock_timestamp())", (uuid.uuid4(), tid, author, kind, user_id, body))


def set_status(c, t, status, author, user_id=None, event=True):
    c.execute("UPDATE support_tickets SET status = %s, updated_at = now(), "
              "closed_at = CASE WHEN %s IN ('resolved', 'closed') THEN coalesce(closed_at, now()) END WHERE id = %s",
              (status, status, t["id"]))
    if event:
        add_message(c, t["id"], author, "status", status, user_id)


def touch(c, t):
    c.execute("UPDATE support_tickets SET updated_at = now() WHERE id = %s", (t["id"],))


# ---- email -------------------------------------------------------------------------------------------------------

def customer_link(t):
    return f"{SITE_URL}/app/support?id={t['id']}"


def admin_link(t):
    return f"{SITE_URL}/admin?ticket={t['id']}"


def tag(t, admin=False):
    return f"{'URGENT ' if admin and t['priority'] == 'urgent' else ''}[PatchLabs #{t['number']}] {t['subject']}"


def customer_recipients(c, t):
    """Whoever raised the ticket while they are still in the workspace; otherwise the workspace's owners."""
    if t["user_id"] and c.execute("SELECT 1 FROM workspace_members WHERE workspace_id = %s AND user_id = %s",
                                  (t["workspace_id"], t["user_id"])).fetchone():
        return [t["user_email"]]
    return [r["email"] for r in c.execute("SELECT u.email FROM workspace_members m JOIN users u ON u.id = m.user_id "
                                          "WHERE m.workspace_id = %s AND m.role = 'owner' ORDER BY m.created_at", (t["workspace_id"],))]


def email_new_ticket(t, message):
    facts = [f"Category: {CATEGORIES[t['category']]}", f"Priority: {t['priority']}"] + ([f"App: {t['app_repo']}"] if t["app_id"] else [])
    mail(FOUNDER_EMAIL, f"New ticket: {tag(t, admin=True)}",
         f"New support ticket #{t['number']} from {t['user_email']} ({t['workspace_name']}, {t['workspace_plan']} plan).\n\n"
         + "\n".join(facts) + f"\nSubject: {t['subject']}\n\n{message}\n\nAnswer it in the admin page:\n{admin_link(t)}")
    mail(t["user_email"], f"We've got your ticket: {tag(t)}",
         f"Thanks. We've got your support ticket #{t['number']}: {t['subject']}\n\nWe reply within a day, by email and on the ticket "
         f"page. Everyone in your {t['workspace_name']} workspace can see the ticket and add to it:\n{customer_link(t)}\n\n"
         f"Your message:\n\n{message}\n\nPatchLabs")


def email_support_reply(c, t, body, status):
    note = {"resolved": "We've marked this ticket resolved. If anything is still wrong, reply on the ticket page and it opens again.",
            "closed": "We've closed this ticket. Reply on the ticket page if you need us again and it opens again."}.get(status)
    for to in customer_recipients(c, t):
        mail(to, f"Re: {tag(t)}",
             f"PatchLabs support replied to your ticket #{t['number']}: {t['subject']}\n\n{body}\n\n" + (f"{note}\n\n" if note else "")
             + f"See the whole thread and reply here (your team sees it too):\n{customer_link(t)}\n\nPatchLabs")


def email_customer_reply(t, user, body, reopened):
    mail(FOUNDER_EMAIL, f"Re: {tag(t, admin=True)}",
         f"{user['email']} replied on ticket #{t['number']} ({t['workspace_name']})" + (", which opens it again" if reopened else "")
         + f".\n\n{body}\n\nAnswer it in the admin page:\n{admin_link(t)}")


# ---- customers ---------------------------------------------------------------------------------------------------

class NewTicket(BaseModel):
    subject: str = Field(max_length=2_000)
    category: str = Field(max_length=40)
    priority: str = Field(default="normal", max_length=40)
    app_id: str | None = Field(default=None, max_length=100)
    message: str = Field(max_length=40_000)


class Reply(BaseModel):
    body: str = Field(max_length=40_000)


@router.get("/workspaces/{wid}/support/tickets")
def list_tickets(wid: str, status: str | None = Query(default=None, max_length=40), user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid)
    where, params = ["t.workspace_id = %s"], [w["id"]]
    masked, mine = None, None
    if w["role"] == "client":  # only tickets about the apps shared with them
        mine, masked = client_apps(c, w["id"], user["id"]), user["id"]
        where.append("t.app_id = ANY(%s)")
        params.append(mine)
    if status == "active":
        where.append("t.status IN ('open', 'waiting_on_customer')")
    elif status:
        where.append("t.status = %s")
        params.append(pick(status, STATUSES, STATUS_SENTENCE))
    rows = c.execute(LIST_SQL + " WHERE " + " AND ".join(where) + " ORDER BY t.updated_at DESC LIMIT 200", params).fetchall()
    scope = ("WHERE workspace_id = %s AND app_id = ANY(%s)", (w["id"], mine)) if masked else ("WHERE workspace_id = %s", (w["id"],))
    return {"tickets": [summary(t, masked_for=masked) for t in rows], "counts": status_counts(c, *scope)}


@router.post("/workspaces/{wid}/support/tickets", status_code=201)
def create_ticket(wid: str, body: NewTicket, user=Depends(current_user), c=Depends(db)):
    w = membership(c, user, wid, perm="support")
    subject, message = subject_of(body.subject), body_of(body.message)
    category = pick(body.category, CATEGORIES, "Pick a category: billing, a finding, a fix, account, bug or other.")
    priority = pick(body.priority or "normal", PRIORITIES, "Priority is normal or urgent.")
    app_id = None
    if body.app_id:
        a = c.execute("SELECT id FROM apps WHERE id = %s AND workspace_id = %s", (as_uuid(body.app_id, "App not found."), w["id"])).fetchone()
        if not a:
            raise HTTPException(422, "That app isn't in this workspace.")
        app_id = a["id"]
    if w["role"] == "client" and not (app_id and may_see_app(c, "client", w["id"], user["id"], app_id)):
        raise HTTPException(422, "Pick the app this ticket is about: one of the apps shared with you.")
    if recent(c, "support_ticket", user["id"]) >= TICKETS_PER_USER_PER_DAY:
        raise HTTPException(429, f"That's {TICKETS_PER_USER_PER_DAY} tickets from you today. Reply on an open ticket, "
                                 f"or email {FOUNDER_EMAIL}.")
    record(c, "support_ticket", user["id"])
    tid = uuid.uuid4()
    c.execute("INSERT INTO support_tickets (id, workspace_id, user_id, app_id, subject, category, priority) VALUES (%s, %s, %s, %s, %s, %s, %s)",
              (tid, w["id"], user["id"], app_id, subject, category, priority))
    add_message(c, tid, "customer", "message", message, user["id"])
    t = ticket_row(c, tid)
    audit.log(c, w["id"], "ticket.raised", user, target={"type": "ticket", "id": tid, "label": f"#{t['number']}"},
              detail={"number": t["number"], "category": category, "priority": priority, "app_id": app_id})
    email_new_ticket(t, message)
    return ticket_view(c, t, masked_for=user["id"] if w["role"] == "client" else None)


@router.get("/support/tickets/{tid}")
def get_ticket(tid: str, user=Depends(current_user), c=Depends(db)):
    t = member_ticket(c, user, tid)
    return ticket_view(c, t, masked_for=t["masked_for"])


@router.post("/support/tickets/{tid}/messages", status_code=201)
def reply(tid: str, body: Reply, user=Depends(current_user), c=Depends(db)):
    t = member_ticket(c, user, tid, write=True)
    text = body_of(body.body)
    if recent(c, "support_reply", user["id"]) >= REPLIES_PER_USER_PER_DAY:
        raise HTTPException(429, f"That's {REPLIES_PER_USER_PER_DAY} replies from you today. Email {FOUNDER_EMAIL} if it can't wait.")
    record(c, "support_reply", user["id"])
    add_message(c, t["id"], "customer", "message", text, user["id"])
    reopened = t["status"] in ("resolved", "closed")
    set_status(c, t, "open", "customer", user["id"], event=reopened)  # a customer reply always puts the ticket back with us
    email_customer_reply(t, user, text, reopened)
    return ticket_view(c, ticket_row(c, t["id"]), masked_for=t["masked_for"])


@router.post("/support/tickets/{tid}/close")
def close(tid: str, user=Depends(current_user), c=Depends(db)):
    t = member_ticket(c, user, tid, write=True)
    if t["status"] != "closed":
        set_status(c, t, "closed", "customer", user["id"])
    return ticket_view(c, ticket_row(c, t["id"]), masked_for=t["masked_for"])


# ---- admin -------------------------------------------------------------------------------------------------------

class AdminReply(BaseModel):
    body: str = Field(max_length=40_000)
    internal: bool = False
    status: str | None = Field(default=None, max_length=40)


class AdminPatch(BaseModel):
    status: str | None = Field(default=None, max_length=40)
    priority: str | None = Field(default=None, max_length=40)


@router.get("/admin/support/tickets", dependencies=ADMIN)
def admin_list(status: str | None = Query(default=None, max_length=40), category: str | None = Query(default=None, max_length=40),
               priority: str | None = Query(default=None, max_length=40), workspace_id: str | None = Query(default=None, max_length=100),
               q: str | None = Query(default=None, max_length=200), c=Depends(db)):
    where, params = [], []
    if status == "active":
        where.append("t.status IN ('open', 'waiting_on_customer')")
    elif status:
        where.append("t.status = %s")
        params.append(pick(status, STATUSES, STATUS_SENTENCE))
    if category:
        where.append("t.category = %s")
        params.append(pick(category, CATEGORIES, "Unknown category."))
    if priority:
        where.append("t.priority = %s")
        params.append(pick(priority, PRIORITIES, "Priority is normal or urgent."))
    if workspace_id:
        where.append("t.workspace_id = %s")
        params.append(as_uuid(workspace_id, "Workspace not found."))
    q = clean_text(q)
    if q:
        num = q.lstrip("#")
        where.append("(strpos(lower(t.subject), lower(%s)) > 0 OR strpos(lower(coalesce(u.email, '')), lower(%s)) > 0 "
                     "OR strpos(lower(w.name), lower(%s)) > 0" + (" OR t.number = %s" if num.isdigit() and len(num) < 15 else "") + ")")
        params += [q, q, q] + ([int(num)] if num.isdigit() and len(num) < 15 else [])
    rows = c.execute(LIST_SQL + (" WHERE " + " AND ".join(where) if where else "") +
                     " ORDER BY CASE t.status WHEN 'open' THEN 0 WHEN 'waiting_on_customer' THEN 1 WHEN 'resolved' THEN 2 ELSE 3 END, "
                     "(t.priority = 'urgent') DESC, t.updated_at DESC LIMIT 500", params).fetchall()
    return {"tickets": [summary(t, admin=True) for t in rows], "counts": status_counts(c)}


@router.get("/admin/support/tickets/{tid}", dependencies=ADMIN)
def admin_get(tid: str, c=Depends(db)):
    return ticket_view(c, ticket_row(c, tid), admin=True)


@router.post("/admin/support/tickets/{tid}/messages", status_code=201, dependencies=ADMIN)
def admin_reply(tid: str, body: AdminReply, c=Depends(db)):
    t = ticket_row(c, tid)
    text = body_of(body.body)
    status = pick(body.status, STATUSES, STATUS_SENTENCE) if body.status else None
    if body.internal:  # a note for us: no email, and the customer's "updated" time doesn't move
        add_message(c, t["id"], "support", "note", text)
        if status and status != t["status"]:
            set_status(c, t, status, "support")
    else:
        add_message(c, t["id"], "support", "message", text)
        new = status or "waiting_on_customer"
        set_status(c, t, new, "support", event=new in ("resolved", "closed") and new != t["status"])
        email_support_reply(c, t, text, new)
    return ticket_view(c, ticket_row(c, t["id"]), admin=True)


@router.patch("/admin/support/tickets/{tid}", dependencies=ADMIN)
def admin_patch(tid: str, body: AdminPatch, c=Depends(db)):
    t = ticket_row(c, tid)
    if body.status and body.status != t["status"]:
        set_status(c, t, pick(body.status, STATUSES, STATUS_SENTENCE), "support")
    if body.priority:
        c.execute("UPDATE support_tickets SET priority = %s WHERE id = %s",
                  (pick(body.priority, PRIORITIES, "Priority is normal or urgent."), t["id"]))
    return ticket_view(c, ticket_row(c, t["id"]), admin=True)


# ---- data export (GET /me/export) --------------------------------------------------------------------------------

def export(c, uid):
    """Tickets the user raised or wrote in: their own messages, plus our replies and status changes on tickets they raised.
    Teammates' messages and internal notes are left out. Deleting the account keeps workspace tickets anonymised
    (user_id is set to NULL, shown as "a former member"); tickets of a workspace deleted with the account go with it."""
    tickets = c.execute("SELECT t.id, t.number, t.workspace_id, t.subject, t.category, t.priority, t.status, t.app_id, t.created_at, "
                        "t.updated_at, t.closed_at, (t.user_id IS NOT DISTINCT FROM %(u)s) AS raised_by_you FROM support_tickets t "
                        "WHERE t.user_id = %(u)s OR EXISTS (SELECT 1 FROM support_messages m WHERE m.ticket_id = t.id AND m.user_id = %(u)s) "
                        "ORDER BY t.created_at", {"u": uid}).fetchall()
    for t in tickets:
        t["messages"] = c.execute("SELECT m.author, m.kind, m.body, m.created_at, (m.user_id IS NOT DISTINCT FROM %(u)s) AS written_by_you "
                                  "FROM support_messages m WHERE m.ticket_id = %(t)s AND m.kind <> 'note' "
                                  "AND (m.user_id = %(u)s OR (%(raised)s AND m.author = 'support')) ORDER BY m.created_at",
                                  {"u": uid, "t": t["id"], "raised": t["raised_by_you"]}).fetchall()
    return tickets
