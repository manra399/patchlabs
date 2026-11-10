"""Native chat alerts. A workspace webhook that is a Slack incoming webhook, a Discord webhook or a Microsoft Teams incoming
webhook gets that platform's message format (title, severity counts, top findings, link to the report) instead of the
signed JSON event. Everything else keeps the signed JSON. Delivery always goes through core.send_webhook: same SSRF
checks (https, public addresses, pinned IP), 5 s timeout, no redirects, and the X-PatchLabs-Signature headers.

Detection (webhook_format = auto):
  slack    hooks.slack.com/services/... (and /workflows/...)
  discord  discord.com / discordapp.com (incl. ptb., canary.) /api/webhooks/...
  teams    *.webhook.office.com (incoming webhook connectors) and *.powerplatform.com/powerautomate/... (Teams Workflows)
A Teams Workflows URL on *.logic.azure.com can't be told apart from any other Logic App, so it needs webhook_format = teams.
"""
from urllib.parse import urlsplit

from core import SITE_URL, send_webhook, webhook_secret
from taxonomy import SEVERITY_RANK, findings_of

FORMATS = ("auto", "json", "slack", "discord", "teams")
SEVERITIES = ("critical", "high", "medium", "low", "info")
COLOURS = {"critical": 0xD1242F, "high": 0xE16F24, "medium": 0xD4A72C, "low": 0x4C8DD6, "info": 0x8C959F, None: 0x2EA44F}
TOP = 5


def detect(url):
    try:
        u = urlsplit(url or "")
        host, path = (u.hostname or "").lower(), u.path or ""
    except ValueError:
        return "json"
    if host == "hooks.slack.com" and path.startswith(("/services/", "/workflows/", "/triggers/")):
        return "slack"
    if host in ("discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com") and path.startswith("/api/webhooks/"):
        return "discord"
    if host.endswith(".webhook.office.com") or (host.endswith(".powerplatform.com") and "/powerautomate/" in path):
        return "teams"
    return "json"


def kind(url, fmt="auto"):
    return detect(url) if (fmt or "auto") == "auto" else fmt


# ---- the message -------------------------------------------------------------------------------------------------

def counts(summary):
    c = summary.get("counts") if isinstance(summary, dict) else None
    if isinstance(c, dict) and c:
        return {s: int(c.get(s) or 0) for s in SEVERITIES}
    out = {s: 0 for s in SEVERITIES}
    for f in findings_of(summary):
        s = str(f.get("severity") or "").lower()
        if s in out:
            out[s] += 1
    return out


def top_findings(summary, suppressed=()):
    sup = set(suppressed)

    def intended(f):  # a lab finding on a table the team marked as meant to be readable
        return f.get("line") == "lab" and str(f.get("object") or "").split(".")[-1] in sup
    fs = [f for f in findings_of(summary) if not intended(f)]
    fs.sort(key=lambda f: SEVERITY_RANK.get(str(f.get("severity") or "").lower(), 9))
    return [{"id": str(f.get("id") or ""), "severity": str(f.get("severity") or "").lower(), "title": str(f.get("title") or "")[:200],
             "object": str(f.get("object") or f.get("file") or "")[:200]} for f in fs[:TOP]]


def check_message(name, headline, status, summary, d, url, app_url):
    return {"title": f"PatchLabs: {name}", "headline": headline[:1].upper() + headline[1:] + ".", "status": status,
            "counts": counts(summary), "tables_leaking": list((summary or {}).get("tables_leaking") or []) if isinstance(summary, dict) else [],
            "new_leaks": d.get("new_leaks", []), "fixed": d.get("fixed", []), "suppressed": d.get("suppressed", []),
            "findings": top_findings(summary, d.get("suppressed", [])), "url": url, "app_url": app_url, "link_text": "Open the report"}


def test_message(workspace_name):
    return {"title": f"PatchLabs: webhooks for {workspace_name} are working", "status": "test",
            "headline": "This is a test message. Finished checks will post here with severity counts and the top findings.",
            "counts": {}, "tables_leaking": [], "new_leaks": [], "fixed": [], "suppressed": [], "findings": [],
            "url": f"{SITE_URL}/app/settings", "app_url": None, "link_text": "Open PatchLabs settings"}


def worst(m):
    return next((s for s in SEVERITIES if m["counts"].get(s)), "critical" if m["tables_leaking"] else None)


def lines(m):
    out = []
    if m["new_leaks"]:
        out.append("New leaks since the last check: " + ", ".join(m["new_leaks"]))
    elif m["tables_leaking"]:
        out.append("Tables leaking: " + ", ".join(m["tables_leaking"]))
    if m["fixed"]:
        out.append("Fixed since the last check: " + ", ".join(m["fixed"]))
    if m["suppressed"]:
        out.append("Marked as intended (no alert): " + ", ".join(m["suppressed"]))
    return out


def finding_line(f):
    return f"{f['id']} ({f['severity'] or 'unrated'}): {f['title']}" + (f" in {f['object']}" if f["object"] else "")


def counts_text(m):
    return ", ".join(f"{m['counts'][s]} {s}" for s in SEVERITIES if m["counts"].get(s)) or "no findings"


# ---- platform formats --------------------------------------------------------------------------------------------

def _slack_esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack(m):
    blocks = [{"type": "header", "text": {"type": "plain_text", "text": m["title"][:150], "emoji": False}},
              {"type": "section", "text": {"type": "mrkdwn", "text": _slack_esc("\n".join([m["headline"]] + lines(m)))[:3000]}}]
    if m["status"] not in ("test", "failed"):
        blocks.append({"type": "section", "fields": [{"type": "mrkdwn", "text": f"*{s.title()}*\n{m['counts'].get(s, 0)}"}
                                                     for s in SEVERITIES]})
    if m["findings"]:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": ("*Top findings*\n" + "\n".join(
            "• " + _slack_esc(finding_line(f)) for f in m["findings"]))[:3000]}})
    blocks.append({"type": "actions", "elements": [{"type": "button", "text": {"type": "plain_text", "text": m["link_text"]},
                                                    "url": m["url"]}]})
    return {"text": f"{m['title']}: {m['headline']} {m['url']}", "blocks": blocks, "unfurl_links": False}


def discord(m):
    desc = "\n".join([m["headline"]] + lines(m))
    if m["findings"]:
        desc += "\n\n**Top findings**\n" + "\n".join("• " + finding_line(f) for f in m["findings"])
    embed = {"title": m["title"][:256], "url": m["url"], "description": desc[:4096], "color": COLOURS[worst(m)],
             "footer": {"text": "PatchLabs"}}
    if m["status"] not in ("test", "failed"):
        embed["fields"] = [{"name": s.title(), "value": str(m["counts"].get(s, 0)), "inline": True} for s in SEVERITIES]
    return {"username": "PatchLabs", "content": None, "embeds": [embed],
            "allowed_mentions": {"parse": []}}  # repo names, labels and titles can never ping @everyone


def teams(m):
    body = [{"type": "TextBlock", "text": m["title"], "size": "Large", "weight": "Bolder", "wrap": True},
            {"type": "TextBlock", "text": "\n\n".join([m["headline"]] + lines(m)), "wrap": True}]
    if m["status"] not in ("test", "failed"):
        body.append({"type": "FactSet", "facts": [{"title": s.title(), "value": str(m["counts"].get(s, 0))} for s in SEVERITIES]})
    if m["findings"]:
        body.append({"type": "TextBlock", "text": "Top findings", "weight": "Bolder", "wrap": True})
        body += [{"type": "TextBlock", "text": "- " + finding_line(f), "wrap": True, "spacing": "Small"} for f in m["findings"]]
    card = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4", "body": body,
            "actions": [{"type": "Action.OpenUrl", "title": m["link_text"], "url": m["url"]}]}
    return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None,
                                                "content": card}]}


RENDER = {"slack": slack, "discord": discord, "teams": teams}


def deliver(c, w, event_payload, message):
    """Sends to the workspace webhook in its format; returns (kind, status code). Raises like send_webhook."""
    k = kind(w["webhook_url"], w.get("webhook_format"))
    body = RENDER[k](message) if k in RENDER else event_payload
    return k, send_webhook(w["webhook_url"], body, webhook_secret(c, w))
