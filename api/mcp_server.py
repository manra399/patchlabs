"""Remote MCP server at POST /mcp: JSON-RPC 2.0 over Streamable HTTP, stateless, plain JSON responses.
Tools: rls_check, headers_check, start_check, get_check (open); list_apps, run_check (need an X-API-Key header).
POST /mcp/public serves only the four open tools, for clients that connect without auth."""
import json

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import ValidationError

import core, monitor, posture, rls
from core import ORIGINS, ip_hash, pool

router = APIRouter()
PROTOCOLS = ("2025-06-18", "2025-11-25", "2025-03-26", "2024-11-05")
MAX_BODY, MAX_BATCH = 256 * 1024, 20
INSTRUCTIONS = ("PatchLabs finds personal-data leaks in Supabase / Lovable apps. rls_check is a free static scan of a public repo's "
                "migrations. headers_check grades a public site's HTTPS, certificate, security headers and cookies from one page load. "
                "start_check asks for the full lab check (the owner proves they own the repo with a one-line file) and get_check reads it. list_apps and "
                "run_check work on a workspace's monitored apps and need the workspace API key in the X-API-Key header.")


def hints(read_only, idempotent, open_world):
    """MCP tool annotations. No tool deletes or overwrites anything, so destructiveHint is always False."""
    return {"readOnlyHint": read_only, "destructiveHint": False, "idempotentHint": idempotent, "openWorldHint": open_world}


def schema(props, required):
    return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


REPO = {"type": "string", "description": "Public GitHub repo, e.g. owner/name or https://github.com/owner/name"}
TOOLS = [
    {"name": "rls_check", "title": "Static RLS check", "annotations": {"title": "Static RLS check", **hints(True, True, True)}, "inputSchema": schema({"repo": REPO}, ["repo"]),
     "description": "Free, no sign-up. Reads a public GitHub repo's supabase/migrations and lists row-level-security mistakes that could let strangers or other users read personal data (findings PL-001..PL-008 and PL-014, each with a fix). Static analysis only: it never connects to the live app or database. Suited to Supabase, Lovable and Bolt repos."},
    {"name": "headers_check", "title": "Security headers check", "annotations": {"title": "Security headers check", **hints(True, True, True)},
     "inputSchema": schema({"url": {"type": "string", "description": "A public site, e.g. https://app.example.com"}}, ["url"]),
     "description": "Grade a public site's HTTPS, TLS certificate, security headers and cookie flags from one load of its home page "
                    "(no sign-up). Returns findings PL-027..PL-036 with fixes."},
    {"name": "start_check", "title": "Request a full leak check", "annotations": {"title": "Request a full leak check", **hints(False, False, True)},
     "inputSchema": schema({"repo": REPO, "email": {"type": "string", "description": "Where the report goes"}}, ["repo", "email"]),
     "description": "Request the full lab check: the database is rebuilt from the repo with fake rows, leaks are proven as each kind of user, and a tested fix is written. Creates a check and emails the report address; nothing runs until the repo owner proves ownership with a one-line file. Returns a check id and link. Only call when the user asks for the full check and gives their email."},
    {"name": "get_check", "title": "Get a check", "annotations": {"title": "Get a check", **hints(True, True, False)}, "inputSchema": schema({"check_id": {"type": "string", "description": "The check id that start_check or run_check returned"}}, ["check_id"]),
     "description": "Read one check by id. Read-only, safe to call again to poll. Returns status: awaiting_verification (includes the one-line "
                    "file the repo owner must add, then nothing runs until they do), queued, running, done, no_leaks, needs_review or failed. "
                    "When finished it also returns the summary (each finding with severity, CWE/OWASP and days open), the plain-English "
                    "report (report_md) and the tested fix (fix_sql), plus the event timeline. Use after start_check or run_check; "
                    "poll every minute or so while queued or running."},
    {"name": "list_apps", "title": "List monitored apps", "annotations": {"title": "List monitored apps", **hints(True, True, False)}, "inputSchema": schema({}, []),
     "description": "List the apps monitored in the API key's workspace, each with its id (pass it as app_id to run_check), its last finished check (id and status, for get_check) and any open_check_id. Needs X-API-Key."},
    {"name": "run_check", "title": "Run a check on an app", "annotations": {"title": "Run a check on an app", **hints(False, False, True)}, "inputSchema": schema({"app_id": {"type": "string"}}, ["app_id"]),
     "description": "Queue a new check for a monitored app now (counts toward the plan's monthly runs). Needs X-API-Key."},
]
BY_NAME = {t["name"]: t for t in TOOLS}
# /mcp/public: the four tools that need no key, for clients that only support no-auth servers (the Claude connector directory).
PUBLIC = ("rls_check", "headers_check", "start_check", "get_check")
PUBLIC_TOOLS = [t for t in TOOLS if t["name"] in PUBLIC]
PUBLIC_INSTRUCTIONS = INSTRUCTIONS.split(" list_apps and")[0]


def call_tool(name, args, request, c):
    import app as main  # loaded by now; imported here to avoid a cycle
    if name == "rls_check":
        return rls.rls_check(c, str(args["repo"]), ip_hash(request))
    if name == "headers_check":
        return posture.headers_check(posture.HeadersCheck(url=str(args["url"])), request, c)
    if name == "start_check":
        return main.create_check(main.NewCheck(repo=str(args["repo"]), email=str(args["email"])), request, c)
    if name == "get_check":
        return main.get_check(str(args["check_id"]), c)
    key = core.api_key(request.headers.get("x-api-key", ""), c)
    if name == "list_apps":
        return {"apps": [monitor.app_view(c, a) for a in c.execute("SELECT * FROM apps WHERE workspace_id = %s ORDER BY created_at",
                                                                   (key["workspace_id"],)).fetchall()]}
    return monitor.v1_run(str(args["app_id"]), key, c)


def error(mid, code, message):
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def text_result(data, is_error=False):
    if is_error:
        return {"content": [{"type": "text", "text": data}], "isError": True}
    data = jsonable_encoder(data)
    return {"content": [{"type": "text", "text": json.dumps(data)}], "structuredContent": data, "isError": False}


def one(m, request, c, public=False):
    if not isinstance(m, dict) or m.get("jsonrpc") != "2.0" or not isinstance(m.get("method"), str):
        return error(m.get("id") if isinstance(m, dict) else None, -32600, "Invalid Request")
    mid, method, params = m.get("id"), m["method"], m.get("params") or {}
    if "id" not in m:  # notifications get no response
        return None
    if not isinstance(params, dict):
        return error(mid, -32602, "params must be an object")
    if method == "initialize":
        asked = params.get("protocolVersion")
        res = {"protocolVersion": asked if asked in PROTOCOLS else PROTOCOLS[0], "capabilities": {"tools": {"listChanged": False}},
               "serverInfo": {"name": "patchlabs", "title": "PatchLabs", "version": "2.1.0"},
               "instructions": PUBLIC_INSTRUCTIONS if public else INSTRUCTIONS}
    elif method == "ping":
        res = {}
    elif method == "tools/list":
        res = {"tools": PUBLIC_TOOLS if public else TOOLS}
    elif method == "tools/call":
        name, args = params.get("name"), params.get("arguments") or {}
        if name not in BY_NAME or (public and name not in PUBLIC):
            return error(mid, -32602, f"Unknown tool: {name}")
        missing = [k for k in BY_NAME[name]["inputSchema"]["required"] if not isinstance(args, dict) or args.get(k) in (None, "")]
        if missing:
            return error(mid, -32602, "Missing arguments: " + ", ".join(missing))
        try:
            res = text_result(call_tool(name, args, request, c))
        except HTTPException as e:
            res = text_result(str(e.detail), True)
        except ValidationError as e:
            res = text_result("; ".join(f"{'.'.join(map(str, x['loc']))}: {x['msg']}" for x in e.errors()), True)
    else:
        return error(mid, -32601, f"Method not found: {method}")
    return {"jsonrpc": "2.0", "id": mid, "result": res}


def handle(raw, request, public=False):
    try:
        msg = json.loads(raw or b"")
    except ValueError:
        return JSONResponse(error(None, -32700, "Parse error"))
    if isinstance(msg, list) and not msg:
        return JSONResponse(error(None, -32600, "Invalid Request"))
    if isinstance(msg, list) and len(msg) > MAX_BATCH:
        return JSONResponse(error(None, -32600, f"Batches are limited to {MAX_BATCH} requests"))
    with pool.connection() as c:
        if isinstance(msg, list):
            out = [r for r in (one(m, request, c, public) for m in msg) if r is not None]
        else:
            out = one(msg, request, c, public)
    return JSONResponse(out) if out else Response(status_code=202)


def refuse(status, message):
    return JSONResponse({**error(None, -32600, message), "detail": message}, status_code=status)


@router.post("/mcp")
async def mcp(request: Request):
    return await serve(request, False)


@router.post("/mcp/public")
async def mcp_public(request: Request):
    return await serve(request, True)


async def serve(request, public):
    origin = request.headers.get("origin")
    if origin and origin not in ORIGINS:  # browsers on other sites can't drive the server (DNS rebinding / CSRF)
        return refuse(403, "Origin not allowed")
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        return refuse(415, "Send JSON-RPC with Content-Type: application/json")
    if (request.headers.get("content-length") or "0").isdigit() and int(request.headers.get("content-length") or 0) > MAX_BODY:
        return refuse(413, "Request body too large")
    raw = bytearray()
    async for chunk in request.stream():
        raw += chunk
        if len(raw) > MAX_BODY:
            return refuse(413, "Request body too large")
    return await run_in_threadpool(handle, bytes(raw), request, public)


@router.get("/mcp")
@router.delete("/mcp")
@router.get("/mcp/public")
@router.delete("/mcp/public")
def mcp_no_stream():
    return JSONResponse({"detail": "This MCP server is stateless: POST JSON-RPC requests to /mcp."}, status_code=405, headers={"Allow": "POST"})
