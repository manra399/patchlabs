"""Remote MCP server at POST /mcp: JSON-RPC 2.0 over Streamable HTTP, stateless, plain JSON responses.
Tools: rls_check, start_check, get_check (open); list_apps, run_check (need an X-API-Key header)."""
import json

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import ValidationError

import core, monitor, rls
from core import ORIGINS, ip_hash, pool

router = APIRouter()
PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
MAX_BODY, MAX_BATCH = 256 * 1024, 20
INSTRUCTIONS = ("PatchLabs finds personal-data leaks in Supabase / Lovable apps. rls_check is a free static scan of a public repo's "
                "migrations. start_check asks for the full lab check (the owner must verify the repo by email). list_apps and "
                "run_check work on a workspace's monitored apps and need the workspace API key in the X-API-Key header.")


def schema(props, required):
    return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


REPO = {"type": "string", "description": "Public GitHub repo, e.g. owner/name or https://github.com/owner/name"}
TOOLS = [
    {"name": "rls_check", "title": "Static RLS check", "inputSchema": schema({"repo": REPO}, ["repo"]),
     "description": "Scan a public repo's supabase/migrations for row-level-security mistakes (static analysis, no sign-up)."},
    {"name": "start_check", "title": "Request a full leak check",
     "inputSchema": schema({"repo": REPO, "email": {"type": "string", "description": "Where the report goes"}}, ["repo", "email"]),
     "description": "Request the full lab check. Returns a check id and a link; the repo owner proves ownership with a one-line file."},
    {"name": "get_check", "title": "Get a check", "inputSchema": schema({"check_id": {"type": "string"}}, ["check_id"]),
     "description": "Status, summary, report and fix for a check id."},
    {"name": "list_apps", "title": "List monitored apps", "inputSchema": schema({}, []),
     "description": "Apps monitored in the API key's workspace, with their last check. Needs X-API-Key."},
    {"name": "run_check", "title": "Run a check on an app", "inputSchema": schema({"app_id": {"type": "string"}}, ["app_id"]),
     "description": "Queue a check for a monitored app now. Needs X-API-Key."},
]
BY_NAME = {t["name"]: t for t in TOOLS}


def call_tool(name, args, request, c):
    import app as main  # loaded by now; imported here to avoid a cycle
    if name == "rls_check":
        return rls.rls_check(c, str(args["repo"]), ip_hash(request))
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


def one(m, request, c):
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
               "serverInfo": {"name": "patchlabs", "title": "PatchLabs", "version": "2.0.0"}, "instructions": INSTRUCTIONS}
    elif method == "ping":
        res = {}
    elif method == "tools/list":
        res = {"tools": TOOLS}
    elif method == "tools/call":
        name, args = params.get("name"), params.get("arguments") or {}
        if name not in BY_NAME:
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


def handle(raw, request):
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
            out = [r for r in (one(m, request, c) for m in msg) if r is not None]
        else:
            out = one(msg, request, c)
    return JSONResponse(out) if out else Response(status_code=202)


def refuse(status, message):
    return JSONResponse({**error(None, -32600, message), "detail": message}, status_code=status)


@router.post("/mcp")
async def mcp(request: Request):
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
    return await run_in_threadpool(handle, bytes(raw), request)


@router.get("/mcp")
@router.delete("/mcp")
def mcp_no_stream():
    return JSONResponse({"detail": "This MCP server is stateless: POST JSON-RPC requests to /mcp."}, status_code=405, headers={"Allow": "POST"})
