"""Remote MCP server: raw JSON-RPC 2.0 requests against POST /mcp."""
import json

from helpers import STATE, add_repo, claim, finish, outbox, sign_in, verified_app

H = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def rpc(client, method, params=None, mid=1, headers=None):
    body = {"jsonrpc": "2.0", "id": mid, "method": method, **({"params": params} if params is not None else {})}
    r = client.post("/mcp", content=json.dumps(body), headers={**H, **(headers or {})})
    assert r.status_code == 200, r.text
    return r.json()


def call(client, name, args=None, headers=None):
    return rpc(client, "tools/call", {"name": name, "arguments": args or {}}, headers=headers)["result"]


def test_initialize_and_list(client):
    r = rpc(client, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}})
    assert r["jsonrpc"] == "2.0" and r["id"] == 1
    res = r["result"]
    assert res["protocolVersion"] == "2025-06-18" and res["capabilities"]["tools"] == {"listChanged": False}
    assert res["serverInfo"]["name"] == "patchlabs"
    assert rpc(client, "initialize", {"protocolVersion": "1999-01-01"})["result"]["protocolVersion"] == "2025-06-18"
    assert rpc(client, "initialize", {"protocolVersion": "2025-03-26"})["result"]["protocolVersion"] == "2025-03-26"
    tools = rpc(client, "tools/list", mid="abc")
    assert tools["id"] == "abc"
    names = [t["name"] for t in tools["result"]["tools"]]
    assert names == ["rls_check", "headers_check", "start_check", "get_check", "list_apps", "list_checks", "run_check"]
    for t in tools["result"]["tools"]:
        assert t["description"] and t["inputSchema"]["type"] == "object"
        a = t["annotations"]
        assert a["title"] == t["title"] and a["destructiveHint"] is False
        assert set(a) == {"title", "readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"}
    read_only = {t["name"] for t in tools["result"]["tools"] if t["annotations"]["readOnlyHint"]}
    assert read_only == {"rls_check", "headers_check", "get_check", "list_apps", "list_checks"}
    assert rpc(client, "initialize", {"protocolVersion": "2025-11-25"})["result"]["protocolVersion"] == "2025-11-25"
    assert rpc(client, "ping")["result"] == {}


def test_notifications_and_protocol_errors(client):
    r = client.post("/mcp", content=json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}), headers=H)
    assert r.status_code == 202 and r.content == b""
    assert client.post("/mcp", content=b"{nope", headers=H).json()["error"]["code"] == -32700
    assert client.post("/mcp", content=json.dumps({"id": 1, "method": "x"}), headers=H).json()["error"]["code"] == -32600
    assert client.post("/mcp", content=b"[]", headers=H).json()["error"]["code"] == -32600
    assert rpc(client, "resources/list")["error"]["code"] == -32601
    assert rpc(client, "tools/call", {"name": "nope"})["error"]["code"] == -32602
    assert rpc(client, "tools/call", {"name": "get_check", "arguments": {}})["error"]["code"] == -32602
    assert client.get("/mcp").status_code == 405


def test_batch(client):
    body = [{"jsonrpc": "2.0", "id": 1, "method": "ping"}, {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    r = client.post("/mcp", content=json.dumps(body), headers=H).json()
    assert [x["id"] for x in r] == [1, 2]


def test_rls_check_tool(client):
    add_repo("acme/shop")
    STATE.migrations["acme/shop"] = {"001.sql": "create table people (id int, email text);"}
    res = call(client, "rls_check", {"repo": "acme/shop"})
    assert res["isError"] is False
    assert res["structuredContent"]["findings"][0]["id"] == "PL-008"
    assert json.loads(res["content"][0]["text"])["repo"] == "acme/shop"
    bad = call(client, "rls_check", {"repo": "acme/missing"})
    assert bad["isError"] is True and "couldn't find" in bad["content"][0]["text"]


def test_headers_check_tool(client, monkeypatch):
    import posture
    page = {"status": 200, "headers": {"content-security-policy": "default-src 'self'"}, "cookies": [], "body": "", "tls": None}
    monkeypatch.setattr(posture, "fetch", lambda url, verify=True: page)
    res = call(client, "headers_check", {"url": "shop.example.com"})
    assert res["isError"] is False and res["structuredContent"]["url"] == "https://shop.example.com"
    assert "PL-031" in [f["id"] for f in res["structuredContent"]["findings"]]
    bad = call(client, "headers_check", {"url": "http://127.0.0.1"})
    assert bad["isError"] is True and "IP addresses" in bad["content"][0]["text"]


def test_start_and_get_check_tools(client):
    add_repo("acme/shop")
    res = call(client, "start_check", {"repo": "acme/shop", "email": "dev@example.com"})
    assert res["isError"] is False
    cid = res["structuredContent"]["id"]
    assert res["structuredContent"]["status"] == "awaiting_verification"
    assert outbox("dev@example.com")[-1]["subject"] == "Your PatchLabs leak check for acme/shop"
    got = call(client, "get_check", {"check_id": cid})
    assert got["structuredContent"]["status"] == "awaiting_verification" and got["structuredContent"]["verify"]["code"]
    assert call(client, "get_check", {"check_id": "nope"})["isError"] is True
    bad = call(client, "start_check", {"repo": "acme/shop", "email": "not-an-email"})
    assert bad["isError"] is True and "email" in bad["content"][0]["text"]


def test_api_key_tools(client):
    u = sign_in(client, "owner@example.com")
    a, cid = verified_app(client, u)
    key = {"X-API-Key": client.post(f"/workspaces/{u.wid}/api-keys", json={"name": "mcp"}, headers=u.h).json()["key"]}
    assert call(client, "list_apps")["isError"] is True
    assert call(client, "list_apps", headers={"X-API-Key": "pl_live_bad"})["isError"] is True
    apps = call(client, "list_apps", headers=key)["structuredContent"]["apps"]
    assert [x["id"] for x in apps] == [a["id"]]
    busy = call(client, "run_check", {"app_id": a["id"]}, headers=key)
    assert busy["isError"] is True and "already" in busy["content"][0]["text"]
    finish(client, claim(client)["id"], "no_leaks")
    ok = call(client, "run_check", {"app_id": a["id"]}, headers=key)
    assert ok["isError"] is False and ok["structuredContent"]["status"] == "queued"
    other = sign_in(client, "other@example.com")
    okey = {"X-API-Key": client.post(f"/workspaces/{other.wid}/api-keys", json={"name": "x"}, headers=other.h).json()["key"]}
    assert call(client, "run_check", {"app_id": a["id"]}, headers=okey)["isError"] is True
    assert call(client, "list_apps", headers=okey)["structuredContent"]["apps"] == []
    assert "cost" not in json.dumps(apps).lower()
    hist = call(client, "list_checks", headers=key)["structuredContent"]["checks"]
    assert len(hist) == 2 and hist[0]["status"] == "queued" and hist[1]["status"] == "no_leaks" and hist[1]["finished"] is True
    assert hist[1]["id"] == cid and all(h["app_id"] == a["id"] for h in hist)
    assert len(call(client, "list_checks", {"limit": 1}, headers=key)["structuredContent"]["checks"]) == 1
    assert len(call(client, "list_checks", {"app_id": a["id"]}, headers=key)["structuredContent"]["checks"]) == 2
    assert call(client, "list_checks", headers=okey)["structuredContent"]["checks"] == []
    assert call(client, "list_checks", {"app_id": a["id"]}, headers=okey)["isError"] is True
    assert call(client, "list_checks", {"app_id": "nope"}, headers=key)["isError"] is True
    assert call(client, "list_checks")["isError"] is True
    assert call(client, "list_checks", {"limit": "lots"}, headers=key)["isError"] is True
    assert "cost" not in json.dumps(hist).lower()


def test_public_endpoint_has_only_open_tools(client):
    def prpc(method, params=None):
        body = {"jsonrpc": "2.0", "id": 1, "method": method, **({"params": params} if params is not None else {})}
        r = client.post("/mcp/public", content=json.dumps(body), headers=H)
        assert r.status_code == 200, r.text
        return r.json()
    init = prpc("initialize", {"protocolVersion": "2025-06-18"})["result"]
    assert "X-API-Key" not in init["instructions"] and "rls_check" in init["instructions"]
    names = [t["name"] for t in prpc("tools/list")["result"]["tools"]]
    assert names == ["rls_check", "headers_check", "start_check", "get_check"]
    err = prpc("tools/call", {"name": "list_apps", "arguments": {}})
    assert err["error"]["code"] == -32602 and "Unknown tool" in err["error"]["message"]
    assert client.get("/mcp/public").status_code == 405
