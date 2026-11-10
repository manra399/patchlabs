"""Test plumbing: a local stub for GitHub and webhook receivers, environment set-up, and small API helpers."""
import json, os, re, sys, tempfile, threading, time, types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
API_DIR = os.path.dirname(HERE)
ROOT = os.path.dirname(API_DIR)

STATE = types.SimpleNamespace()


def reset_stub():
    STATE.repos, STATE.files, STATE.hooks, STATE.hook_status, STATE.contents_status = {}, {}, [], 200, None
    STATE.migrations, STATE.shas, STATE.calls = {}, {}, []


reset_stub()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, body=b"", ctype="application/json"):
        body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        STATE.calls.append(self.path)
        if path.startswith("/gh/repos/"):
            parts = path[len("/gh/repos/"):].split("/")
            repo = "/".join(parts[:2]).lower()
            if len(parts) == 4 and parts[2] == "commits" and repo in STATE.repos:
                return self.reply(200, STATE.shas.get(repo, "a" * 40).encode(), "text/plain")
            if parts[2:] == ["contents", "supabase", "migrations"]:
                if repo not in STATE.migrations:
                    return self.reply(404, {"message": "Not Found"})
                return self.reply(200, [{"name": n, "path": f"supabase/migrations/{n}", "type": "file", "size": len(t.encode())}
                                        for n, t in STATE.migrations[repo].items()] + [{"name": "seed", "path": "supabase/migrations/seed",
                                                                                         "type": "dir", "size": 0}])
            if len(parts) == 2:
                return self.reply(200, STATE.repos[repo]) if repo in STATE.repos else self.reply(404, {"message": "Not Found"})
            if parts[2:] == ["contents", "patchlabs-verify.txt"]:
                if STATE.contents_status:
                    return self.reply(STATE.contents_status, {"message": "rate limited"})
                if repo in STATE.files:
                    return self.reply(200, STATE.files[repo].encode(), "text/plain")
                return self.reply(404, {"message": "Not Found"})
        if path.startswith("/raw/"):
            parts = path[len("/raw/"):].split("/")
            repo = "/".join(parts[:2]).lower()
            if repo in STATE.files and parts[-1] == "patchlabs-verify.txt":
                return self.reply(200, STATE.files[repo].encode(), "text/plain")
            if len(parts) == 6 and parts[3:5] == ["supabase", "migrations"] and parts[5] in STATE.migrations.get(repo, {}):
                return self.reply(200, STATE.migrations[repo][parts[5]].encode(), "text/plain")
        return self.reply(404, {"message": "Not Found"})

    def do_POST(self):
        path = urlsplit(self.path).path
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if path == "/slow":
            time.sleep(6.5)
        if path in ("/hook", "/slow") or path.startswith(("/services/", "/api/webhooks/", "/webhookb2/", "/powerautomate/")):
            STATE.hooks.append({"path": path, "host": self.headers.get("Host"), "headers": dict(self.headers),
                                "body": json.loads(body or b"null"), "raw": body})
            return self.reply(STATE.hook_status, {"ok": True})
        return self.reply(404, {"message": "Not Found"})


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
server.daemon_threads = True
threading.Thread(target=server.serve_forever, daemon=True).start()
PORT = server.server_address[1]
STUB = f"http://127.0.0.1:{PORT}"
OUTBOX = os.path.join(tempfile.mkdtemp(), "outbox.jsonl")

os.environ.update(
    DATABASE_URL=os.environ.get("DATABASE_URL", "postgresql://postgres:test@localhost:5432/patchlabs"),
    WORKER_TOKEN="worker-test-token", ADMIN_TOKEN="admin-test-token", SITE_URL="https://patchlabs.test",
    GITHUB_API=f"{STUB}/gh", RAW_GITHUB=f"{STUB}/raw", SCHEMA_PATH=os.path.join(ROOT, "db", "schema.sql"),
    EMAIL_OUTBOX=OUTBOX, AUTH_PER_IP_PER_HOUR="100000", FOUNDER_EMAIL="manraj@patchlabs.dev",
    CORS_ORIGINS="https://patchlabs.dev,https://www.patchlabs.dev",
    RECEIPT_PRIVATE_KEY="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",  # bytes 0..31, test only
    PATCHLABS_DEV="1")
sys.path.insert(0, API_DIR)

W = {"Authorization": "Bearer worker-test-token"}
A = {"Authorization": "Bearer admin-test-token"}


def sql(q, params=()):
    import core
    with core.pool.connection() as c:
        cur = c.execute(q, params)
        return cur.fetchall() if cur.description else None


def outbox(to=None):
    if not os.path.exists(OUTBOX):
        return []
    msgs = [json.loads(l) for l in open(OUTBOX) if l.strip()]
    return [m for m in msgs if to is None or m["to"] == to]


def link_param(msg, name):
    m = re.search(r"https://patchlabs\.test/app/login\?\S+", msg["text"])
    assert m, msg["text"]
    return parse_qs(urlsplit(m.group(0)).query)[name][0]


def add_repo(repo, branch="main"):
    STATE.repos[repo.lower()] = {"full_name": repo, "default_branch": branch}


def start(client, email, **kw):
    r = client.post("/auth/start", json={"email": email, **kw})
    assert r.status_code == 202, r.text
    return outbox(email.lower())[-1]


def sign_in(client, email, invite=None):
    tok = link_param(start(client, email), "token")
    r = client.post("/auth/finish", json={"token": tok, **({"invite": invite} if invite else {})})
    assert r.status_code == 200, r.text
    d = r.json()
    h = {"Authorization": f"Bearer {d['session']}"}
    me = client.get("/me", headers=h).json()
    personal = [w for w in me["workspaces"] if w["role"] == "owner"]
    return types.SimpleNamespace(session=d["session"], h=h, user=d["user"], wid=personal[0]["id"] if personal else None,
                                 email=email.lower(), finish=d)


def create_app(client, u, repo="acme/shop", wid=None, **kw):
    add_repo(repo)
    r = client.post(f"/workspaces/{wid or u.wid}/apps", json={"repo": repo, **kw}, headers=u.h)
    assert r.status_code == 201, r.text
    return r.json()


def verify(client, u, a):
    STATE.files[a["repo"].lower()] = f"{a['verify']['code']}\n"
    r = client.post(f"/apps/{a['id']}/verify", headers=u.h)
    assert r.status_code == 200, r.text
    return r.json()


def verified_app(client, u, repo="acme/shop", **kw):
    a = create_app(client, u, repo, **kw)
    v = verify(client, u, a)
    return a, v["check_id"]


def claim(client):
    r = client.post("/worker/claim", headers=W)
    assert r.status_code == 200, r.text
    return r.json()["check"]


def finish(client, cid, status="done", tables=(), proof=True, cost=0.42):
    summary = {"tables_leaking": list(tables), "readable_by_anyone": list(tables), "readable_by_signed_in": [],
               "lab_proof_passed": proof, "models": [{"model": "haiku", "cost_usd": 0.1}], "run_dir": "/Users/x/run"}
    body = {"status": status, "cost_usd": cost}
    if status != "failed":
        body.update(summary=summary, report_md="# Report", fix_sql="ALTER TABLE x ENABLE ROW LEVEL SECURITY;" if tables else None)
    else:
        body["error"] = "boom"
    r = client.post(f"/worker/checks/{cid}/result", json=body, headers=W)
    assert r.status_code == 200, r.text


def invite_as(client, owner, email, role, wid=None, app_ids=None):
    """Invites `email` with `role` (and, for clients, the apps they may see), signs them in accepting it."""
    body = {"email": email, "role": role, **({"app_ids": app_ids} if app_ids is not None else {})}
    r = client.post(f"/workspaces/{wid or owner.wid}/invites", json=body, headers=owner.h)
    assert r.status_code == 201, r.text
    u = sign_in(client, email, invite=link_param(outbox(email.lower())[-1], "invite"))
    assert u.finish["invite"]["accepted"], u.finish
    return u


def finish_with(client, cid, findings, status="done", tables=(), questions=None):
    """Worker result carrying the v3 finding list (summary.findings)."""
    summary = {"tables_leaking": list(tables), "lab_proof_passed": True, "findings": findings}
    if questions:
        summary["questions_for_owner"] = questions
    r = client.post(f"/worker/checks/{cid}/result", headers=W, json={"status": status, "summary": summary, "report_md": "# Report",
                                                                     "fix_sql": "ALTER TABLE x ENABLE ROW LEVEL SECURITY;" if tables else None})
    assert r.status_code == 200, r.text
