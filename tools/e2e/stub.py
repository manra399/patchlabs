"""E2E stub for GitHub (repo lookup + verify file), a webhook receiver and fake live sites (for live posture), with /_ctl
control endpoints for the test."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

FILES, HOOKS, STATE, SITES = {}, [], {"hook_status": 200}, {}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, body=b"", ctype="application/json"):
        body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def site(self, path):
        """/_site/<scheme>/<host><path>: a fake live site set with /_ctl/site (e2e_main routes *.e2e-site.net here)."""
        scheme, host, rest = (path[len("/_site/"):].split("/", 2) + ["", ""])[:3]
        s, rest = SITES.get(host), "/" + rest
        if not s:
            return self.reply(404, {"message": "Not Found"})
        if scheme == "http" and s.get("redirect", True):
            self.send_response(301)
            self.send_header("Location", f"https://{host}{rest}")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if rest in s.get("files", {}):
            return self.reply(200, s["files"][rest].encode(), "text/plain")
        if rest != "/":
            return self.reply(404, b"not found", "text/plain")
        body = s.get("body", "<!doctype html><title>E2E site</title>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for k, v in s.get("headers", {}).items():
            self.send_header(k, v)
        for c in s.get("cookies", []):
            self.send_header("Set-Cookie", c)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path.startswith("/_site/"):
            return self.site(path)
        if path == "/_ctl/hooks":
            return self.reply(200, HOOKS)
        if path.startswith("/gh/repos/"):
            parts = path[len("/gh/repos/"):].split("/")
            repo = "/".join(parts[:2])
            if len(parts) == 2:
                if "missing" in repo:
                    return self.reply(404, {"message": "Not Found"})
                return self.reply(200, {"full_name": repo, "default_branch": "main"})
            if parts[2:] == ["contents", "patchlabs-verify.txt"]:
                f = FILES.get(repo.lower())
                return self.reply(200, f.encode(), "text/plain") if f else self.reply(404, {"message": "Not Found"})
        if path.startswith("/raw/"):
            parts = path[len("/raw/"):].split("/")
            f = FILES.get("/".join(parts[:2]).lower())
            if f and parts[-1] == "patchlabs-verify.txt":
                return self.reply(200, f.encode(), "text/plain")
        return self.reply(404, {"message": "Not Found"})

    def do_POST(self):
        path = urlsplit(self.path).path
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"null")
        if path == "/_ctl/file":
            FILES[body["repo"].lower()] = body["content"]
            return self.reply(200, {"ok": True})
        if path == "/_ctl/site":
            SITES[body["host"]] = body
            return self.reply(200, {"ok": True})
        if path == "/_ctl/hook_status":
            STATE["hook_status"] = int(body["status"])
            return self.reply(200, {"ok": True})
        if path == "/hook":
            HOOKS.append({"headers": dict(self.headers), "body": body})
            return self.reply(STATE["hook_status"], {"ok": True})
        return self.reply(404, {"message": "Not Found"})


ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
