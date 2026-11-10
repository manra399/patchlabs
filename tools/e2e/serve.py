"""Static server for docs/ that resolves URLs the way GitHub Pages does: /pricing → pricing.html, /app/ → app/index.html.
   python3 tools/e2e/serve.py <port> [directory=docs]"""
import os, sys
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


class Pages(SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def translate_path(self, path):
        p = super().translate_path(path)
        if not os.path.exists(p) and os.path.exists(p + ".html"):
            return p + ".html"
        return p

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


if __name__ == "__main__":
    port, root = int(sys.argv[1]), sys.argv[2] if len(sys.argv) > 2 else "docs"
    ThreadingHTTPServer(("127.0.0.1", port), partial(Pages, directory=os.path.abspath(root))).serve_forever()
