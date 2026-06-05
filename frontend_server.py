"""
LensIQ Admin Dashboard — static frontend server (port 7789).
Serves dashboard.html (and assets) from ./public.
The dashboard talks to the backend API on :7788 (auto-detected from hostname).

  python frontend_server.py      # or via pm2 (ecosystem.config.js)
"""
import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

BASE = os.path.dirname(os.path.abspath(__file__))
PUBLIC = os.path.join(BASE, "public")
PORT = int(os.environ.get("LENSIQ_FRONTEND_PORT", "7789"))


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=PUBLIC, **k)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        # SPA-style: serve dashboard.html for "/" and unknown paths
        if self.path == "/" or (not os.path.splitext(self.path)[1] and "?" not in self.path):
            self.path = "/dashboard.html"
        return super().do_GET()


if __name__ == "__main__":
    os.makedirs(PUBLIC, exist_ok=True)
    print(f"[lensiq-frontend] serving {PUBLIC} on :{PORT}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
