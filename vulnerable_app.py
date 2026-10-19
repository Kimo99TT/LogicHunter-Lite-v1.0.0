#!/usr/bin/env python3
"""Deliberately vulnerable test target for LogicHunter.
DO NOT DEPLOY ANYWHERE PUBLIC. localhost only."""
import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

USERS = {
    "1": {"id": "1", "name": "Alice", "email": "alice@example.com", "role": "user"},
    "2": {"id": "2", "name": "Bob", "email": "bob@example.com", "role": "user"},
    "3": {"id": "3", "name": "Charlie", "email": "charlie@example.com", "role": "admin"},
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(p.query)

        if p.path == "/api/user":  # IDOR: any id returns that user's data
            uid = q.get("id", [""])[0]
            user = USERS.get(uid)
            self._json(200, user) if user else self._json(404, {"error": "not found"})

        elif p.path == "/admin":  # AuthBypass: no cookie check at all
            self._send(200, "text/html",
                       "<html><body><h1>Admin Panel</h1></body></html>")

        elif p.path == "/protected":  # Safe auth-control fixture for regression tests
            cookie = self.headers.get("Cookie", "")
            if "session=lab-valid-session" in cookie:
                self._json(200, {"resource": "lab-only", "owner": "test-user"})
            else:
                self._json(403, {"error": "forbidden"})

        else:
            self._send(404, "text/html", "<h1>Not Found</h1>")

    def _send(self, status, ctype, body):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body.encode())))
        self.end_headers()
        self.wfile.write(body.encode())

    def _json(self, status, obj):
        self._send(status, "application/json", json.dumps(obj))

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("Vulnerable test app: http://127.0.0.1:9999")
    print("Endpoints: /api/user?id=1|2|3  |  /admin  |  /protected (Cookie: session=lab-valid-session)")
    HTTPServer(("127.0.0.1", 9999), Handler).serve_forever()
