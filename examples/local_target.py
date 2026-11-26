"""A deliberately weak local demo server for testing permesso.

Deliberate weaknesses: no security headers, version-disclosing Server banner,
cookie without HttpOnly/Secure. HTTP only (no TLS) on 127.0.0.1 by default.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer

PAGE = """<!doctype html><html><head><title>Router Admin Panel (demo)</title></head>
<body><h1>Router Admin Panel</h1>
<form><label>User <input name=u></label><label>Pass
<input type=password name=p></label><button>Login</button></form>
</body></html>"""


class WeakHandler(BaseHTTPRequestHandler):
    server_version = "DemoNas/1.4.2"  # version disclosure on purpose

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "sid=demo123; Path=/")  # no HttpOnly/Secure
        self.end_headers()  # and no security headers at all
        self.wfile.write(PAGE.encode())

    def log_message(self, fmt, *args):
        pass


class FixedHandler(WeakHandler):
    """Same app, hardened: for demonstrating drift diff between scans."""

    server_version = "DemoNas"  # no version token

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "sid=demo123; Path=/; HttpOnly; Secure")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=()")
        self.end_headers()
        self.wfile.write(PAGE.encode())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--fixed", action="store_true",
                    help="serve the hardened variant (for drift-diff demos)")
    args = ap.parse_args()
    handler = FixedHandler if args.fixed else WeakHandler
    kind = "hardened" if args.fixed else "weak"
    print(f"{kind} demo server on http://{args.host}:{args.port} (Ctrl+C to stop)")
    HTTPServer((args.host, args.port), handler).serve_forever()


if __name__ == "__main__":
    main()
