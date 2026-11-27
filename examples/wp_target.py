"""A deliberately weak fake WordPress site for testing the wordpress adapter.

Deliberate weaknesses: version disclosure (meta + readme + feed), an old
plugin version (akismet 3.1.4 — affected by the < 3.1.5 XSS, CVE-2015-9357),
REST user enumeration, exposed debug.log. No real WP code involved.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer

HOMEPAGE = """<!doctype html><html><head>
<meta name="generator" content="WordPress 6.3">
<link rel="stylesheet" href="/wp-content/themes/faketheme/style.css">
<script src="/wp-content/plugins/akismet/fake.js"></script>
</head><body><h1>Fake WP News</h1><p>Hello from the demo.</p></body></html>"""

README_AKISMET = """=== Akismet ===
Contributors: matt
Tags: spam
Stable tag: 3.1.4

Fake readme for the demo plugin.
"""

FEED = '<?xml version="1.0"?><rss><channel><generator>https://wordpress.org/?v=6.3</generator></channel></rss>'
USERS_JSON = '[{"id":1,"name":"admin","slug":"admin"},{"id":2,"name":"editor","slug":"editor"}]'
DEBUG_LOG = "PHP Notice:  Undefined index: id in /var/www/wp-content/plugins/fakething/x.php on line 42\n"


class FakeWPHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4"

    def do_GET(self):
        routes = {
            "/": HOMEPAGE,
            "/feed/": FEED,
            "/wp-json/wp/v2/users": USERS_JSON,
            "/wp-content/plugins/akismet/readme.txt": README_AKISMET,
            "/wp-content/debug.log": DEBUG_LOG,
        }
        if self.path in routes:
            body = routes[self.path].encode()
            ctype = "application/json" if "wp-json" in self.path else "text/html"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"404")

    def log_message(self, fmt, *args):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8124)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    print(f"fake WordPress demo on http://{args.host}:{args.port} (Ctrl+C to stop)")
    HTTPServer((args.host, args.port), FakeWPHandler).serve_forever()


if __name__ == "__main__":
    main()
