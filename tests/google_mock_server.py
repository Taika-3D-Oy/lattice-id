#!/usr/bin/env python3
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    token_body = b"{}"
    jwks_body = b"{}"

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        if self.path.startswith("/certs"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(self.jwks_body)
            return

        if self.path.startswith("/o/oauth2/v2/auth"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"mock-google-auth")
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path.startswith("/token"):
            _ = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(self.token_body)
            return

        self.send_response(404)
        self.end_headers()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--token-json", required=True)
    parser.add_argument("--jwks-json", required=True)
    args = parser.parse_args()

    with open(args.token_json, "rb") as handle:
        Handler.token_body = handle.read()
    with open(args.jwks_json, "rb") as handle:
        Handler.jwks_body = handle.read()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()