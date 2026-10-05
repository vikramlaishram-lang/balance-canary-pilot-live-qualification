"""Deterministic, read-only Cloud Run qualification fixture; not a business app."""
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
from urllib.parse import parse_qs, urlsplit

SERVICE = "balance-canary-target"


@dataclass(frozen=True)
class Identity:
    version: str
    revision: str
    service: str

    @classmethod
    def environment(cls):
        return cls(os.environ.get("VERSION", ""), os.environ.get("K_REVISION", ""), os.environ.get("K_SERVICE", ""))


def transform(value):
    """The tiny application's deterministic operation, also exercised by smoke."""
    return value[::-1]


def response(identity, path):
    url = urlsplit(path)
    if url.path == "/":
        return 200, {"VERSION": identity.version, "revision": identity.revision,
                     "service": identity.service, "result": transform("balance")}
    if url.path != "/balance-health":
        return 404, {"error": "unknown path"}
    query = parse_qs(url.query, keep_blank_values=True)
    if set(query) != {"nonce"} or len(query["nonce"]) != 1 or not re.fullmatch(r"[0-9a-f]{32}", query["nonce"][0]):
        return 400, {"error": "one 32-character hexadecimal nonce is required"}
    ready = (identity.version in {"baseline", "candidate"} and identity.service == SERVICE
             and bool(re.fullmatch(SERVICE + r"-[a-z0-9-]+", identity.revision)))
    smoke = transform("balance") == "ecnalab" and transform("canary") == "yranac"
    return 200, {"VERSION": identity.version, "revision": identity.revision, "nonce": query["nonce"][0],
                 "checks": {"ready": ready, "smoke": smoke}}


def server(identity, host="0.0.0.0", port=8080):
    class Handler(BaseHTTPRequestHandler):
        def emit(self, status, body):
            raw = json.dumps(body, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            self.emit(*response(identity, self.path))

        def do_POST(self):
            self.emit(405, {"error": "read-only fixture"})

        def log_message(self, *args):
            pass

    return ThreadingHTTPServer((host, port), Handler)


if __name__ == "__main__":
    server(Identity.environment(), port=int(os.environ.get("PORT", "8080"))).serve_forever()
