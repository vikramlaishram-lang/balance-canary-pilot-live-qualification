from __future__ import annotations

import base64
import hmac
import json
import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .contracts import Policy, Rejected, canonical, load, require, strict_json
from .engine import Coordinator, Observer, Writer
from .store import Store


LIMIT = 2 * 1024 * 1024


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Rejected("service redirect refused")


class Client:
    def __init__(self, url, token_file):
        self.url = url.rstrip("/")
        self.token = Path(token_file).read_text().strip()
        require(len(self.token) >= 32, "internal service token too short")
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def request(self, path, body=None):
        req = Request(self.url + path, data=canonical(body) if body is not None else None,
                      headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        try:
            with self.opener.open(req, timeout=45) as response:
                raw = response.read(LIMIT + 1)
                require(len(raw) <= LIMIT, "service response too large")
                return strict_json(raw)
        except HTTPError as exc:
            # Body is a bounded structured service error; no credential headers.
            message = exc.read(4096).decode(errors="replace")
            raise Rejected(f"service HTTP {exc.code}: {message}") from exc

    def dispatch(self, approval):
        return self.request("/dispatch", approval)

    def settle(self, objective_id, samples):
        return self.request("/settle", {"objective_id": objective_id, "samples": samples})

    def sample(self, intent, dispatch, challenge):
        return self.request("/observe", {"intent": intent, "dispatch": dispatch, "challenge": challenge})


class Application:
    def __init__(self, role, engine, token_file):
        self.role, self.engine = role, engine
        self.token = Path(token_file).read_text().strip()
        require(len(self.token) >= 32, "service token too short")

    def __call__(self, env, start_response):
        try:
            supplied = env.get("HTTP_AUTHORIZATION", "")
            require(hmac.compare_digest(supplied, "Bearer " + self.token), "authentication required")
            method, path = env["REQUEST_METHOD"], env.get("PATH_INFO", "")
            body = None
            if method == "POST":
                require(env.get("CONTENT_TYPE", "").split(";")[0] == "application/json", "JSON required")
                length = int(env.get("CONTENT_LENGTH", "0"))
                require(0 < length <= LIMIT, "invalid request size")
                raw = env["wsgi.input"].read(length)
                require(len(raw) == length, "incomplete request")
                body = strict_json(raw)
            result = self.route(method, path, body)
            code = "200 OK"
        except Rejected as exc:
            result = {"error": str(exc)}
            code = "401 Unauthorized" if str(exc) == "authentication required" else "400 Bad Request"
        except Exception:
            result, code = {"error": "service operation failed; inspect durable state before retrying"}, "500 Internal Server Error"
        data = canonical(result)
        start_response(code, [("Content-Type", "application/json"), ("Content-Length", str(len(data))),
                              ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff")])
        return [data]

    def route(self, method, path, body):
        if method == "GET" and path == "/health":
            return {"process": "running", "role": self.role, "qualification": "PILOT_CANDIDATE"}
        if self.role == "gateway":
            if method == "GET" and path == "/policy":
                return {"policy": self.engine.policy.value, "policy_digest": self.engine.policy.digest}
            if method == "POST" and path == "/jobs":
                return self.engine.submit(body)
            if method == "GET" and path == "/jobs":
                return [{"objective_id": r["id"], "state": r["state"], "next_action": r["document"].get("next_action")}
                        for r in self.engine.store.list()]
            if method == "GET" and path.startswith("/jobs/"):
                result = self.engine.store.get(path[len("/jobs/"):])
                require(result is not None, "unknown objective")
                return result
        elif self.role == "writer":
            if method == "POST" and path == "/dispatch":
                return self.engine.dispatch(body)
            if method == "POST" and path == "/settle":
                require(type(body) is dict and set(body) == {"objective_id", "samples"}, "invalid settlement fields")
                return self.engine.settle(body["objective_id"], body["samples"])
        elif self.role == "observer":
            if method == "POST" and path == "/observe":
                require(type(body) is dict and set(body) == {"intent", "dispatch", "challenge"}, "invalid observation fields")
                return self.engine.sample(body["intent"], body["dispatch"], body["challenge"])
            if method == "GET" and path.startswith("/evidence/"):
                import re
                key = path[len("/evidence/"):]
                require(re.fullmatch(r"[0-9a-f]{64}", key), "invalid evidence digest")
                raw = (self.engine.evidence_directory / (key + ".bin")).read_bytes()
                return {"sha256": key, "base64": base64.b64encode(raw).decode()}
        raise Rejected("route unavailable to this role")


def configured(role):
    policy = Policy(load(os.environ["BALANCE_POLICY"]))
    directory = Path(os.environ.get("BALANCE_DATA", "/data"))
    if role == "gateway":
        # This branch never constructs cloud credentials or receives signing keys.
        return Coordinator(policy, Store(directory / "objectives.db"),
                           Client(os.environ["WRITER_URL"], os.environ["WRITER_TOKEN_FILE"]),
                           Client(os.environ["OBSERVER_URL"], os.environ["OBSERVER_TOKEN_FILE"]),
                           os.environ["AUTHORITY_PUBLIC_KEY"], os.environ["WRITER_PUBLIC_KEY"],
                           os.environ["OBSERVER_PUBLIC_KEY"])
    from .cloud import CloudRunReader, CloudRunWriter
    if role == "writer":
        return Writer(policy, Store(directory / "intents.db", writer=True), CloudRunWriter(policy),
                      os.environ["AUTHORITY_PUBLIC_KEY"], os.environ["SIGNING_PRIVATE_KEY"], os.environ["OBSERVER_PUBLIC_KEY"])
    if role == "observer":
        return Observer(policy, CloudRunReader(policy), os.environ["WRITER_PUBLIC_KEY"],
                        os.environ["SIGNING_PRIVATE_KEY"], directory / "evidence")
    raise Rejected("unknown service role")


def create_app():
    role = os.environ["BALANCE_ROLE"]
    return Application(role, configured(role), os.environ["API_TOKEN_FILE"])
