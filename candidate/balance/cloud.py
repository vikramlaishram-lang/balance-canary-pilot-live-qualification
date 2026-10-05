"""Cloud Run v2 REST transport. No automatic retry of a target mutation."""
from __future__ import annotations

from urllib.parse import urlencode

from .contracts import Rejected, strict_json, require


class GoogleTransport:
    def __init__(self):
        import requests
        import google.auth
        from google.auth.transport.requests import Request
        self.credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        request = Request()
        def bounded_request(*args, **kwargs):
            kwargs["timeout"] = 10
            return request(*args, **kwargs)
        self.auth_request = bounded_request
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.mount("https://", requests.adapters.HTTPAdapter(max_retries=0))

    def request(self, method, url, body=None, audience=None, public=False):
        headers = {"Accept": "application/json", "Cache-Control": "no-cache"}
        if audience:
            from google.oauth2.id_token import fetch_id_token
            headers["Authorization"] = "Bearer " + fetch_id_token(self.auth_request, audience)
        elif not public:
            self.credentials.before_request(self.auth_request, method, url, headers)
        with self.session.request(method, url, json=body, headers=headers, timeout=(10, 20),
                                  allow_redirects=False, stream=True) as response:
            raw = bytearray()
            for chunk in response.iter_content(8192):
                raw.extend(chunk)
                require(len(raw) <= 262144, "provider response exceeds 256 KiB")
            # Any error after invoking PATCH is uncertain to the caller.
            require(200 <= response.status_code < 300, f"provider HTTP {response.status_code}")
            return strict_json(bytes(raw)), bytes(raw)


class CloudRunReader:
    def __init__(self, policy, transport=None):
        self.policy = policy
        self.transport = transport or GoogleTransport()

    def service(self, target):
        require(target == self.policy.value["target"], "read target outside configured policy")
        return self.transport.request("GET", "https://run.googleapis.com/v2/" + target)

    def operation(self, name):
        from .engine import operation_in_scope
        require(operation_in_scope(name, self.policy.value["target"]), "read operation outside target location")
        return self.transport.request("GET", "https://run.googleapis.com/v2/" + name)

    def probe(self, nonce):
        url = self.policy.value["health_url"] + "?" + urlencode({"nonce": nonce})
        return self.transport.request("GET", url, audience=self.policy.value["health_audience"] or None,
                                      public=not self.policy.value["health_audience"])


class CloudRunWriter(CloudRunReader):
    def patch(self, intent):
        self.policy.validate_intent(intent)
        body = {"name": intent["target"], "etag": intent["expected_etag"], "traffic": [
            {"type": "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION", "revision": intent["base_revision"], "percent": intent["base_percent"]},
            {"type": "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION", "revision": intent["candidate_revision"], "percent": intent["candidate_percent"]},
        ]}
        data, _ = self.transport.request("PATCH", "https://run.googleapis.com/v2/" + intent["target"] + "?updateMask=traffic&allowMissing=false", body)
        return data
