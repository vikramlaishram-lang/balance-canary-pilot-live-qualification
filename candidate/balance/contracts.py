from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from pathlib import Path
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class Rejected(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Rejected(reason)


def canonical(value):
    # This protocol accepts integers, strings, booleans, null, arrays and objects;
    # floating point is excluded. This is a local encoding, not a JCS claim.
    def check(v):
        require(type(v) in (str, int, bool, type(None), list, dict), "unsupported JSON value")
        if isinstance(v, dict):
            require(all(type(k) is str for k in v), "non-string key")
            for item in v.values():
                check(item)
        if isinstance(v, list):
            for item in v:
                check(item)
    check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def strict_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, "duplicate JSON member")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_float=lambda _: (_ for _ in ()).throw(Rejected("float forbidden")),
                           parse_constant=lambda _: (_ for _ in ()).throw(Rejected("constant forbidden")))
        canonical(value)
        return value
    except (ValueError, TypeError) as exc:
        raise Rejected("invalid JSON: " + str(exc)) from exc


def digest(value):
    return hashlib.sha256(b"balance-canary:v1\0" + canonical(value)).hexdigest()


def load(path):
    return strict_json(Path(path).read_bytes())


def sign(payload, private_key):
    key = serialization.load_pem_private_key(Path(private_key).read_bytes(), password=None)
    require(isinstance(key, Ed25519PrivateKey), "Ed25519 required")
    signature = key.sign(b"balance-canary:signed:v1\0" + canonical(payload))
    return {"payload": payload, "signature": base64.b64encode(signature).decode()}


def verify(envelope, public_key, kind):
    require(type(envelope) is dict and set(envelope) == {"payload", "signature"}, "invalid signed envelope")
    payload = envelope["payload"]
    require(type(payload) is dict and payload.get("kind") == kind, "wrong claim type")
    try:
        key = serialization.load_pem_public_key(Path(public_key).read_bytes())
        key.verify(base64.b64decode(envelope["signature"], validate=True),
                   b"balance-canary:signed:v1\0" + canonical(payload))
    except Exception as exc:
        raise Rejected("signature did not verify") from exc
    return payload


def make_keys(private_path, public_path):
    private_path, public_path = Path(private_path), Path(public_path)
    require(not private_path.exists() and not public_path.exists(), "key file already exists")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    with private_path.open("xb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    private_path.chmod(0o600)
    public_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                         serialization.PublicFormat.SubjectPublicKeyInfo))


INTENT_FIELDS = {"version", "objective_id", "target", "service_uid", "base_revision",
                 "candidate_revision", "base_percent", "candidate_percent", "expected_etag",
                 "expected_generation", "policy_digest"}
TARGET = re.compile(r"projects/[a-z][a-z0-9-]{4,61}[a-z0-9]/locations/[a-z0-9-]+/services/[a-z][a-z0-9-]{0,62}\Z")


class Policy:
    def __init__(self, value):
        self.value = value
        fields = {"version", "target", "holder", "max_candidate_percent", "max_grant_seconds",
                  "health_url", "health_audience", "required_checks", "min_samples", "min_window_seconds",
                  "sample_interval_seconds", "max_observations", "evidence_max_age_seconds"}
        require(type(value) is dict and set(value) == fields, "policy fields must be exact")
        require(type(value["version"]) is int and value["version"] == 1 and TARGET.fullmatch(value["target"]), "invalid policy target/version")
        for key in ("max_candidate_percent", "max_grant_seconds", "min_samples", "min_window_seconds",
                    "sample_interval_seconds", "max_observations", "evidence_max_age_seconds"):
            require(type(value[key]) is int and value[key] > 0, "positive integer required: " + key)
        require(value["max_candidate_percent"] <= 10, "pilot ceiling is 10 percent")
        require(value["max_grant_seconds"] <= 900, "pilot approval lifetime is at most 900 seconds")
        require(2 <= value["min_samples"] <= value["max_observations"] <= 120, "invalid sample bounds")
        require(value["min_window_seconds"] >= value["sample_interval_seconds"], "observation window too short")
        checks = value["required_checks"]
        require(type(checks) is list and checks and len(set(checks)) == len(checks), "nonempty unique completion checks required")
        require(all(type(k) is str and re.fullmatch(r"[a-z][a-z0-9_]{0,40}", k) for k in checks), "invalid check name")
        require(type(value["holder"]) is str and bool(value["holder"]), "holder required")
        url = urlparse(value["health_url"])
        require(url.scheme == "https" and url.hostname and not url.username and not url.password
                and not url.query and not url.fragment and url.port in (None, 443), "fixed HTTPS probe URL required")
        audience = value["health_audience"]
        require(type(audience) is str and (not audience or audience.startswith("https://")), "invalid health audience")
        self.digest = digest(value)

    def validate_intent(self, intent):
        require(type(intent) is dict and set(intent) == INTENT_FIELDS, "intent fields must be exact")
        require(type(intent["version"]) is int and intent["version"] == 1, "intent version unsupported")
        require(intent["target"] == self.value["target"], "target outside configured policy")
        require(intent["policy_digest"] == self.digest, "completion/authority policy changed")
        for key in ("objective_id", "service_uid", "expected_etag", "expected_generation"):
            require(type(intent[key]) is str and 0 < len(intent[key]) <= 200, "missing intent field: " + key)
        require(re.fullmatch(r"[A-Za-z0-9_-]{1,100}", intent["objective_id"]), "invalid objective identifier")
        require(intent["expected_generation"].isdigit(), "generation must be an integer string")
        service = intent["target"].rsplit("/", 1)[-1]
        for key in ("base_revision", "candidate_revision"):
            value = intent[key]
            require(type(value) is str and value.startswith(service + "-") and
                    re.fullmatch(r"[a-z][a-z0-9-]{0,62}", value), "explicit revision of this service required")
        require(intent["base_revision"] != intent["candidate_revision"], "revisions must differ")
        require(type(intent["candidate_percent"]) is int and type(intent["base_percent"]) is int, "integer traffic required")
        require(1 <= intent["candidate_percent"] <= self.value["max_candidate_percent"], "traffic outside policy")
        require(intent["base_percent"] + intent["candidate_percent"] == 100, "traffic must total 100")
        return digest(intent)

    def authorization(self, envelope, public_key, now=None, check_time=True):
        payload = verify(envelope, public_key, "AUTHORIZATION")
        require(set(payload) == {"kind", "intent", "holder", "issuer", "issued_at", "expires_at"}, "authorization fields must be exact")
        require(payload["issuer"] == "operator" and payload["holder"] == self.value["holder"], "wrong authority holder/issuer")
        require(type(payload["issued_at"]) is int and type(payload["expires_at"]) is int, "integer authority times required")
        require(0 < payload["expires_at"] - payload["issued_at"] <= self.value["max_grant_seconds"], "invalid authority lifetime")
        if check_time:
            now = int(time.time()) if now is None else now
            require(payload["issued_at"] <= now < payload["expires_at"], "authority is not current")
        self.validate_intent(payload["intent"])
        return payload


def traffic_map(items, target):
    result = {}
    require(type(items) is list, "traffic array missing")
    for item in items:
        require(type(item) is dict, "invalid traffic entry")
        revision = item.get("revision", "")
        if revision.startswith(target + "/revisions/"):
            revision = revision.rsplit("/", 1)[-1]
        percent = item.get("percent", 0)
        require(type(percent) is int and 0 <= percent <= 100, "invalid observed percent")
        require(type(revision) is str and revision and revision not in result, "missing/duplicate revision")
        require(not item.get("tag"), "tagged services are outside this pilot")
        require(item.get("type") in (None, "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION"), "floating traffic target forbidden")
        result[revision] = percent
    require(sum(result.values()) == 100, "observed traffic does not total 100")
    return {k: v for k, v in result.items() if v}


def service_ready(service, intent):
    require(service.get("name") == intent["target"] and service.get("uid") == intent["service_uid"], "wrong target identity")
    # ProtoJSON may omit a non-presence boolean when its value is false.
    # Identity, terminal condition and observed generation remain mandatory.
    require(service.get("reconciling", False) is False, "target is reconciling")
    require(service.get("terminalCondition", {}).get("state") == "CONDITION_SUCCEEDED", "target is not ready")
    require(service.get("generation") == service.get("observedGeneration") and bool(service.get("generation")), "generation not observed")
    require(bool(service.get("etag")), "target version missing")


def expected_traffic(intent):
    return {intent["base_revision"]: intent["base_percent"], intent["candidate_revision"]: intent["candidate_percent"]}
