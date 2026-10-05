from __future__ import annotations

import copy
import hashlib
import os
import re
import time
from pathlib import Path
from uuid import uuid4

from .contracts import Rejected, digest, expected_traffic, require, service_ready, sign, traffic_map, verify


def operation_in_scope(name, target):
    prefix = target.split("/services/")[0] + "/operations/"
    return type(name) is str and name.startswith(prefix) and bool(re.fullmatch(r"[A-Za-z0-9_-]+", name[len(prefix):]))


class Writer:
    def __init__(self, policy, store, provider, approval_public, signing_private, observer_public, clock=time.time):
        self.policy, self.store, self.provider = policy, store, provider
        self.approval_public, self.signing_private = approval_public, signing_private
        self.observer_public, self.clock = observer_public, clock

    def _receipt(self, intent, state, operation=None, reason=None):
        return sign({"kind": "DISPATCH_RECORD", "objective_id": intent["objective_id"],
                     "intent_digest": digest(intent), "state": state, "operation": operation,
                     "recorded_at": int(self.clock()), "reason": reason}, self.signing_private)

    def dispatch(self, approval):
        # Replay verifies authentic binding but never needs new execution authority.
        auth = self.policy.authorization(approval, self.approval_public, check_time=False)
        intent = auth["intent"]
        intent_digest = digest(intent)
        existing = self.store.get(intent["objective_id"])
        if existing:
            require(existing["digest"] == intent_digest, "IDEMPOTENCY_KEY_REUSE_MISMATCH")
            return existing["document"]["receipt"]
        self.policy.authorization(approval, self.approval_public, now=int(self.clock()))
        document = {"intent": intent, "approval": approval, "receipt": self._receipt(intent, "EFFECT_UNKNOWN",
                    reason="Intent reserved; dispatch may occur. Never automatically redispatch this reservation.")}
        record, created = self.store.create(intent["objective_id"], intent_digest, intent["target"], "RESERVED", document)
        if not created:
            return record["document"]["receipt"]
        try:
            before, _ = self.provider.service(intent["target"])
            service_ready(before, intent)
            require(before["etag"] == intent["expected_etag"] and before["generation"] == intent["expected_generation"],
                    "target changed after approval")
            require(traffic_map(before.get("trafficStatuses"), intent["target"]) == {intent["base_revision"]: 100},
                    "pilot requires a 100-percent base baseline")
            # A lengthy preflight does not extend the authority window.
            self.policy.authorization(approval, self.approval_public, now=int(self.clock()))
        except Exception as exc:
            document["receipt"] = self._receipt(intent, "NOT_DISPATCHED", reason=str(exc)[:300])
            self.store.update(intent["objective_id"], "NOT_DISPATCHED", document, {"RESERVED"})
            return document["receipt"]
        # The durable reservation precedes this one provider mutation attempt.
        # No exception after this point is treated as proof of no effect.
        try:
            operation = self.provider.patch(intent)
            require(operation_in_scope(operation.get("name"), intent["target"]), "invalid provider operation identity")
            document["receipt"] = self._receipt(intent, "SUBMITTED", operation=operation["name"])
            self.store.update(intent["objective_id"], "SUBMITTED", document, {"RESERVED"})
        except Exception as exc:
            document["receipt"] = self._receipt(intent, "EFFECT_UNKNOWN", reason=str(exc)[:300])
            self.store.update(intent["objective_id"], "UNKNOWN", document, {"RESERVED"})
        return document["receipt"]

    def settle(self, objective_id, samples):
        record = self.store.get(objective_id)
        require(record is not None, "unknown objective")
        document = record["document"]
        if record["state"] == "SETTLED":
            return document["receipt"]
        require(record["state"] == "SUBMITTED", "uncertain intent cannot be silently settled")
        require(type(samples) is list and bool(samples), "completion samples required")
        last = verify(samples[-1], self.observer_public, "OBSERVATION")
        require(type(last.get("observed_at")) is int and last["observed_at"] <= int(self.clock()), "future settlement evidence")
        # Settlement releases a local reservation after a historically satisfied
        # completion window. It grants no authority to change the target again.
        validate_completion(self.policy, document["intent"], document["receipt"], samples,
                            self.observer_public, now=last["observed_at"], trusted_dispatch=True)
        # Preserve the original dispatch receipt; release the target reservation only.
        document["completion_samples"] = samples
        self.store.update(objective_id, "SETTLED", document, {"SUBMITTED"})
        return document["receipt"]


class Observer:
    def __init__(self, policy, provider, writer_public, signing_private, evidence_directory, clock=time.time):
        self.policy, self.provider, self.writer_public = policy, provider, writer_public
        self.signing_private, self.clock = signing_private, clock
        self.evidence_directory = Path(evidence_directory)
        self.evidence_directory.mkdir(parents=True, exist_ok=True)

    def _capture(self, raw):
        hashed = hashlib.sha256(raw).hexdigest()
        path = self.evidence_directory / (hashed + ".bin")
        try:
            with path.open("xb") as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            directory_fd = os.open(self.evidence_directory, os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except FileExistsError:
            require(hashlib.sha256(path.read_bytes()).hexdigest() == hashed, "stored raw evidence changed")
        return hashed

    def sample(self, intent, dispatch, challenge):
        self.policy.validate_intent(intent)
        require(type(challenge) is str and re.fullmatch(r"[0-9a-f]{32}", challenge), "invalid observation challenge")
        receipt = verify(dispatch, self.writer_public, "DISPATCH_RECORD")
        require(receipt.get("intent_digest") == digest(intent) and receipt.get("objective_id") == intent["objective_id"],
                "dispatch/observation binding mismatch")
        payload = {"kind": "OBSERVATION", "intent_digest": digest(intent), "policy_digest": self.policy.digest,
                   "target": intent["target"], "service_uid": intent["service_uid"], "challenge": challenge,
                   "observed_at": int(self.clock()), "operation": receipt.get("operation"), "generation": None,
                   "verdict": "OBSERVATION_UNAVAILABLE", "checks": {}, "evidence": {}, "reason": None}
        try:
            current, raw = self.provider.service(intent["target"])
            payload["evidence"]["service_before"] = self._capture(raw)
            service_ready(current, intent)
            payload["generation"] = current["generation"]
            actual = traffic_map(current.get("trafficStatuses"), intent["target"])
            payload["observed_traffic"] = actual
            if not receipt.get("operation"):
                payload["verdict"] = "ATTRIBUTION_UNKNOWN"
                payload["reason"] = "State observed, but this dispatch has no confirmed provider operation identity."
            else:
                require(operation_in_scope(receipt["operation"], intent["target"]), "operation outside target location")
                operation, raw = self.provider.operation(receipt["operation"])
                payload["evidence"]["operation"] = self._capture(raw)
                require(operation.get("name") == receipt["operation"], "wrong operation response")
                if operation.get("done") is not True:
                    payload["verdict"] = "WAITING_OPERATION"
                elif "error" in operation:
                    payload["verdict"] = "OPERATION_ERROR"
                else:
                    committed = operation.get("response", {})
                    require(committed.get("name") == intent["target"] and committed.get("uid") == intent["service_uid"],
                            "operation response is not the approved service instance")
                    require(type(committed.get("generation")) is str and committed["generation"].isdigit(), "operation generation missing")
                    require(int(committed["generation"]) > int(intent["expected_generation"]), "operation did not advance generation")
                    if current["generation"] != committed["generation"] or actual != expected_traffic(intent):
                        payload["verdict"] = "STATE_DIVERGED"
                    else:
                        health, raw = self.provider.probe(challenge)
                        payload["evidence"]["health"] = self._capture(raw)
                        require(health.get("nonce") == challenge, "health response is stale or unbound")
                        revision = health.get("revision")
                        if revision == intent["base_revision"]:
                            payload["verdict"] = "BASE_SAMPLE"
                        else:
                            require(revision == intent["candidate_revision"], "wrong health revision")
                            checks = health.get("checks")
                            require(type(checks) is dict, "health checks missing")
                            payload["checks"] = {k: checks.get(k) is True for k in self.policy.value["required_checks"]}
                            payload["verdict"] = "PASS" if all(payload["checks"].values()) else "CHECK_FAILED"
                        after, raw = self.provider.service(intent["target"])
                        payload["evidence"]["service_after"] = self._capture(raw)
                        service_ready(after, intent)
                        require(after["generation"] == current["generation"] and after["etag"] == current["etag"]
                                and traffic_map(after.get("trafficStatuses"), intent["target"]) == expected_traffic(intent),
                                "target changed during observation")
        except Exception as exc:
            # A later read failure adds uncertainty; it cannot erase an
            # already established failure of the required candidate checks.
            if payload["verdict"] == "CHECK_FAILED":
                payload["reason"] = ("Final target verification unavailable: " + str(exc))[:300]
            else:
                payload["verdict"] = "OBSERVATION_UNAVAILABLE"
                payload["reason"] = str(exc)[:300]
        payload["observed_at"] = int(self.clock())
        return sign(payload, self.signing_private)


def validate_completion(policy, intent, dispatch, samples, observer_public, now, trusted_dispatch=False, writer_public=None):
    policy.validate_intent(intent)
    receipt = dispatch["payload"] if trusted_dispatch else verify(dispatch, writer_public, "DISPATCH_RECORD")
    require(receipt.get("intent_digest") == digest(intent) and receipt.get("state") == "SUBMITTED", "no confirmed dispatch")
    require(operation_in_scope(receipt.get("operation"), intent["target"]), "missing operation identity")
    require(type(samples) is list and len(samples) >= policy.value["min_samples"], "insufficient samples")
    verified = []
    challenges = set()
    for sample in samples:
        item = verify(sample, observer_public, "OBSERVATION")
        require(item.get("verdict") == "PASS", "nonpassing observation")
        require(item.get("intent_digest") == digest(intent) and item.get("policy_digest") == policy.digest,
                "observation belongs to a different intent or completion policy")
        require(item.get("target") == intent["target"] and item.get("service_uid") == intent["service_uid"], "wrong observed target")
        require(item.get("operation") == receipt["operation"] and item.get("observed_traffic") == expected_traffic(intent),
                "wrong observed operation or traffic")
        require(type(item.get("generation")) is str and item["generation"].isdigit()
                and int(item["generation"]) > int(intent["expected_generation"]), "invalid observed generation")
        evidence = item.get("evidence")
        require(type(evidence) is dict and set(evidence) == {"service_before", "operation", "health", "service_after"}
                and all(type(v) is str and re.fullmatch(r"[0-9a-f]{64}", v) for v in evidence.values()),
                "required evidence references missing")
        require(type(item.get("checks")) is dict and set(item["checks"]) == set(policy.value["required_checks"])
                and all(v is True for v in item["checks"].values()), "completion checks weakened")
        require(type(item.get("observed_at")) is int and receipt["recorded_at"] <= item["observed_at"] <= now,
                "invalid evidence time")
        require(item.get("challenge") not in challenges and bool(item.get("challenge")), "replayed observation")
        challenges.add(item["challenge"])
        if verified:
            require(item["observed_at"] > verified[-1]["observed_at"], "observations must be time ordered")
            require(item["generation"] == verified[-1]["generation"], "generation changed during completion window")
        verified.append(item)
    require(verified[-1]["observed_at"] - verified[0]["observed_at"] >= policy.value["min_window_seconds"], "observation window too short")
    require(now - verified[-1]["observed_at"] <= policy.value["evidence_max_age_seconds"], "final observation is stale")
    return {"kind": "COMPLETION_RECORD", "objective_id": intent["objective_id"], "intent_digest": digest(intent),
            "policy_digest": policy.digest, "operation": receipt["operation"], "generation": verified[-1]["generation"],
            "checks": policy.value["required_checks"], "sample_count": len(verified),
            "window_start": verified[0]["observed_at"], "window_end": verified[-1]["observed_at"],
            "completed_at": now, "sample_digests": [digest(s) for s in samples],
            "claim": "The approved operation is correlated with the observed traffic state; the configured candidate probe checks passed at the recorded sample times."}


class Coordinator:
    def __init__(self, policy, store, writer, observer, approval_public, writer_public, observer_public, clock=time.time):
        self.policy, self.store, self.writer, self.observer = policy, store, writer, observer
        self.approval_public, self.writer_public, self.observer_public = approval_public, writer_public, observer_public
        self.clock = clock

    def submit(self, approval):
        auth = self.policy.authorization(approval, self.approval_public, check_time=False)
        intent = auth["intent"]
        old = self.store.get(intent["objective_id"])
        if old:
            require(old["digest"] == digest(intent), "IDEMPOTENCY_KEY_REUSE_MISMATCH")
            return old
        self.policy.authorization(approval, self.approval_public, now=int(self.clock()))
        return self.store.create(intent["objective_id"], digest(intent), intent["target"], "READY",
                                 {"intent": intent, "approval": approval, "samples": [], "observations": 0, "next_at": 0})[0]

    def advance(self, objective_id):
        record = self.store.get(objective_id)
        require(record is not None, "unknown objective")
        if record["state"] == "COMPLETED" and not record["document"].get("settled"):
            doc = copy.deepcopy(record["document"])
            try:
                self.writer.settle(objective_id, doc["samples"])
                doc["settled"] = True
                doc.pop("settlement_error", None)
            except Exception as exc:
                doc["settlement_error"] = str(exc)[:300]
            return self.store.update(objective_id, "COMPLETED", doc, {"COMPLETED"})
        if record["state"] not in {"READY", "OBSERVING", "OUTCOME_UNKNOWN"}:
            return record
        doc = copy.deepcopy(record["document"])
        now = int(self.clock())
        if now < doc["next_at"]:
            return record
        intent = doc["intent"]
        try:
            dispatch = self.writer.dispatch(doc["approval"])
            receipt = verify(dispatch, self.writer_public, "DISPATCH_RECORD")
            require(receipt.get("intent_digest") == digest(intent), "writer returned a different intent")
            doc["dispatch"] = dispatch
            if receipt["state"] == "NOT_DISPATCHED":
                doc["next_action"] = "Review the precondition or expired approval; submit a newly approved objective if appropriate."
                return self.store.update(objective_id, "NEEDS_REVIEW", doc, {"READY", "OBSERVING", "OUTCOME_UNKNOWN"})
            challenge = uuid4().hex
            sample = self.observer.sample(intent, dispatch, challenge)
            observed = verify(sample, self.observer_public, "OBSERVATION")
            require(observed.get("challenge") == challenge and observed.get("intent_digest") == digest(intent), "unbound observer response")
            require(type(observed.get("observed_at")) is int and 0 <= int(self.clock()) - observed["observed_at"] <= self.policy.value["evidence_max_age_seconds"], "stale observation")
            doc["last_observation"] = sample
            doc["observations"] += 1
            verdict = observed.get("verdict")
            checks = observed.get("checks")
            failed_required_check = type(checks) is dict and any(
                checks.get(k) is False for k in self.policy.value["required_checks"])
            # Signed check facts retain their meaning even if the observer's
            # summary verdict is neutral or contradictory.
            if failed_required_check or verdict in {"CHECK_FAILED", "STATE_DIVERGED", "OPERATION_ERROR"}:
                doc["samples"] = []
                doc["next_action"] = "Operator review required. No rollback or repeat mutation is authorized by this objective."
                return self.store.update(objective_id, "NEEDS_REVIEW", doc, {"READY", "OBSERVING", "OUTCOME_UNKNOWN"})
            if verdict == "PASS":
                if doc["samples"] and doc["samples"][-1]["payload"]["generation"] != observed["generation"]:
                    doc["samples"] = []
                doc["samples"].append(sample)
            elif verdict != "BASE_SAMPLE":
                doc["samples"] = []
            try:
                completion = validate_completion(self.policy, intent, dispatch, doc["samples"], self.observer_public,
                                                 int(self.clock()), writer_public=self.writer_public)
            except Rejected:
                completion = None
            if completion:
                doc["completion"] = completion
                doc["settled"] = False
                doc["next_action"] = "Declared canary checks satisfied at the recorded times. Further rollout requires separate authority."
                self.store.update(objective_id, "COMPLETED", doc, {"READY", "OBSERVING", "OUTCOME_UNKNOWN"})
                return self.advance(objective_id)
            state = "OUTCOME_UNKNOWN" if receipt["state"] == "EFFECT_UNKNOWN" else "OBSERVING"
            doc["next_action"] = "Continue bounded read-only observation; no new dispatch."
        except Exception as exc:
            # A lost writer response is never converted to failure/no effect.
            state = "OUTCOME_UNKNOWN"
            doc["observations"] += 1
            doc["last_error"] = str(exc)[:300]
            doc["next_action"] = "Recover the original writer record, then observe; do not create a replacement intent."
        if doc["observations"] >= self.policy.value["max_observations"]:
            state = "NEEDS_REVIEW"
            doc["next_action"] = "Observation budget exhausted. Objective unresolved; inspect retained records and target independently."
        doc["next_at"] = int(self.clock()) + self.policy.value["sample_interval_seconds"]
        return self.store.update(objective_id, state, doc, {"READY", "OBSERVING", "OUTCOME_UNKNOWN"})
