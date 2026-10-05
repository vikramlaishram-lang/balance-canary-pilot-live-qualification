import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from uuid import uuid4
from wsgiref.simple_server import make_server, WSGIRequestHandler

from balance.contracts import Policy, Rejected, digest, make_keys, sign, strict_json, verify
from balance.engine import Coordinator, Observer, Writer, validate_completion
from balance.http import Application, Client
from balance.store import Store


class CloudFixture:
    """Simulated provider; the real cloud client is tested separately for request shape."""
    def __init__(self, target, clock):
        self.target, self.clock, self.calls = target, clock, 0
        self.mode, self.health_mode = "ok", "ok"
        self.value = {"name": target, "uid": "service-instance-01", "etag": "v10", "generation": "10",
                      "observedGeneration": "10", "reconciling": False,
                      "terminalCondition": {"state": "CONDITION_SUCCEEDED"},
                      "trafficStatuses": [{"revision": "payments-base", "percent": 100}]}
        self.op = None

    def service(self, target):
        assert target == self.target
        if self.mode == "observer_down" and self.calls:
            raise TimeoutError("simulated observer outage")
        value = copy.deepcopy(self.value)
        return value, json.dumps(value).encode()

    def patch(self, intent):
        self.calls += 1
        assert intent["expected_etag"] == self.value["etag"]
        self.value.update(etag="v11", generation="11", observedGeneration="11", trafficStatuses=[
            {"revision": intent["base_revision"], "percent": intent["base_percent"]},
            {"revision": intent["candidate_revision"], "percent": intent["candidate_percent"]}])
        self.op = {"name": self.target.split("/services/")[0] + "/operations/op-1", "done": True,
                   "response": copy.deepcopy(self.value)}
        if self.mode == "lost_ack":
            raise TimeoutError("simulated accepted mutation with lost response")
        return {"name": self.op["name"]}

    def operation(self, name):
        assert name == self.op["name"]
        return copy.deepcopy(self.op), json.dumps(self.op).encode()

    def probe(self, nonce):
        value = {"nonce": nonce, "revision": "payments-candidate", "checks": {"ready": True, "smoke": True}}
        if self.health_mode == "missing":
            value["checks"] = {}
        if self.health_mode == "failed":
            value["checks"]["smoke"] = False
        if self.health_mode == "stale":
            value["nonce"] = "old"
        if self.health_mode == "wrong_revision":
            value["revision"] = "payments-unrelated"
        if self.health_mode == "base":
            value["revision"] = "payments-base"
        if self.health_mode == "drift":
            self.rollback()
        return value, json.dumps(value).encode()

    def rollback(self):
        self.value.update(etag="v12", generation="12", observedGeneration="12",
                          trafficStatuses=[{"revision": "payments-base", "percent": 100}])


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.now = 1000
        self.clock = lambda: self.now
        for role in ("authority", "writer", "observer"):
            make_keys(self.root / (role + ".key"), self.root / (role + ".pub"))
        self.policy = Policy({"version": 1, "target": "projects/pilot-project/locations/us-central1/services/payments",
                              "holder": "balance-coordinator", "max_candidate_percent": 10, "max_grant_seconds": 900,
                              "health_url": "https://payments.example.test/balance-health", "health_audience": "",
                              "required_checks": ["ready", "smoke"], "min_samples": 3, "min_window_seconds": 20,
                              "sample_interval_seconds": 5, "max_observations": 20, "evidence_max_age_seconds": 30})
        self.intent = {"version": 1, "objective_id": "objective-1", "target": self.policy.value["target"],
                       "service_uid": "service-instance-01", "base_revision": "payments-base",
                       "candidate_revision": "payments-candidate", "base_percent": 90, "candidate_percent": 10,
                       "expected_etag": "v10", "expected_generation": "10", "policy_digest": self.policy.digest}
        self.cloud = CloudFixture(self.intent["target"], self.clock)
        self.writer = Writer(self.policy, Store(self.root / "writer.db", writer=True), self.cloud,
                             self.root / "authority.pub", self.root / "writer.key", self.root / "observer.pub", self.clock)
        self.observer = Observer(self.policy, self.cloud, self.root / "writer.pub", self.root / "observer.key",
                                 self.root / "evidence", self.clock)
        self.coordinator = self.make_coordinator()
        self.approval = self.authorize(self.intent)

    def tearDown(self):
        self.temp.cleanup()

    def make_coordinator(self, writer=None, observer=None):
        return Coordinator(self.policy, Store(self.root / "jobs.db"), writer or self.writer, observer or self.observer,
                           self.root / "authority.pub", self.root / "writer.pub", self.root / "observer.pub", self.clock)

    def authorize(self, intent):
        return sign({"kind": "AUTHORIZATION", "issuer": "operator", "holder": "balance-coordinator", "intent": intent,
                     "issued_at": self.now, "expires_at": self.now + 300}, self.root / "authority.key")

    def samples(self):
        receipt = self.writer.dispatch(self.approval)
        samples = []
        for self.now in (1000, 1010, 1020):
            samples.append(self.observer.sample(self.intent, receipt, uuid4().hex))
        return receipt, samples

    def complete(self, coordinator=None):
        coordinator = coordinator or self.coordinator
        coordinator.submit(self.approval)
        for self.now in (1000, 1010, 1020):
            result = coordinator.advance("objective-1")
        return result

    def test_end_to_end_completion_and_exact_replay(self):
        result = self.complete()
        self.assertEqual(result["state"], "COMPLETED")
        self.assertTrue(result["document"]["settled"])
        self.assertEqual(self.cloud.calls, 1)
        self.assertEqual(self.coordinator.submit(self.approval), result)
        self.now = 5000
        self.assertEqual(self.writer.dispatch(self.approval), result["document"]["dispatch"])
        self.assertEqual(self.cloud.calls, 1)
        self.writer.store.verify_history()
        self.coordinator.store.verify_history()

    def test_mutating_any_intent_field_invalidates_authorization(self):
        for field in self.intent:
            with self.subTest(field=field):
                approval = copy.deepcopy(self.approval)
                old = approval["payload"]["intent"][field]
                approval["payload"]["intent"][field] = old + 1 if type(old) is int else old + "x"
                with self.assertRaises(Rejected):
                    self.writer.dispatch(approval)
        self.assertEqual(self.cloud.calls, 0)

    def test_same_id_new_validly_signed_intent_rejected(self):
        self.writer.dispatch(self.approval)
        changed = {**self.intent, "candidate_percent": 5, "base_percent": 95}
        with self.assertRaisesRegex(Rejected, "IDEMPOTENCY"):
            self.writer.dispatch(self.authorize(changed))
        self.assertEqual(self.cloud.calls, 1)

    def test_caller_cannot_supply_or_weaken_policy_checks(self):
        changed = {**self.intent, "required_checks": []}
        with self.assertRaises(Rejected):
            self.writer.dispatch(self.authorize(changed))
        with self.assertRaises(Rejected):
            Policy({**self.policy.value, "required_checks": []})
        self.cloud.health_mode = "missing"
        self.coordinator.submit(self.approval)
        result = self.coordinator.advance("objective-1")
        self.assertEqual(result["state"], "NEEDS_REVIEW")
        self.assertNotIn("completion", result["document"])

    def test_expired_authority_has_no_dispatch(self):
        self.now = 1400
        with self.assertRaises(Rejected):
            self.writer.dispatch(self.approval)
        self.assertEqual(self.cloud.calls, 0)

    def test_expiry_during_preflight_has_no_dispatch(self):
        original = self.cloud.service
        def late(target):
            result = original(target)
            self.now = 1400
            return result
        self.cloud.service = late
        result = self.writer.dispatch(self.approval)
        self.assertEqual(result["payload"]["state"], "NOT_DISPATCHED")
        self.assertEqual(self.cloud.calls, 0)

    def test_stale_target_version_has_no_dispatch(self):
        self.cloud.value["etag"] = "different"
        self.assertEqual(self.writer.dispatch(self.approval)["payload"]["state"], "NOT_DISPATCHED")
        self.assertEqual(self.cloud.calls, 0)

    def test_service_recreated_with_same_name_has_no_dispatch(self):
        self.cloud.value["uid"] = "new-service-instance"
        self.assertEqual(self.writer.dispatch(self.approval)["payload"]["state"], "NOT_DISPATCHED")
        self.assertEqual(self.cloud.calls, 0)

    def test_lost_ack_remains_unknown_despite_matching_state(self):
        self.cloud.mode = "lost_ack"
        self.coordinator.submit(self.approval)
        result = self.coordinator.advance("objective-1")
        self.assertEqual(result["state"], "OUTCOME_UNKNOWN")
        self.assertEqual(result["document"]["last_observation"]["payload"]["verdict"], "ATTRIBUTION_UNKNOWN")
        self.now += 10
        self.make_coordinator().advance("objective-1")
        self.assertEqual(self.cloud.calls, 1)
        self.assertEqual(self.writer.store.get("objective-1")["state"], "UNKNOWN")

    def test_unknown_intent_cannot_be_bypassed_with_new_objective_id(self):
        self.cloud.mode = "lost_ack"
        self.writer.dispatch(self.approval)
        changed = {**self.intent, "objective_id": "replacement-id"}
        with self.assertRaisesRegex(Rejected, "UNRESOLVED"):
            self.writer.dispatch(self.authorize(changed))
        self.assertEqual(self.cloud.calls, 1)

    def test_intervening_rollback_not_overwritten_on_retry(self):
        self.cloud.mode = "lost_ack"
        self.writer.dispatch(self.approval)
        self.cloud.rollback()
        self.writer.dispatch(self.approval)
        self.assertEqual(self.cloud.calls, 1)
        self.assertEqual(self.cloud.value["trafficStatuses"], [{"revision": "payments-base", "percent": 100}])

    def test_observer_outage_retained_and_recovered_without_redispatch(self):
        self.cloud.mode = "observer_down"
        self.coordinator.submit(self.approval)
        first = self.coordinator.advance("objective-1")
        self.assertEqual(first["document"]["last_observation"]["payload"]["verdict"], "OBSERVATION_UNAVAILABLE")
        self.cloud.mode = "ok"
        resumed = self.make_coordinator()
        for self.now in (1010, 1020, 1030):
            result = resumed.advance("objective-1")
        self.assertEqual(result["state"], "COMPLETED")
        self.assertEqual(self.cloud.calls, 1)

    def test_external_change_during_health_observation_blocks_completion(self):
        self.cloud.health_mode = "drift"
        self.coordinator.submit(self.approval)
        result = self.coordinator.advance("objective-1")
        self.assertEqual(result["document"]["last_observation"]["payload"]["verdict"], "OBSERVATION_UNAVAILABLE")
        self.assertFalse(result["document"]["samples"])

    def test_failed_candidate_check_requires_review(self):
        self.cloud.health_mode = "failed"
        self.assertEqual(self.complete()["state"], "NEEDS_REVIEW")
        self.assertEqual(self.cloud.calls, 1)

    def test_failed_check_survives_final_read_outage_and_restart(self):
        self.cloud.health_mode = "failed"
        self.coordinator.submit(self.approval)
        read_service, read_probe = self.cloud.service, self.cloud.probe
        health_received = False

        def probe(nonce):
            nonlocal health_received
            result = read_probe(nonce)
            health_received = True
            return result

        def service(target):
            if health_received:
                raise TimeoutError("service_after unavailable after failed candidate check")
            return read_service(target)

        with patch.object(self.cloud, "probe", side_effect=probe), patch.object(self.cloud, "service", side_effect=service):
            first = self.coordinator.advance("objective-1")

        observed = verify(first["document"]["last_observation"], self.root / "observer.pub", "OBSERVATION")
        self.assertEqual(observed["verdict"], "CHECK_FAILED")
        self.assertEqual(observed["checks"], {"ready": True, "smoke": False})
        self.assertIn("service_after unavailable", observed["reason"])
        self.assertNotIn("service_after", observed["evidence"])
        raw = (self.root / "evidence" / (observed["evidence"]["health"] + ".bin")).read_bytes()
        self.assertIs(json.loads(raw)["checks"]["smoke"], False)
        self.assertEqual(first["state"], "NEEDS_REVIEW")

        self.cloud.health_mode = "ok"
        resumed = self.make_coordinator()
        for self.now in (1010, 1020, 1030):
            sample = self.observer.sample(self.intent, first["document"]["dispatch"], uuid4().hex)
            self.assertEqual(verify(sample, self.root / "observer.pub", "OBSERVATION")["verdict"], "PASS")
            result = resumed.advance("objective-1")
            self.assertEqual(result, first)
            self.assertNotIn("completion", result["document"])
        self.assertEqual(self.cloud.calls, 1)
        self.assertEqual(self.writer.store.get("objective-1")["state"], "SUBMITTED")

    def test_signed_failed_check_requires_review_despite_neutral_verdict(self):
        self.cloud.health_mode = "failed"
        self.coordinator.submit(self.approval)
        observe = self.observer.sample

        def neutral_verdict(intent, dispatch, challenge):
            sample = observe(intent, dispatch, challenge)
            payload = copy.deepcopy(sample["payload"])
            self.assertIs(payload["checks"]["smoke"], False)
            # Simulate a trusted observer emitting the old contradictory claim.
            payload["verdict"] = "OBSERVATION_UNAVAILABLE"
            return sign(payload, self.root / "observer.key")

        with patch.object(self.observer, "sample", side_effect=neutral_verdict):
            result = self.coordinator.advance("objective-1")
        observed = verify(result["document"]["last_observation"], self.root / "observer.pub", "OBSERVATION")
        self.assertEqual(observed["verdict"], "OBSERVATION_UNAVAILABLE")
        self.assertIs(observed["checks"]["smoke"], False)
        self.assertEqual(result["state"], "NEEDS_REVIEW")
        self.assertFalse(result["document"]["samples"])
        self.assertNotIn("completion", result["document"])
        self.assertEqual(self.cloud.calls, 1)

    def test_stale_or_wrong_revision_probe_never_counts(self):
        receipt = self.writer.dispatch(self.approval)
        for mode in ("stale", "wrong_revision"):
            self.cloud.health_mode = mode
            self.assertEqual(self.observer.sample(self.intent, receipt, uuid4().hex)["payload"]["verdict"], "OBSERVATION_UNAVAILABLE")

    def test_signed_but_weakened_observation_cannot_complete(self):
        receipt, samples = self.samples()
        payload = copy.deepcopy(samples[-1]["payload"])
        payload["checks"] = {"ready": True}
        samples[-1] = sign(payload, self.root / "observer.key")
        with self.assertRaisesRegex(Rejected, "checks weakened"):
            validate_completion(self.policy, self.intent, receipt, samples, self.root / "observer.pub", self.now,
                                writer_public=self.root / "writer.pub")

    def test_duplicate_or_stale_observation_cannot_complete(self):
        receipt, samples = self.samples()
        with self.assertRaises(Rejected):
            validate_completion(self.policy, self.intent, receipt, [samples[0]] * 3, self.root / "observer.pub", self.now,
                                writer_public=self.root / "writer.pub")
        with self.assertRaisesRegex(Rejected, "stale"):
            validate_completion(self.policy, self.intent, receipt, samples, self.root / "observer.pub", self.now + 100,
                                writer_public=self.root / "writer.pub")

    def test_wrong_target_and_wrong_signer_observations_rejected(self):
        receipt, samples = self.samples()
        altered = copy.deepcopy(samples[-1]["payload"])
        altered["target"] += "-other"
        for role in ("observer", "writer"):
            bad = samples[:-1] + [sign(altered, self.root / (role + ".key"))]
            with self.assertRaises(Rejected):
                validate_completion(self.policy, self.intent, receipt, bad, self.root / "observer.pub", self.now,
                                    writer_public=self.root / "writer.pub")

    def test_concurrent_same_intent_has_one_mutation(self):
        original = self.cloud.patch
        def slow(intent):
            time.sleep(0.05)
            return original(intent)
        self.cloud.patch = slow
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda _: self.writer.dispatch(self.approval), range(16)))
        self.assertEqual(self.cloud.calls, 1)
        self.writer.store.verify_history()

    def test_process_death_after_effect_preserves_reservation(self):
        (self.root / "approval.json").write_text(json.dumps(self.approval))
        (self.root / "policy.json").write_text(json.dumps(self.policy.value))
        script = r'''
import json, os, sys
from pathlib import Path
from balance.contracts import Policy,load
from balance.engine import Writer
from balance.store import Store
from tests.test_runtime import CloudFixture
root=Path(sys.argv[1]); policy=Policy(load(root/'policy.json'))
cloud=CloudFixture(policy.value['target'],lambda:1000)
original=cloud.patch
def crash(intent):
    result=original(intent)
    (root/'external-effect.json').write_text(json.dumps(cloud.value))
    os._exit(73)
cloud.patch=crash
writer=Writer(policy,Store(root/'writer.db',writer=True),cloud,root/'authority.pub',root/'writer.key',root/'observer.pub',lambda:1000)
writer.dispatch(load(root/'approval.json'))
'''
        child = subprocess.run([sys.executable, "-c", script, str(self.root)], capture_output=True, text=True, timeout=15)
        self.assertEqual(child.returncode, 73, child.stderr)
        self.assertTrue((self.root / "external-effect.json").exists())
        self.assertEqual(self.writer.store.get("objective-1")["state"], "RESERVED")
        self.assertEqual(self.writer.dispatch(self.approval)["payload"]["state"], "EFFECT_UNKNOWN")
        self.assertEqual(self.cloud.calls, 0)

    def test_completion_durable_before_settlement_then_resumes_after_expiry(self):
        with patch.object(self.writer, "settle", side_effect=ConnectionError("offline settlement outage")):
            result = self.complete()
        self.assertEqual(result["state"], "COMPLETED")
        self.assertFalse(result["document"]["settled"])
        self.now = 5000
        result = self.make_coordinator().advance("objective-1")
        self.assertTrue(result["document"]["settled"])
        self.assertEqual(self.cloud.calls, 1)

    def test_history_detects_edit_without_claiming_external_anchoring(self):
        self.writer.dispatch(self.approval)
        with self.writer.store.connect() as db:
            db.execute("UPDATE events SET event='{}' WHERE sequence=1")
        with self.assertRaises(Rejected):
            self.writer.store.verify_history()

    def test_duplicate_json_keys_and_noninteger_numbers_rejected(self):
        for raw in ('{"a":1,"a":2}', '{"a":0.1}', '{"a":NaN}'):
            with self.assertRaises(Rejected):
                strict_json(raw)

    def test_cloud_request_carries_native_etag_and_only_traffic_mask(self):
        from balance.cloud import CloudRunWriter
        seen = []
        class Transport:
            def request(inner, method, url, body):
                seen.append((method, url, body))
                return {"name": "operation"}, b"{}"
        CloudRunWriter(self.policy, Transport()).patch(self.intent)
        method, url, body = seen[0]
        self.assertEqual(method, "PATCH")
        self.assertTrue(url.endswith("?updateMask=traffic&allowMissing=false"))
        self.assertEqual(body["etag"], "v10")
        self.assertEqual(set(body), {"name", "etag", "traffic"})

    def test_protojson_omitted_false_reconciling_is_supported(self):
        self.cloud.value.pop("reconciling")
        self.assertEqual(self.complete()["state"], "COMPLETED")

    def test_contradictory_ready_state_still_rejected(self):
        self.cloud.value["reconciling"] = True
        self.assertEqual(self.writer.dispatch(self.approval)["payload"]["state"], "NOT_DISPATCHED")
        self.assertEqual(self.cloud.calls, 0)

    def test_completion_requires_generation_and_raw_evidence_references(self):
        receipt, samples = self.samples()
        for field, value in (("generation", None), ("evidence", {})):
            payload = copy.deepcopy(samples[-1]["payload"])
            payload[field] = value
            changed = samples[:-1] + [sign(payload, self.root / "observer.key")]
            with self.assertRaises(Rejected):
                validate_completion(self.policy, self.intent, receipt, changed, self.root / "observer.pub", self.now,
                                    writer_public=self.root / "writer.pub")

    def test_observation_budget_ends_in_review_without_erasing_unknown(self):
        self.cloud.mode = "lost_ack"
        self.coordinator.submit(self.approval)
        for _ in range(self.policy.value["max_observations"]):
            result = self.coordinator.advance("objective-1")
            self.now += 10
        self.assertEqual(result["state"], "NEEDS_REVIEW")
        self.assertEqual(self.writer.store.get("objective-1")["state"], "UNKNOWN")
        self.assertEqual(self.cloud.calls, 1)

    def test_real_http_role_boundaries_and_end_to_end(self):
        class Quiet(WSGIRequestHandler):
            def log_message(self, *args):
                pass
        servers, clients = [], []
        for role, engine in (("writer", self.writer), ("observer", self.observer)):
            token = self.root / (role + ".token")
            token.write_text(role + "a" * 64)
            server = make_server("127.0.0.1", 0, Application(role, engine, token), handler_class=Quiet)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            servers.append((server, thread))
            clients.append(Client(f"http://127.0.0.1:{server.server_port}", token))
        try:
            with self.assertRaises(Rejected):
                clients[1].request("/dispatch", self.approval)
            wrong = self.root / "wrong.token"
            wrong.write_text("b" * 64)
            with self.assertRaises(Rejected):
                Client(clients[0].url, wrong).dispatch(self.approval)
            result = self.complete(self.make_coordinator(*clients))
            self.assertEqual(result["state"], "COMPLETED")
            self.assertEqual(self.cloud.calls, 1)
            # Exact raw evidence can be recovered independently by digest.
            key = result["document"]["samples"][0]["payload"]["evidence"]["health"]
            import base64, hashlib
            raw = base64.b64decode(clients[1].request("/evidence/" + key)["base64"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), key)
        finally:
            for server, thread in servers:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
