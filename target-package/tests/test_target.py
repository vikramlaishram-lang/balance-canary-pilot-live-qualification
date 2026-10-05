import copy
import json
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, ProxyHandler, build_opener

from target.app import Identity, SERVICE, response, server
from provision import pin_record, REGION


class TargetTests(unittest.TestCase):
    def test_two_markers_and_probe_contract_over_http(self):
        seen = []
        for marker in ("baseline", "candidate"):
            identity = Identity(marker, SERVICE + "-fixture-" + marker, SERVICE)
            httpd = server(identity, host="127.0.0.1", port=0)
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            try:
                opener = build_opener(ProxyHandler({}))
                url = "http://127.0.0.1:" + str(httpd.server_port)
                with opener.open(url + "/", timeout=3) as result:
                    root = json.load(result)
                with opener.open(url + "/balance-health?nonce=" + "a" * 32, timeout=3) as result:
                    health = json.load(result)
                    self.assertEqual(result.headers["Cache-Control"], "no-store")
                self.assertEqual(root["VERSION"], marker)
                self.assertEqual(root["result"], "ecnalab")
                self.assertEqual(health["revision"], identity.revision)
                self.assertEqual(health["nonce"], "a" * 32)
                self.assertEqual(health["checks"], {"ready": True, "smoke": True})
                seen.append(health["revision"])
            finally:
                httpd.shutdown(); httpd.server_close(); thread.join(timeout=2)
        self.assertNotEqual(seen[0], seen[1])

    def test_nonce_is_required_unique_and_exact(self):
        identity = Identity("candidate", SERVICE + "-fixture-candidate", SERVICE)
        for query in ("", "?nonce=old", "?nonce=" + "a" * 32 + "&nonce=" + "b" * 32):
            with self.subTest(query=query):
                self.assertEqual(response(identity, "/balance-health" + query)[0], 400)

    def test_checks_evaluate_configuration_and_application_behavior(self):
        query = "/balance-health?nonce=" + "a" * 32
        self.assertFalse(response(Identity("unknown", "", SERVICE), query)[1]["checks"]["ready"])
        with patch("target.app.transform", return_value="broken"):
            self.assertFalse(response(Identity("candidate", SERVICE + "-fixture", SERVICE), query)[1]["checks"]["smoke"])

    def test_mutation_request_is_refused(self):
        httpd = server(Identity("baseline", SERVICE + "-fixture", SERVICE), host="127.0.0.1", port=0)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            request = Request("http://127.0.0.1:" + str(httpd.server_port), data=b"{}", method="POST")
            with self.assertRaises(HTTPError) as caught:
                build_opener(ProxyHandler({})).open(request, timeout=3)
            self.assertEqual(caught.exception.code, 405)
        finally:
            httpd.shutdown(); httpd.server_close(); thread.join(timeout=2)


class PinningTests(unittest.TestCase):
    def setUp(self):
        self.project = "balance-canary-pilot-fixture"
        self.target = f"projects/{self.project}/locations/{REGION}/services/{SERVICE}"
        self.base, self.candidate = SERVICE + "-fixture-base", SERVICE + "-fixture-candidate"
        self.image = REGION + "-docker.pkg.dev/" + self.project + "/balance-pilot/target@sha256:" + "a" * 64
        traffic = [{"type": "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION", "revision": self.base, "percent": 100}]
        self.service = {"name": self.target, "uid": "SIMULATED-UID", "generation": "3", "observedGeneration": "3",
            "etag": "SIMULATED-ETAG", "terminalCondition": {"state": "CONDITION_SUCCEEDED"},
            "traffic": traffic, "trafficStatuses": copy.deepcopy(traffic), "uri": "https://fixture.run.app"}
        self.revisions = {"revisions": [{"name": self.target + "/revisions/" + name,
            "containers": [{"image": self.image, "env": [{"name": "VERSION", "value": marker}]}]}
            for name, marker in ((self.base, "baseline"), (self.candidate, "candidate"))]}

    def test_pins_actual_fields_without_granting_authority(self):
        record = pin_record(self.project, self.service, self.revisions, self.base, self.candidate, self.image)
        self.assertEqual(record["service_uid"], self.service["uid"])
        self.assertEqual(record["initial_traffic"], {self.base: 100, self.candidate: 0})
        self.assertEqual(record["proposed_authorized_traffic"], {self.base: 90, self.candidate: 10})
        self.assertIs(record["authority_granted"], False)
        self.assertIsNone(record["writer_principal"])
        self.assertEqual(record["balance_live_consequence"], "NOT_RUN")

    def test_rejects_extra_revision_wrong_marker_and_wrong_initial_traffic(self):
        extra = copy.deepcopy(self.revisions)
        extra["revisions"].append(copy.deepcopy(extra["revisions"][0]))
        with self.assertRaisesRegex(ValueError, "exactly"):
            pin_record(self.project, self.service, extra, self.base, self.candidate, self.image)
        wrong = copy.deepcopy(self.revisions)
        wrong["revisions"][1]["containers"][0]["env"][0]["value"] = "baseline"
        with self.assertRaisesRegex(ValueError, "marker"):
            pin_record(self.project, self.service, wrong, self.base, self.candidate, self.image)
        drifted = copy.deepcopy(self.service)
        drifted["trafficStatuses"][0]["percent"] = 90
        drifted["trafficStatuses"].append({"type": "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION", "revision": self.candidate, "percent": 10})
        with self.assertRaisesRegex(ValueError, "initial traffic"):
            pin_record(self.project, drifted, self.revisions, self.base, self.candidate, self.image)


if __name__ == "__main__":
    unittest.main()
