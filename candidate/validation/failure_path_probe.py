"""Run the same failure sequence against either release without editing it.

python failure_path_probe.py --source /path/to/balance-canary-pilot --out result.json
The provider is simulated; runtime, signatures and durable stores are native.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import patch
from uuid import uuid4


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    sys.path.insert(0, str(source))
    from balance import __version__
    from balance.contracts import verify
    from tests.test_runtime import RuntimeTests

    fixture = RuntimeTests(methodName="runTest")
    fixture.setUp()
    try:
        fixture.cloud.health_mode = "failed"
        fixture.coordinator.submit(fixture.approval)
        read_service, read_probe = fixture.cloud.service, fixture.cloud.probe
        health_received = False

        def probe(nonce):
            nonlocal health_received
            result = read_probe(nonce)
            health_received = True
            return result

        def service(target):
            if health_received:
                raise TimeoutError("service_after timeout after candidate smoke=false")
            return read_service(target)

        with patch.object(fixture.cloud, "probe", side_effect=probe), patch.object(fixture.cloud, "service", side_effect=service):
            first = fixture.coordinator.advance("objective-1")

        negative = verify(first["document"]["last_observation"], fixture.root / "observer.pub", "OBSERVATION")
        assert negative["checks"] == {"ready": True, "smoke": False}
        raw_hash = negative["evidence"]["health"]
        raw = (fixture.root / "evidence" / (raw_hash + ".bin")).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == raw_hash
        assert json.loads(raw)["checks"]["smoke"] is False

        fixture.cloud.health_mode = "ok"
        resumed = fixture.make_coordinator()
        later_passes, states = [], []
        for fixture.now in (1010, 1020, 1030):
            # Establish that passing evidence is available even when the worker
            # correctly refuses to continue a job awaiting review.
            sample = fixture.observer.sample(fixture.intent, first["document"]["dispatch"], uuid4().hex)
            later_passes.append(sample)
            assert verify(sample, fixture.root / "observer.pub", "OBSERVATION")["verdict"] == "PASS"
            result = resumed.advance("objective-1")
            states.append(result["state"])
        evidence = {"version": __version__, "source_engine_sha256": hashlib.sha256((source / "balance/engine.py").read_bytes()).hexdigest(),
            "external_target": "SIMULATED", "cloud_calls": 0, "first_state": first["state"],
            "first_observation": first["document"]["last_observation"], "raw_health": json.loads(raw),
            "raw_health_sha256": raw_hash, "later_signed_passes": later_passes, "states_after_restart": states,
            "final_state": result["state"], "completion": result["document"].get("completion"),
            "writer_state": fixture.writer.store.get("objective-1")["state"], "simulated_mutations": fixture.cloud.calls,
            "objective_history": resumed.store.export(),
            "public_verification_keys": {r: (fixture.root / (r + ".pub")).read_text() for r in ("writer", "observer")}}
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(evidence, indent=2) + "\n")
        print(json.dumps({k: evidence[k] for k in ("version", "first_state", "states_after_restart", "final_state", "writer_state", "simulated_mutations")}, indent=2))
    finally:
        fixture.tearDown()


if __name__ == "__main__":
    main()
