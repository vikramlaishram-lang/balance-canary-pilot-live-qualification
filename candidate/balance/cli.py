from __future__ import annotations

import argparse
import json
import secrets
import time
from pathlib import Path

from .contracts import Policy, load, make_keys, require, sign, traffic_map


def output(path, value):
    path = Path(path)
    require(not path.exists(), "output exists; choose a new filename")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as f:
        f.write(json.dumps(value, indent=2) + "\n")
    print(str(path.resolve()))


def main():
    parser = argparse.ArgumentParser(description="Balance canary pilot: preparation and explicit operator authorization")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Create independent local signing keys and API tokens; makes no cloud calls")
    init.add_argument("--directory", required=True, type=Path)
    snapshot = sub.add_parser("snapshot", help="Read current service through the local operator's Google credentials")
    snapshot.add_argument("--policy", required=True)
    snapshot.add_argument("--out", required=True)
    prepare = sub.add_parser("prepare", help="Create an unsigned, exact canary intent from a saved service snapshot")
    prepare.add_argument("--policy", required=True)
    prepare.add_argument("--snapshot", required=True)
    prepare.add_argument("--candidate", required=True)
    prepare.add_argument("--percent", type=int, default=10)
    prepare.add_argument("--objective-id", required=True)
    prepare.add_argument("--out", required=True)
    approve = sub.add_parser("approve", help="Sign exactly the reviewed intent using the offline operator key")
    approve.add_argument("--policy", required=True)
    approve.add_argument("--intent", required=True)
    approve.add_argument("--key", required=True)
    approve.add_argument("--seconds", type=int, default=300)
    approve.add_argument("--out", required=True)
    send = sub.add_parser("submit", help="Submit a signed objective; authorizes its configured worker to execute")
    send.add_argument("--url", required=True)
    send.add_argument("--token-file", required=True)
    send.add_argument("--approval", required=True)
    status = sub.add_parser("status")
    status.add_argument("--url", required=True)
    status.add_argument("--token-file", required=True)
    status.add_argument("--objective-id", required=True)
    args = parser.parse_args()
    if args.command == "init":
        root = args.directory
        require(not root.exists(), "initialization directory must be new")
        root.mkdir(parents=True, mode=0o700)
        for role in ("authority", "writer", "observer"):
            make_keys(root / (role + ".key"), root / (role + ".pub"))
        for role in ("gateway", "writer", "observer"):
            path = root / (role + ".token")
            path.write_text(secrets.token_hex(32) + "\n")
            path.chmod(0o600)
        print("Created independent credentials. Keep authority.key off the runtime host; see DEPLOYMENT.md for ownership and IAM.")
    elif args.command == "snapshot":
        from .cloud import CloudRunReader
        policy = Policy(load(args.policy))
        service, _ = CloudRunReader(policy).service(policy.value["target"])
        output(args.out, service)
    elif args.command == "prepare":
        policy, snapshot = Policy(load(args.policy)), load(args.snapshot)
        require(snapshot.get("name") == policy.value["target"], "snapshot target mismatch")
        baseline = traffic_map(snapshot.get("trafficStatuses"), policy.value["target"])
        require(len(baseline) == 1 and next(iter(baseline.values())) == 100, "single explicit base revision required")
        intent = {"version": 1, "objective_id": args.objective_id, "target": policy.value["target"],
                  "service_uid": snapshot["uid"], "base_revision": next(iter(baseline)), "candidate_revision": args.candidate,
                  "base_percent": 100 - args.percent, "candidate_percent": args.percent,
                  "expected_etag": snapshot["etag"], "expected_generation": snapshot["generation"], "policy_digest": policy.digest}
        policy.validate_intent(intent)
        output(args.out, intent)
    elif args.command == "approve":
        policy, intent = Policy(load(args.policy)), load(args.intent)
        policy.validate_intent(intent)
        require(0 < args.seconds <= policy.value["max_grant_seconds"], "approval lifetime outside policy")
        now = int(time.time())
        output(args.out, sign({"kind": "AUTHORIZATION", "issuer": "operator", "holder": policy.value["holder"],
                               "intent": intent, "issued_at": now, "expires_at": now + args.seconds}, args.key))
    else:
        from .http import Client
        client = Client(args.url, args.token_file)
        result = client.request("/jobs", load(args.approval)) if args.command == "submit" else client.request("/jobs/" + args.objective_id)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
