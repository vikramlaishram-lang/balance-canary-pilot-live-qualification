"""Prepare one NEW disposable project and exactly two revisions. Never sets 90/10.

Cloud creation is not attempted by `plan`. `create` requires an authenticated
operator with Docker, project-creation permissions and a selected billing account.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from urllib.request import Request, HTTPRedirectHandler, ProxyHandler, build_opener
import zipfile

ROOT = Path(__file__).resolve().parent
REGION = "asia-south1"
SERVICE = "balance-canary-target"
REPOSITORY = "balance-pilot"
CANDIDATE = ROOT / "runtime/BALANCE_Canary_Pilot_0.1.1_2026-09-12.zip"
CANDIDATE_SHA = "00ea748bdacab7b743bf54db2fbf6ee976ac6cdbc249cc3a8c176b80346cf74e"


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def write(path, value):
    with Path(path).open("x") as f:
        f.write(json.dumps(value, indent=2) + "\n")


def revision_name(value):
    require(type(value) is str and bool(value), "provider revision identity missing")
    name = value.rsplit("/", 1)[-1]
    require(bool(re.fullmatch(SERVICE + r"-[a-z0-9-]+", name)), "unexpected revision name")
    return name


def pin_record(project, service, revisions, base, candidate, image):
    target = f"projects/{project}/locations/{REGION}/services/{SERVICE}"
    require(service.get("name") == target and service.get("uid"), "wrong or unidentified target instance")
    require(service.get("reconciling", False) is False, "service is still reconciling")
    require(service.get("terminalCondition", {}).get("state") == "CONDITION_SUCCEEDED", "service is not ready")
    require(service.get("generation") == service.get("observedGeneration") and service.get("generation"), "generation not observed")
    require(bool(service.get("etag")), "service etag missing")
    require(base != candidate, "two distinct revisions required")
    require(not revisions.get("nextPageToken"), "revision inventory incomplete")
    rows = revisions.get("revisions", [])
    require(len(rows) == 2 and {revision_name(r.get("name")) for r in rows} == {base, candidate}, "exactly the two deployed revisions must exist")
    for revision in rows:
        require(revision["name"].startswith(target + "/revisions/"), "revision outside target")
        containers = revision.get("containers", [])
        require(len(containers) == 1 and containers[0].get("image") == image, "revision image does not match pinned digest")
        env = {e["name"]: e.get("value") for e in containers[0].get("env", [])}
        expected = "baseline" if revision_name(revision["name"]) == base else "candidate"
        require(env.get("VERSION") == expected, "deployed version marker mismatch")
    for field in ("traffic", "trafficStatuses"):
        traffic = service.get(field)
        require(type(traffic) is list and bool(traffic), "traffic evidence missing: " + field)
        percentages = {}
        for t in traffic:
            require(t.get("type") == "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION" and not t.get("tag"), "explicit untagged traffic required")
            name = revision_name(t.get("revision"))
            require(name in {base, candidate} and name not in percentages, "unexpected/duplicate traffic revision")
            percent = t.get("percent", 0)
            require(type(percent) is int and 0 <= percent <= 100, "invalid traffic percent")
            percentages[name] = percent
        require({n: v for n, v in percentages.items() if v} == {base: 100}, "initial traffic must remain baseline 100%, candidate 0%")
    uri = service.get("uri")
    require(type(uri) is str and uri.startswith("https://") and uri.endswith(".run.app"), "provider service URL missing or unexpected")
    return {"kind": "DISPOSABLE_TARGET_RECORD", "status": "TARGET_PREPARED_QUALIFICATION_NOT_RUN",
        "recorded_at": datetime.now(timezone.utc).isoformat(), "project": project, "region": REGION,
        "service": SERVICE, "target": target, "service_uid": service["uid"], "service_uri": uri,
        "base_revision": base, "candidate_revision": candidate,
        "initial_traffic": {base: 100, candidate: 0}, "proposed_authorized_traffic": {base: 90, candidate: 10},
        "observed_generation": service["observedGeneration"], "etag": service["etag"], "image": image,
        "balance_candidate_zip_sha256": CANDIDATE_SHA,
        "authority_granted": False, "writer_principal": None, "observer_principal": None,
        "iam_isolation": "NOT_QUALIFIED", "balance_live_consequence": "NOT_RUN"}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("provider redirect refused")


class Run:
    def __init__(self, directory, project):
        self.directory, self.project, self.sequence = directory, project, 0

    def command(self, args, *, parse=False):
        self.sequence += 1
        prefix = self.directory / f"{self.sequence:02d}"
        write(str(prefix) + "-command.json", args)
        print("Running:", " ".join(args), flush=True)
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=1200)
        except subprocess.TimeoutExpired:
            raise RuntimeError("Command timed out; effects may have occurred. Inspect this project before any continuation.") from None
        Path(str(prefix) + "-stdout.txt").write_text(result.stdout)
        Path(str(prefix) + "-stderr.txt").write_text(result.stderr)
        require(result.returncode == 0, f"Command failed ({result.returncode}); inspect retained output. No automated replay is attempted.")
        return json.loads(result.stdout) if parse else result.stdout.strip()

    def gcloud(self, *args, parse=False):
        flags = ["--project=" + self.project, "--quiet"]
        if parse:
            flags.append("--format=json")
        return self.command(["gcloud", *args, *flags], parse=parse)

    def resource(self, name, filename):
        # The access token is never printed or included in retained command logs.
        token = subprocess.check_output(["gcloud", "auth", "print-access-token"], text=True, timeout=60).strip()
        request = Request("https://run.googleapis.com/v2/" + name,
                          headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
        opener = build_opener(ProxyHandler({}), NoRedirect())
        with opener.open(request, timeout=30) as reply:
            raw = reply.read(2 * 1024 * 1024 + 1)
        require(len(raw) <= 2 * 1024 * 1024, "resource response exceeds capture limit")
        (self.directory / filename).write_bytes(raw)
        return json.loads(raw)


def create(args):
    require(re.fullmatch(r"balance-canary-pilot-[a-z0-9][a-z0-9-]*[a-z0-9]", args.project_id or "")
            and len(args.project_id) <= 30, "supply an unused 6–30 character disposable project ID starting balance-canary-pilot-")
    require(re.fullmatch(r"[A-Za-z0-9]{6}(?:-[A-Za-z0-9]{6}){2}", args.billing_account or ""), "select a real billing account")
    require(shutil.which("gcloud") and shutil.which("docker"), "authenticated gcloud and a running Docker engine are required")
    require(CANDIDATE.is_file() and hashlib.sha256(CANDIDATE.read_bytes()).hexdigest() == CANDIDATE_SHA, "pinned Balance archive is missing or changed")
    output = args.out.resolve()
    require(not output.exists(), "choose a new evidence directory; existing run state is not overwritten")
    output.mkdir(parents=True)
    run = Run(output, args.project_id)
    run.command(["docker", "info", "--format", "{{json .ServerVersion}}"])
    accounts = run.command(["gcloud", "auth", "list", "--filter=status:ACTIVE", "--format=json"], parse=True)
    require(len(accounts) == 1, "select exactly one active operator identity before creation")
    project_args = ["projects", "create", args.project_id, "--name=Balance disposable qualification",
                    "--labels=purpose=balance-qualification,disposable=true"]
    if args.organization:
        project_args.append("--organization=" + args.organization)
    if args.folder:
        project_args.append("--folder=" + args.folder)
    # Always create. An existing project is a failure, never an implicit reuse.
    run.command(["gcloud", *project_args, "--quiet"])
    project = run.gcloud("projects", "describe", args.project_id, parse=True)
    require(project.get("projectId") == args.project_id, "created project identity mismatch")
    run.gcloud("billing", "projects", "link", args.project_id, "--billing-account=" + args.billing_account)
    run.gcloud("services", "enable", "run.googleapis.com", "artifactregistry.googleapis.com", "iam.googleapis.com")
    run.gcloud("artifacts", "repositories", "create", REPOSITORY, "--repository-format=docker", "--location=" + REGION)
    run.gcloud("iam", "service-accounts", "create", "balance-target-runtime", "--display-name=Disposable target identity")
    target_account = "balance-target-runtime@" + args.project_id + ".iam.gserviceaccount.com"
    host = REGION + "-docker.pkg.dev"
    run.gcloud("auth", "configure-docker", host)
    repository_image = f"{host}/{args.project_id}/{REPOSITORY}/target"
    tagged_image = repository_image + ":qualification"
    run.command(["docker", "build", "--pull", "--platform=linux/amd64", "--tag", tagged_image, str(ROOT / "target")])
    run.command(["docker", "push", tagged_image])
    inspected = run.command(["docker", "image", "inspect", tagged_image], parse=True)
    images = [v for v in inspected[0].get("RepoDigests", []) if v.startswith(repository_image + "@sha256:")]
    require(len(images) == 1 and re.fullmatch(r"sha256:[0-9a-f]{64}", images[0].split("@", 1)[1]), "pushed immutable image digest unavailable")
    image = images[0]
    deploy_args = ["run", "deploy", SERVICE, "--image=" + image, "--region=" + REGION,
        "--service-account=" + target_account, "--no-allow-unauthenticated", "--invoker-iam-check",
        "--no-session-affinity", "--min-instances=0", "--max-instances=1", "--cpu=1", "--memory=256Mi",
        "--concurrency=10", "--timeout=10s", "--port=8080"]
    target = f"projects/{args.project_id}/locations/{REGION}/services/{SERVICE}"
    run.gcloud(*deploy_args, "--set-env-vars=VERSION=baseline")
    base_service = run.resource(target, "base-service-v2.json")
    base = revision_name(base_service.get("latestCreatedRevision"))
    run.gcloud("run", "services", "update-traffic", SERVICE, "--region=" + REGION, "--to-revisions=" + base + "=100")
    run.gcloud(*deploy_args, "--set-env-vars=VERSION=candidate", "--no-traffic")
    candidate_service = run.resource(target, "candidate-service-v2.json")
    candidate = revision_name(candidate_service.get("latestCreatedRevision"))
    final = run.resource(target, "final-service-v2.json")
    revisions = run.resource(target + "/revisions", "revisions-v2.json")
    record = pin_record(args.project_id, final, revisions, base, candidate, image)
    record["target_runtime_principal"] = target_account
    record["operator_account"] = accounts[0].get("account")
    record["project_number"] = project.get("projectNumber")
    record["source_sha256"] = hashlib.sha256((ROOT / "target/app.py").read_bytes()).hexdigest()
    record["raw_evidence_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in output.glob("*-v2.json")}
    with zipfile.ZipFile(CANDIDATE) as package:
        policy = json.loads(package.read("balance-canary-pilot/policy.example.json"))
    policy.update(target=target, health_url=record["service_uri"] + "/balance-health", health_audience=record["service_uri"])
    write(output / "policy.json", policy)
    record["policy_file_sha256"] = hashlib.sha256((output / "policy.json").read_bytes()).hexdigest()
    write(output / "target-record.json", record)
    (output / "target-record.sha256").write_text(hashlib.sha256((output / "target-record.json").read_bytes()).hexdigest() + "  target-record.json\n")
    print("Target prepared at baseline 100%. Balance authority, IAM and live consequence qualification have not run.")
    print(str(output / "target-record.json"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan", help="Print target shape without creating resources")
    start = sub.add_parser("create", help="Create a NEW billed disposable project and deploy exactly two target revisions")
    start.add_argument("--project-id", required=True)
    start.add_argument("--billing-account", required=True)
    parent = start.add_mutually_exclusive_group()
    parent.add_argument("--organization")
    parent.add_argument("--folder")
    start.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "plan":
        print(json.dumps({"status": "PREPARED_NOT_DEPLOYED", "project": None, "region": REGION, "service": SERVICE,
            "base_revision": None, "candidate_revision": None, "markers": ["baseline", "candidate"],
            "initial_traffic": {"base": 100, "candidate": 0}, "pilot_consequence": {"base": 90, "candidate": 10},
            "balance_candidate_sha256": CANDIDATE_SHA,
            "required_operator_inputs": ["unused disposable project ID", "selected billing account", "authenticated gcloud and Docker", "organization/folder if required"]}, indent=2))
    else:
        try:
            create(args)
        except Exception as exc:
            print("STOPPED:", str(exc), file=sys.stderr)
            print("Creation may be partial. Preserve the evidence directory and inspect actual resources before continuing.", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
