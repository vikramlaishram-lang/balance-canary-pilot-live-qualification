#!/usr/bin/env python3
"""Stage-1 evidence collector. No commit, tag, push, cloud creation or deployment."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import zipfile

VERSION = "0.1"
RECORD_NAME = "BALANCE_Canary_Pilot_v0.1.1_Baseline_Record_v0.1.yaml"
TAG = "pilot-v0.1.1-local-qualified"
DEFAULT_RECORD = "qualification/baseline/" + RECORD_NAME
PACKAGES = {
    "candidate": {
        "filename": "BALANCE_Canary_Pilot_0.1.1_2026-09-12.zip",
        "sha256": "00ea748bdacab7b743bf54db2fbf6ee976ac6cdbc249cc3a8c176b80346cf74e",
        "zip_root": "balance-canary-pilot", "repo_path": "candidate", "entries": 32,
    },
    "disposable_target_package": {
        "filename": "BALANCE_Disposable_Target_asia-south1_2026-09-12.zip",
        "sha256": "b2c6d3bb33eb6b6365b18ea8b458068845e4eab10cba9b38623e69419cd03a4c",
        "zip_root": "balance-disposable-target", "repo_path": "target-package", "entries": 13,
    },
}
BASE_ALLOWED = [
    "BASELINE.md", ".gitignore", ".gitattributes", "tools/verify_baseline.py",
    *["artifacts/" + p["filename"] for p in PACKAGES.values()],
]
LOCAL_KEYS = [
    "archive_integrity", "manifests_verified", "source_binding_verified",
    "candidate_31_of_31", "target_fixture_6_of_6",
    "provisioning_plan_prepared_not_deployed", "provisioning_plan_initial_100_0",
    "operator_environment_ready", "collector_issued_no_cloud_create_command",
    "scoped_operator_no_cloud_declaration",
]
SCOPE_LIMITS = [
    "DOES_NOT_ESTABLISH_LIVE_CLOUD_QUALIFICATION",
    "DOES_NOT_ESTABLISH_RUNTIME_IAM_OR_IDENTITY_ISOLATION",
    "NO_CLOUD_ABSENCE_REQUIRES_OPERATOR_DECLARATION",
    "REMOTE_REF_MATCH_IS_POINT_IN_TIME",
    "TRUSTS_COLLECTOR_HOST_TOOLCHAIN_AND_CLOCK",
]

class BaselineError(Exception):
    pass

def require(value, reason):
    if value is not True:
        raise BaselineError(reason)

def now():
    return datetime.now(timezone.utc).isoformat()

def digest(data):
    return hashlib.sha256(data).hexdigest()

def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise BaselineError("Duplicate JSON key: " + key)
            result[key] = value
        return result
    def invalid_constant(value):
        raise BaselineError("Non-JSON numeric constant: " + value)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant)

def relative(value):
    require(type(value) is str and bool(value), "Missing relative path")
    p = PurePosixPath(value)
    require(not p.is_absolute() and p.as_posix() == value and
            all(x not in ("", ".", "..") for x in p.parts), "Noncanonical relative path")
    require(not any(ord(c) < 32 for c in value), "Control character in path")
    return p

def under(root, value):
    p = relative(value)
    path = root.joinpath(*p.parts)
    cursor = root
    require(not root.is_symlink(), "Symlinked repository root")
    for part in p.parts:
        cursor = cursor / part
        require(not cursor.is_symlink(), "Symlink in evidence/source path")
    require(path.resolve().is_relative_to(root.resolve()), "Path escapes repository")
    return path

def read_regular(path):
    require(path.is_file() and not path.is_symlink(), "Required regular file missing")
    return path.read_bytes()

def write_new(path, value, binary=False):
    payload = value if binary else json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb" if binary else "x", **({} if binary else {"encoding": "utf-8"})) as f:
        f.write(payload)

def git(root, *args):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    p = subprocess.run(["git", "-C", str(root), *args], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=60, env=env)
    require(p.returncode == 0, "Git command failed: " + args[0])
    return p.stdout

def archive_data(path, config):
    raw = read_regular(path)
    require(digest(raw) == config["sha256"], "Archive SHA-256 differs from pinned value")
    files = {}
    with zipfile.ZipFile(path) as z:
        require(sum(i.file_size for i in z.infolist()) < 8_000_000, "Unexpected archive size")
        for info in z.infolist():
            name = info.filename
            prefix = config["zip_root"] + "/"
            require(name.startswith(prefix), "Archive member outside pinned root")
            rel = name[len(prefix):]
            relative(rel)
            require(rel not in files, "Duplicate archive member")
            mode = (info.external_attr >> 16) & 0xffff
            require(not info.is_dir() and not stat.S_ISLNK(mode), "Non-file ZIP member")
            require(stat.S_IFMT(mode) in (0, stat.S_IFREG), "Unsupported ZIP file type")
            require(not mode & 0o111, "Unexpected executable file in pinned package")
            files[rel] = z.read(info)
    require("MANIFEST.json" in files, "Embedded manifest missing")
    manifest = strict_json(files["MANIFEST.json"])
    require(type(manifest) is dict and len(manifest) == config["entries"], "Manifest entry count differs")
    require(set(files) == set(manifest) | {"MANIFEST.json"}, "Archive contains undeclared/missing files")
    for rel, spec in manifest.items():
        relative(rel)
        require(type(spec) is dict and type(spec.get("size_bytes")) is int, "Invalid manifest entry")
        require(len(files[rel]) == spec["size_bytes"] and
                digest(files[rel]) == spec.get("sha256"), "Embedded manifest verification failed")
    return files, {
        "archive": {"filename": config["filename"], "expected_sha256": config["sha256"],
                    "observed_sha256": digest(raw), "exact_match": True},
        "manifest": {"expected_entry_count": config["entries"], "verified_entry_count": len(manifest),
                     "missing_count": 0, "changed_count": 0, "unexpected_count": 0,
                     "manifest_sha256": digest(files["MANIFEST.json"]), "result": "PASS"},
    }

def working_files(path):
    require(path.is_dir() and not path.is_symlink(), "Package directory missing")
    files = {}
    for base, dirs, names in os.walk(path, followlinks=False):
        for name in dirs:
            require(not (Path(base) / name).is_symlink(), "Symlinked package directory")
        for name in names:
            p = Path(base) / name
            require(p.is_file() and not p.is_symlink(), "Nonregular package file")
            require(not p.stat().st_mode & 0o111, "Executable working package file")
            files[p.relative_to(path).as_posix()] = p.read_bytes()
    return files

def tracked_entries(root, prefix, commit=None):
    if commit:
        args = ["ls-tree", "-r", "-z", commit]
    else:
        args = ["ls-files", "--stage", "-z"]
    if prefix:
        args += ["--", prefix]
    raw = git(root, *args)
    result = {}
    for row in raw.split(b"\0"):
        if not row:
            continue
        head, path = row.split(b"\t", 1)
        parts = head.decode("ascii").split()
        if commit:
            mode, kind, oid = parts
            require(kind == "blob", "Non-blob tracked entry")
        else:
            mode, oid, stage = parts
            require(stage == "0", "Unmerged index entry")
        require(mode == "100644", "Unsupported executable/symlink/submodule Git mode")
        name = path.decode("utf-8")
        relative(name)
        require(name not in result, "Duplicate tracked path")
        result[name] = oid
    return result

def allowed_paths(record_path, extra):
    paths = BASE_ALLOWED + [record_path] + list(extra)
    for p in paths:
        relative(p)
        require(not p.startswith(("candidate/", "target-package/", ".git/")),
                "Repo-only declaration cannot change frozen package trees")
    return sorted(set(paths))

def verify_sources(root, record_path, extra=(), commit=None):
    all_tracked = tracked_entries(root, "", commit)
    allowed = set(allowed_paths(record_path, extra))
    undeclared = sorted(p for p in all_tracked
                        if not p.startswith(("candidate/", "target-package/")) and p not in allowed)
    require(not undeclared, "Undeclared tracked repo-only files: " + ", ".join(undeclared))
    results = {}
    for key, config in PACKAGES.items():
        ap = under(root, "artifacts/" + config["filename"])
        expected, info = archive_data(ap, config)
        archive_rel = ap.relative_to(root).as_posix()
        require(archive_rel in all_tracked, "Pinned archive is not tracked")
        require(digest(git(root, "cat-file", "blob", all_tracked[archive_rel])) == config["sha256"],
                "Tracked archive bytes differ from pinned archive")
        prefix = config["repo_path"] + "/"
        working = working_files(under(root, config["repo_path"]))
        require(set(working) == set(expected), "Missing or extra working package files")
        require(all(working[p] == expected[p] for p in expected), "Working package bytes changed")
        tracked = {p[len(prefix):]: oid for p, oid in all_tracked.items() if p.startswith(prefix)}
        require(set(tracked) == set(expected), "Missing or extra tracked package files")
        require(all(git(root, "cat-file", "blob", tracked[p]) == expected[p] for p in expected),
                "Tracked package bytes differ from fresh archive decode")
        info["source_binding"] = {
            "repo_path": config["repo_path"],
            "clean_extraction_reference": "Fresh ZIP decode from the pinned archive; no cached extraction",
            "git_scope": "COMMIT_TREE" if commit else "INDEX",
            "compared_files": len(expected), "changed_files": 0, "missing_files": 0,
            "unexpected_tracked_files": 0, "unexpected_working_files": 0, "exact_match": True,
        }
        results[key] = info
    return results, sorted(allowed)

def run(root, argv, cwd, evidence_dir, name):
    started = now()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", GIT_TERMINAL_PROMPT="0",
               GH_PROMPT_DISABLED="1", CLOUDSDK_CORE_DISABLE_PROMPTS="1")
    try:
        p = subprocess.run(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=60, env=env)
        output, code = p.stdout, p.returncode
    except FileNotFoundError:
        output, code = b"NOT_INSTALLED\n", 127
    except subprocess.TimeoutExpired as exc:
        output, code = (exc.stdout or b"") + b"\nCOLLECTOR_TIMEOUT\n", 124
    dest = evidence_dir / name
    write_new(dest, output, binary=True)
    return {"argv": argv, "working_directory": str(cwd), "started_at": started,
            "completed_at": now(), "exit_code": code,
            "stdout_stderr": {"path": dest.relative_to(root).as_posix(), "sha256": digest(output)}}

def test_summary(output, code, expected):
    text = output.decode("utf-8", errors="replace")
    rows = re.findall(r"^Ran (\d+) tests? in .+$", text, re.M)
    terminal = text.strip().splitlines()[-1] if text.strip() else ""
    failed = re.search(r"^FAILED \((.+)\)$", text, re.M)
    counts = {}
    if failed:
        counts = {k: int(v) for k, v in re.findall(r"([a-z]+)=(\d+)", failed.group(1))}
    good = code == 0 and rows == [str(expected)] and terminal == "OK"
    return {"tests_expected": expected, "tests_run": int(rows[0]) if len(rows) == 1 else None,
            "failures": counts.get("failures", 0) if rows else None,
            "errors": counts.get("errors", 0) if rows else None,
            "skipped": counts.get("skipped", 0) if rows else None,
            "result": "PASS" if good else "FAIL"}

def os_profile(root):
    values = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            values[k] = v.strip('"')
    kernel = os.uname().release
    wsl2 = "microsoft-standard" in kernel.lower() or "wsl2" in kernel.lower()
    workspace_expected = Path.home() / "Balance" / "balance-canary-pilot"
    passed = (wsl2 and values.get("ID") == "ubuntu" and values.get("VERSION_ID") == "24.04"
              and root == workspace_expected.resolve() and not str(root).startswith("/mnt/"))
    return {"observed_at": now(), "kernel_release": kernel, "distribution_id": values.get("ID"),
            "distribution_version": values.get("VERSION_ID"), "wsl2_kernel_observed": wsl2,
            "host_operating_system": "Windows (inferred from WSL2)" if wsl2 else "NOT_ESTABLISHED",
            "workspace_expected": str(workspace_expected), "expected_profile_matches": passed}

def plan_observed(output, code):
    try:
        p = strict_json(output)
    except (ValueError, BaselineError):
        return None, False
    expected = {"status": "PREPARED_NOT_DEPLOYED", "project": None, "region": "asia-south1",
                "service": "balance-canary-target", "base_revision": None, "candidate_revision": None,
                "initial_traffic": {"base": 100, "candidate": 0},
                "balance_candidate_sha256": PACKAGES["candidate"]["sha256"]}
    good = code == 0 and type(p) is dict and all(p.get(k) == v for k, v in expected.items())
    if good:
        good = all(type(v) is int for v in p["initial_traffic"].values())
    return p, good

def evidence_file(root, item):
    raw = read_regular(under(root, item["path"]))
    require(digest(raw) == item["sha256"], "Retained evidence digest mismatch")
    return raw

def evidence_check(root, record):
    idx = record["retained_evidence"]
    index = strict_json(evidence_file(root, {"path": idx["index_path"], "sha256": idx["index_sha256"]}))
    require(index["schema"] == {"name": "BALANCE_Local_Evidence_Index", "version": VERSION},
            "Evidence index schema mismatch")
    indexed = {item["path"]: item["sha256"] for item in index["files"]}
    require(len(indexed) == len(index["files"]), "Duplicate evidence index entry")
    for item in index["files"]:
        evidence_file(root, item)
    for key, expected in [("candidate_tests", 31), ("target_fixture_tests", 6)]:
        item = record[key]
        package_key = "candidate" if key == "candidate_tests" else "disposable_target_package"
        require(item["working_directory"] == str(under(root, PACKAGES[package_key]["repo_path"])),
                "Test working-directory binding differs")
        ref = item["stdout_stderr"]
        require(indexed.get(ref["path"]) == ref["sha256"], "Test log not bound to evidence index")
        result = test_summary(evidence_file(root, ref), item["exit_code"], expected)
        require(result["result"] == "PASS" and all(item[k] == v for k, v in result.items()),
                "Test-result fields do not match retained output")
        require(item["argv"] == [record["environment"]["python_executable"], "-m", "unittest", "discover", "-v"],
                "Unexpected test command")
    plan = record["provisioning_plan"]
    require(plan["working_directory"] == str(under(root, PACKAGES["disposable_target_package"]["repo_path"])),
            "Plan working-directory binding differs")
    ref = plan["stdout_stderr"]
    require(indexed.get(ref["path"]) == ref["sha256"], "Plan log not bound to evidence index")
    observed, good = plan_observed(evidence_file(root, ref), plan["exit_code"])
    require(good and observed == plan["observed"] and plan["consequential_operation_performed"] is False,
            "Plan claim does not match retained native output")
    require(plan["argv"] == [record["environment"]["python_executable"], "provision.py", "plan"],
            "Unexpected plan command")
    for item in record["environment"]["tools"].values():
        ref = item["stdout_stderr"]
        require(indexed.get(ref["path"]) == ref["sha256"], "Version evidence not bound to index")
        require(item["exit_code"] == 0, "Required operator tool was unavailable")
    return index

def check_tool(root, commit=None):
    rel = "tools/verify_baseline.py"
    require(Path(__file__).resolve() == under(root, rel).resolve(),
            "Run the verifier from the declared tracked tools directory")
    entries = tracked_entries(root, rel, commit)
    require(rel in entries, "Verifier is not tracked")
    data = read_regular(under(root, rel))
    require(data == git(root, "cat-file", "blob", entries[rel]), "Verifier differs from tracked bytes")
    return {"id": "manifest-hash-compare-v1", "script_path": rel, "script_sha256": digest(data),
            "script_git_blob_oid": entries[rel],
            "script_commit_reference": "POST_COMMIT_FREEZE_ONLY"}

def collect(args):
    root = args.repo.resolve()
    require(args.confirm_no_cloud_created, "Explicit scoped no-cloud-created declaration required")
    require(bool(args.operator.strip()) and "<" not in args.operator, "Actual operator identifier required")
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.github_repository) is not None,
            "Declare the intended GitHub owner/repository")
    require(sys.version_info >= (3, 11), "Python 3.11+ required")
    record_path = args.record
    require(record_path.startswith("qualification/baseline/"), "Record must be outside frozen package trees")
    require(not under(root, record_path).exists(), "Existing baseline record cannot be overwritten")
    tool = check_tool(root)
    packages, allowed = verify_sources(root, record_path, args.allow_repo_file)
    eid = "evidence/local/" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + os.urandom(4).hex()
    ed = under(root, eid)
    ed.mkdir(parents=True, exist_ok=False)
    tools = {}
    for key, argv in [
        ("python", [sys.executable, "--version"]), ("git", ["git", "--version"]),
        ("github_cli", ["gh", "--version"]), ("gcloud", ["gcloud", "--version"]),
        ("docker", ["docker", "version"]), ("docker_compose", ["docker", "compose", "version"]),
    ]:
        tools[key] = run(root, argv, root, ed, key + "-version.txt")
    results = {}
    for key, prefix, count in [("candidate_tests", "candidate", 31), ("target_fixture_tests", "target-package", 6)]:
        item = run(root, [sys.executable, "-m", "unittest", "discover", "-v"],
                   under(root, prefix), ed, key + ".txt")
        item.update(test_summary(evidence_file(root, item["stdout_stderr"]), item["exit_code"], count))
        results[key] = item
    plan = run(root, [sys.executable, "provision.py", "plan"], under(root, "target-package"), ed, "provision-plan.txt")
    observed, good_plan = plan_observed(evidence_file(root, plan["stdout_stderr"]), plan["exit_code"])
    plan.update({"observed": observed, "exact_required_fields_match": good_plan,
                 "consequential_operation_performed": False, "result": "PASS" if good_plan else "FAIL"})
    after, allowed_after = verify_sources(root, record_path, args.allow_repo_file)
    require(packages == after and allowed == allowed_after, "Source changed during local reproduction")
    for info in packages.values():
        info["source_binding"]["comparison_method"] = tool
    comparison_ref = {"path": eid + "/source-comparison.json"}
    write_new(under(root, comparison_ref["path"]), packages)
    comparison_ref["sha256"] = digest(read_regular(under(root, comparison_ref["path"])))
    refs = [i["stdout_stderr"] for i in tools.values()] + [
        i["stdout_stderr"] for i in results.values()] + [plan["stdout_stderr"], comparison_ref]
    index = {"schema": {"name": "BALANCE_Local_Evidence_Index", "version": VERSION},
             "created_at": now(), "files": refs,
             "excludes": ["the index itself", "the baseline record", "post-commit freeze records"]}
    index_path = ed / "EVIDENCE_INDEX.json"
    write_new(index_path, index)
    profile = os_profile(root)
    predicates = {
        "archive_integrity": True, "manifests_verified": True, "source_binding_verified": True,
        "candidate_31_of_31": results["candidate_tests"]["result"] == "PASS",
        "target_fixture_6_of_6": results["target_fixture_tests"]["result"] == "PASS",
        "provisioning_plan_prepared_not_deployed": good_plan,
        "provisioning_plan_initial_100_0": good_plan,
        "operator_environment_ready": profile["expected_profile_matches"] and all(
            i["exit_code"] == 0 for i in tools.values()),
        "collector_issued_no_cloud_create_command": True,
        "scoped_operator_no_cloud_declaration": True,
    }
    record = {
        "schema": {"name": "BALANCE_Canary_Pilot_Baseline_Record", "version": VERSION},
        "status": {"milestone": "MILESTONE_1", "result": "PENDING",
                   "local_reproduction_result": "PASS" if all(predicates.values()) else "FAIL",
                   "result_pending_reason": "Final commit/tag/private-remote checks belong to BASELINE_FREEZE.json",
                   "live_cloud_qualification": "NOT_STARTED"},
        "record_identity": {"created_at": now(), "operator": args.operator, "host": profile,
                            "workspace": str(root), "phase": "PRE_COMMIT"},
        "repository_expected": {"owner_repository": args.github_repository, "remote_name": "origin",
                                "visibility": "private", "branch": "main", "annotated_tag": TAG},
        **packages, "environment": {"python_executable": sys.executable,
                                   "python_version": sys.version, "tools": tools},
        **results, "provisioning_plan": plan,
        "baseline_diff_check": {"procedure_version": "1", "result": "PASS",
                               "candidate_archive_sha_match": True, "candidate_manifest_match": True,
                               "candidate_repo_tree_matches_clean_archive": True,
                               "target_archive_sha_match": True, "target_manifest_match": True,
                               "target_repo_tree_matches_clean_archive": True,
                               "permitted_repo_only_files": allowed,
                               "undeclared_difference_count": 0, "undeclared_differences": [],
                               "comparison_output": comparison_ref},
        "retained_evidence": {"index_path": index_path.relative_to(root).as_posix(),
                              "index_sha256": digest(read_regular(index_path))},
        "no_cloud_declaration": {"operator": args.operator, "declared_at": now(),
                                "scope": "No GCP resource has been created for this Canary pilot",
                                "declared_no_resources_created": True,
                                "basis_kind": "OPERATOR_DECLARATION_NOT_INDEPENDENT_CLOUD_INVENTORY"},
        "local_exit_predicate": predicates, "scope_limits": SCOPE_LIMITS,
    }
    write_new(under(root, record_path), record)
    print(json.dumps({"record": record_path, "local_reproduction_result":
                     record["status"]["local_reproduction_result"], "milestone_1_result": "PENDING",
                     "evidence_directory": eid}, indent=2))
    return 0 if all(predicates.values()) else 1

def parse_remote(output):
    result = {}
    for line in output.decode("ascii").splitlines():
        oid, ref = line.split("\t")
        require(ref not in result, "Duplicate remote ref")
        require(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid) is not None, "Invalid remote object ID")
        result[ref] = oid
    return result

def remote_repository(url):
    match = re.fullmatch(
        r"(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)"
        r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?", url)
    require(match is not None, "Origin must be a credential-free GitHub URL")
    return match.group(1)

def verify_ref_bindings(commit, tag_object, peeled, remote):
    ref = "refs/tags/" + TAG
    require(peeled == commit, "Local peeled tag differs from source commit")
    require(remote.get("refs/heads/main") == commit and remote.get(ref) == tag_object and
            remote.get(ref + "^{}") == commit, "Remote branch/tag object/peeled commit differ")
    return True

def freeze(args):
    root = args.repo.resolve()
    require(args.confirm_no_cloud_created, "Fresh scoped no-cloud-created declaration required")
    require(os_profile(root)["expected_profile_matches"], "Operator WSL2/Ubuntu/workspace profile not established")
    record_path = args.record
    raw = read_regular(under(root, record_path))
    record = strict_json(raw)
    require(record["schema"] == {"name": "BALANCE_Canary_Pilot_Baseline_Record", "version": VERSION},
            "Wrong baseline schema")
    require(record["status"]["result"] == "PENDING" and
            record["status"]["local_reproduction_result"] == "PASS" and
            record["status"]["live_cloud_qualification"] == "NOT_STARTED",
            "Baseline record is not a successful pre-commit reproduction")
    require(set(record["local_exit_predicate"]) == set(LOCAL_KEYS) and
            all(v is True for v in record["local_exit_predicate"].values()), "Local predicates not established")
    require(record["scope_limits"] == SCOPE_LIMITS, "Baseline scope limits changed")
    require(record["record_identity"]["workspace"] == str(root), "Baseline workspace differs")
    require(record["no_cloud_declaration"]["declared_no_resources_created"] is True and
            record["no_cloud_declaration"]["operator"] == record["record_identity"]["operator"],
            "Missing scoped operator declaration")
    require(not git(root, "status", "--porcelain=v1", "--untracked-files=all").strip(), "Repository is not clean")
    require(git(root, "symbolic-ref", "--short", "HEAD").decode().strip() == "main", "Local branch must be main")
    commit = git(root, "rev-parse", "HEAD").decode().strip()
    tree = git(root, "rev-parse", "HEAD^{tree}").decode().strip()
    require(git(root, "show", commit + ":" + record_path) == raw, "Record differs from committed bytes")
    tool = check_tool(root, commit)
    extra = record["baseline_diff_check"]["permitted_repo_only_files"]
    packages, allowed = verify_sources(root, record_path, extra, commit)
    for key, info in packages.items():
        require(record[key]["archive"] == info["archive"] and record[key]["manifest"] == info["manifest"],
                "Recorded package integrity differs from recomputed integrity")
        old = dict(record[key]["source_binding"])
        old.pop("git_scope", None)
        recorded_tool = old.pop("comparison_method", None)
        actual = dict(info["source_binding"])
        actual.pop("git_scope", None)
        require(old == actual and recorded_tool == tool, "Recorded source/tool binding differs")
    require(record["baseline_diff_check"]["result"] == "PASS" and
            record["baseline_diff_check"]["undeclared_difference_count"] == 0 and
            record["baseline_diff_check"]["undeclared_differences"] == [], "Unresolved baseline differences")
    evidence_check(root, record)
    ref = "refs/tags/" + TAG
    require(git(root, "cat-file", "-t", ref).decode().strip() == "tag", "Annotated tag required")
    tag_object = git(root, "rev-parse", ref).decode().strip()
    peeled = git(root, "rev-parse", ref + "^{}").decode().strip()
    require(peeled == commit, "Local peeled tag does not match source commit")
    origin = git(root, "remote", "get-url", "origin").decode().strip()
    owner_repo = remote_repository(origin)
    require(record["repository_expected"] == {
        "owner_repository": record["repository_expected"]["owner_repository"], "remote_name": "origin",
        "visibility": "private", "branch": "main", "annotated_tag": TAG}, "Repository expectation changed")
    require(owner_repo.lower() == record["repository_expected"]["owner_repository"].lower(),
            "Origin differs from the predeclared GitHub repository")
    ed = under(root, "evidence/freeze/" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + os.urandom(4).hex())
    ed.mkdir(parents=True, exist_ok=False)
    privacy = run(root, ["gh", "api", "--hostname", "github.com", "repos/" + owner_repo],
                  root, ed, "github-repository.json")
    require(privacy["exit_code"] == 0, "Cannot establish GitHub repository privacy")
    gh = strict_json(evidence_file(root, privacy["stdout_stderr"]))
    require(gh.get("private") is True and gh.get("full_name", "").lower() == owner_repo.lower()
            and gh.get("default_branch") == "main", "Private expected GitHub repository/default branch not established")
    refs = run(root, ["git", "ls-remote", "origin", "refs/heads/main", ref, ref + "^{}"],
               root, ed, "remote-refs.txt")
    require(refs["exit_code"] == 0, "Cannot resolve remote branch/tag")
    remote = parse_remote(evidence_file(root, refs["stdout_stderr"]))
    verify_ref_bindings(commit, tag_object, peeled, remote)
    require(git(root, "rev-parse", "HEAD").decode().strip() == commit and
            not git(root, "status", "--porcelain=v1", "--untracked-files=all").strip(),
            "Repository changed during freeze checks")
    predicates = dict(record["local_exit_predicate"], repository_clean=True, private_remote_confirmed=True,
                      remote_branch_matches_commit=True, remote_tag_object_matches=True,
                      remote_peeled_tag_matches_commit=True, diff_against_pinned_artifacts_clean=True,
                      fresh_scoped_operator_no_cloud_declaration=True)
    require(all(v is True for v in predicates.values()), "Milestone predicate incomplete")
    receipt = {
        "schema": {"name": "BALANCE_Canary_Pilot_Baseline_Freeze", "version": VERSION},
        "status": {"milestone": "MILESTONE_1", "result": "PASS", "live_cloud_qualification": "NOT_STARTED"},
        "created_at": now(), "operator": record["record_identity"]["operator"],
        "baseline_record": {"path": record_path, "sha256": digest(raw),
                            "git_blob_oid": git(root, "rev-parse", commit + ":" + record_path).decode().strip()},
        "repository": {"source_baseline_commit_sha": commit, "tree_sha": tree, "branch": "main",
                       "working_tree_clean": True, "tag": TAG, "annotated": True,
                       "local_tag_object_sha": tag_object, "local_peeled_commit_sha": peeled,
                       "remote_repository": owner_repo, "remote_url": origin, "visibility_observed": "private",
                       "default_branch_observed": "main", "remote_branch_commit_sha": remote["refs/heads/main"],
                       "remote_tag_object_sha": remote[ref], "remote_peeled_commit_sha": remote[ref + "^{}"],
                       "remote_resolution_verified_at": refs["completed_at"]},
        "verifier": dict(tool, script_commit_sha=commit,
                         script_commit_reference="SOURCE_BASELINE_COMMIT"),
        "recomputed_packages": packages, "retained_evidence": record["retained_evidence"],
        "freeze_evidence": [privacy, refs], "exit_predicate": predicates,
        "milestone_1_pass": {"expression_id": "ALL_REQUIRED_PREDICATES_TRUE_V1", "evaluated": True},
        "no_cloud_declaration": {"declared_at": now(), "operator": record["record_identity"]["operator"],
                                "scope": record["no_cloud_declaration"]["scope"], "declared_no_resources_created": True,
                                "basis_kind": "OPERATOR_DECLARATION_NOT_INDEPENDENT_CLOUD_INVENTORY"},
        "scope_limits": SCOPE_LIMITS,
        "trust_assumptions": ["Collector/verifier code, host and toolchain integrity; no concurrent source edits",
                              "Operator declaration accurately covers this pilot's external resource activity",
                              "Git object integrity, authenticated GitHub responses and configured remote resolution",
                              "Host clock sufficiently accurate for the recorded ordering"],
    }
    output = under(root, args.output)
    require(args.output.startswith("evidence/"), "Freeze receipt must stay outside the source baseline")
    write_new(output, receipt)
    print(json.dumps({"freeze_record": args.output, "milestone_1_result": "PASS",
                     "source_baseline_commit_sha": commit, "live_cloud_qualification": "NOT_STARTED"}, indent=2))
    return 0

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("check-artifacts", help="Offline archive/embedded-manifest verification")
    inspect.add_argument("--archives", type=Path, required=True)
    extract = sub.add_parser("extract", help="Verify then extract into new package directories; no overwrite")
    extract.add_argument("--repo", type=Path, required=True)
    for name in ("collect", "freeze"):
        p = sub.add_parser(name)
        p.add_argument("--repo", type=Path, required=True)
        p.add_argument("--record", default=DEFAULT_RECORD)
        p.add_argument("--confirm-no-cloud-created", action="store_true",
                       help="Scoped operator declaration, not independently established external absence")
        if name == "collect":
            p.add_argument("--operator", required=True)
            p.add_argument("--github-repository", required=True, help="Intended owner/repository, before commit")
            p.add_argument("--allow-repo-file", action="append", default=[])
        else:
            p.add_argument("--output", default="evidence/local/BASELINE_FREEZE.json")
    args = parser.parse_args()
    if args.command == "check-artifacts":
        result = {key: archive_data(args.archives / cfg["filename"], cfg)[1] for key, cfg in PACKAGES.items()}
        print(json.dumps({"archive_checks": result, "milestone_1_result": "PENDING"}, indent=2))
        return 0
    if args.command == "extract":
        root = args.repo.resolve()
        for cfg in PACKAGES.values():
            require(not under(root, cfg["repo_path"]).exists(), "Extraction destination already exists")
        decoded = [(cfg, archive_data(under(root, "artifacts/" + cfg["filename"]), cfg)[0])
                   for cfg in PACKAGES.values()]
        for cfg, files in decoded:
            for rel, data in files.items():
                write_new(under(root, cfg["repo_path"] + "/" + rel), data, binary=True)
        print("Pinned packages extracted; no cloud resources created by this command.")
        return 0
    return collect(args) if args.command == "collect" else freeze(args)

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BaselineError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"baseline_check": "REJECTED", "milestone_1_result": "NOT_COMPLETE",
                          "reason": str(exc)}, indent=2), file=sys.stderr)
        raise SystemExit(1)
