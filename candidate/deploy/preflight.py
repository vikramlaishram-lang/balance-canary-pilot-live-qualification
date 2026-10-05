"""Read-only configuration checks. Does not inspect or change live Google IAM."""
import json
import os
from pathlib import Path
import stat

from balance.contracts import Policy, load, require


def main():
    root = Path.cwd()
    policy = Policy(load(root / "policy.json"))
    require("replace" not in json.dumps(policy.value).lower(), "replace the example target and probe URL")
    require(not (root / "keys/authority.key").exists(), "authority private key must remain off the runtime host")
    for name in ("authority.pub", "writer.pub", "observer.pub", "writer.key", "observer.key", "gateway.token", "writer.token", "observer.token"):
        path = root / "keys" / name
        require(path.is_file() and not path.is_symlink(), "missing regular key/token file: " + name)
        if name.endswith((".key", ".token")):
            require(not path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO), "secret must be owner-only: " + name)
            require(path.stat().st_uid == 10001, "container secret must be owned by UID 10001: " + name)
    principals = []
    for role in ("writer", "observer"):
        path = root / "credentials" / (role + ".json")
        require(path.is_file() and not path.is_symlink(), "missing credential file: " + role)
        credential = load(path)
        require(credential.get("type") == "service_account", "this standalone-host deployment profile requires independent service-account credentials")
        require(bool(credential.get("private_key")) and bool(credential.get("client_email")), "incomplete credential file")
        require(path.stat().st_uid == 10001 and not path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO), "credential ownership/mode incorrect")
        principals.append(credential["client_email"])
    require(principals[0] != principals[1], "writer and observer must have different Google identities")
    print(json.dumps({"configuration": "VALID", "policy_digest": policy.digest,
                      "live_iam": "NOT_EVALUATED", "cloud_consequence": "NOT_RUN",
                      "container_network_and_filesystem_boundary": "NOT_EVALUATED"}, indent=2))


if __name__ == "__main__":
    main()
