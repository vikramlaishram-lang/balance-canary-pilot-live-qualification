# Deployment and first real qualification

This is a prepared deployment path, not a record of a completed deployment. Docker, gcloud, live credentials and a selected target were unavailable in the build environment. The container image and Google authentication path still require execution on the pilot host.

## 1. Select and inspect the pilot target

Use one noncritical Cloud Run service with two existing revisions and a stable 100% allocation to one explicit base revision. The pilot does not build or deploy application revisions. It rejects traffic tags, floating latest-revision allocation, and a reconciling service. Use a test service for the first real qualification.

The approved service must implement the fixed HTTPS probe in `examples/probe_contract.json`. It must echo the unpredictable request query `nonce`, identify its actual deployed revision, and evaluate the configured readiness and smoke checks. Do not implement these booleans as constants for the real application. Define exactly what the smoke check covers; broader business health is outside this record's claim.

The observer samples the normal service URL. Base-revision responses do not count as candidate evidence. At 10% traffic, enough candidate samples are probabilistic; exhausted observation budgets lead to review, not invented success. Session affinity, caches, cookies and routing behavior must be checked on the selected service. Set the probe's `health_audience` to the Cloud Run service's configured authentication audience; use an empty string only for an intentionally public, read-only probe.

## 2. Establish the identity boundary

| Component | Credentials and access |
| --- | --- |
| Operator signing workstation | Authority private key; permission to review the release and explicitly authorize the intent. |
| Gateway and coordinator worker | Public verification keys and internal API tokens. No Google credentials, target-write privilege, signer private key, metadata-server credentials, or impersonation path. |
| Writer | Writer signing key, its own Google identity, service get/update access on exactly the configured Cloud Run service. |
| Observer | Observer signing key, a different Google identity, service/operation reads and invocation of the configured probe. No Cloud Run administrative write permission. |

Google IAM service-update permission is broader than changing traffic fields. The writer code narrows that capability using an explicit update mask and grant validation. This is not a claim that IAM itself enforces a 10% ceiling or field-level traffic-only capability. Similarly, permission to invoke a service does not automatically mean its application endpoints are read-only; the configured probe must be.

Create or select two dedicated service accounts using your normal administration process. Derive and bind the required custom roles to the narrowest supported resource scopes. Confirm the actual Cloud Run service/operation-read checks for your project, including the operation resource's permission scope. Do not resolve a failed permission check by assigning Editor or Owner.

This standalone-host profile expects two independently usable service-account JSON key files. A shared human refresh credential capable of impersonating both roles would defeat the intended separation. Key creation is not automated here. Treat those files as long-lived credentials, restrict their host access, and apply your rotation/revocation process.

Use a dedicated host without an ambient Google service account, metadata credential path, Docker-socket mounts, or other workloads able to access these secrets. The Docker daemon and host administrators remain trusted. The internal bridge configuration must be checked on the real host; it has not been tested in this workspace.

## 3. Prepare host configuration

On the signing workstation, install the package and generate signing keys and internal API tokens:

```bash
python -m pip install '.[deploy]'
python -m balance.cli init --directory signing-material
```

Keep `signing-material/authority.key` on that workstation. Transfer only the three public keys, writer and observer private keys, and three API token files into `keys/` on the deployment host. Place the independent Google files at `credentials/writer.json` and `credentials/observer.json`.

Copy `policy.example.json` to `policy.json`. Fill the exact project/location/service resource and probe URL/audience. Review the required checks, sample count, observation window and observation budget before signing any intent. Policy is read-only in each container, and its complete digest is bound into every intent.

Set secret files to owner-only mode and ownership UID 10001, matching the container user. Keep public keys readable by that user. Ensure parent directories permit Docker to bind the selected files without exposing directory trees to containers. On the host, after reviewing these exact paths:

```bash
sudo chown 10001:10001 keys/writer.key keys/observer.key keys/gateway.token keys/writer.token keys/observer.token credentials/writer.json credentials/observer.json
sudo chmod 600 keys/writer.key keys/observer.key keys/gateway.token keys/writer.token keys/observer.token credentials/writer.json credentials/observer.json
python -m deploy.preflight
```

The preflight is local and read-only. A valid result does not certify IAM, network isolation, or target consequences. Retain a gateway token copy on the operator workstation for authenticated access. Never paste private keys or tokens into an agent conversation.

## 4. Build and start

```bash
docker compose config
docker compose build
docker compose up -d
docker compose ps
```

Only `127.0.0.1:8080` is exposed. Use an SSH tunnel from the operator workstation, or put an authenticated TLS proxy in front of the gateway through your normal reviewed deployment process. Do not publish the internal writer or observer port. The gateway's process health response is not deployment qualification.

The image installs bounded dependency ranges; a network-backed dependency resolution was unavailable during this build. Before a controlled pilot, record the built image digest and resolved package versions, assess those dependencies, and use that image consistently for qualification. Container build success and runtime startup are still required checks.

## 5. Prepare, review and authorize one objective

On the operator workstation with read-capable Google credentials, copy the reviewed `policy.json` and read a fresh service snapshot:

```bash
python -m balance.cli snapshot --policy policy.json --out service-before.json
python -m balance.cli prepare --policy policy.json --snapshot service-before.json --candidate payments-CANDIDATE_REVISION --percent 10 --objective-id pilot-001 --out intent.json
```

Replace the candidate revision with its exact immutable name. Review every field in `intent.json`, including service UID, baseline, candidate, percentages, expected generation, etag and policy digest. A stale snapshot will be refused at dispatch.

Signing and submitting are consequential operator actions: a live worker can execute the approved traffic change immediately after submission.

```bash
python -m balance.cli approve --policy policy.json --intent intent.json --key signing-material/authority.key --seconds 300 --out approval.json
python -m balance.cli submit --url http://127.0.0.1:8080 --token-file signing-material/gateway.token --approval approval.json
python -m balance.cli status --url http://127.0.0.1:8080 --token-file signing-material/gateway.token --objective-id pilot-001
```

No model input, retrieved memory, policy field in the request, or unsigned remembered approval can substitute for this signature. The CLI does not infer that release approval exists; the signing operator supplies that authority explicitly.

## 6. Qualify the real relationship

Record the deployed image, policy digest, exact target, role identities, IAM policy bindings and relevant audit evidence. On the isolated pilot service, confirm that the gateway has no target credentials/impersonation route and that the observer cannot perform an administrative traffic update. Confirm the writer's allowed scope without granting it unrelated services.

Then capture baseline, approved dispatch, returned provider operation, independently read operation result, exact target generation/traffic, nonce-bound candidate samples, completion record, and the raw bytes named by each observation. Replay the same objective and confirm no second provider mutation. An out-of-bound or modified signed intent must produce no dispatch.

Exercise target-version conflict and an interrupted writer under controlled conditions. The real Cloud Run etag behavior, operation response shape and audit correlation must match the assumptions in `balance/cloud.py` and `balance/engine.py`; a local request-shape test cannot establish these facts. Stop qualification if they do not.

Capture raw evidence through the observer's authenticated internal `/evidence/{sha256}` endpoint or from its persistent volume. Export objective state via `/jobs/{objective_id}`. Preserve SQLite databases with a consistent backup method; retain WAL state as required, rather than copying only a live main database file.

The frozen Balance conformance harness is unchanged. This independent candidate does not claim a pass against it. Any later binding must preserve the translation-only rule and report genuine FAIL or INCONCLUSIVE outcomes.

## 7. Operation and recovery

Version 0.1.1 preserves failed required checks across a final-read outage and requires review when signed check facts contain a required failure. It adds no recovery or historical-state migration API. Before resuming a worker against objectives processed by 0.1.0, inspect their retained observations and history for the failed-check/read-outage defect. Existing `COMPLETED` records are not retroactively requalified by installing the patch, and old active histories are not automatically scanned or repaired. Preserve affected records for explicit review; do not hand-edit or delete reservations to obtain progress.

The worker resumes stored work after restart. `NEEDS_REVIEW` requires human investigation and leaves the objective unresolved. A post-dispatch failure does not trigger automatic rollback. Operators can stop the worker to prevent further queued processing, but stopping does not cancel an in-flight provider operation.

There is no online revocation endpoint, no forced completion, and no force-clear for uncertain writer reservations. Use short approval lifetimes and the tested deployment's incident procedures. Do not delete a reservation or reset volumes merely to unblock the next rollout. Investigate the provider operation and actual target first; any recovery tooling that changes retained authority/effect state needs its own reviewed implementation.

Before broad production use, close the live qualification, credential operations, per-grant revocation/cancellation needs, operator recovery path, dependency/image reproducibility, monitoring, backups and workload-specific probe validity. Compare actual completion, unnecessary reviews, recovery effort, time and cost against the team's existing rollout process.

## Primary API references checked during the build

- Cloud Run's update method supports an explicit update mask and returns a long-running operation. [Services.patch](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.services/patch)
- Service etags provide modification-conflict detection; observed traffic and generation have reconciliation semantics. [Service resource](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.services)
- Operation identity can be polled through the location-scoped operation endpoint. [Operations.get](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.operations/get)
- Authenticated service invocation uses an ID token with the appropriate audience. [Cloud Run service authentication](https://docs.cloud.google.com/run/docs/authenticating/service-to-service), [google-auth ID token API](https://google-auth.readthedocs.io/en/latest/reference/google.oauth2.id_token.html)
