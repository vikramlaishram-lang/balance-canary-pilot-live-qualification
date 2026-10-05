# Balance Runtime — canary pilot

**Independent implementation candidate v0.1.1, 12 September 2026. Failed-check/read-outage regression verified locally; container deployment and live Google Cloud qualification not run.**

The first customer task is: **Take this approved revision to a canary of at most 10%, then establish that the agreed candidate checks pass over the configured observation window. Keep the objective unresolved when the evidence does not support completion.**

This package implements that one workflow within the canonical Balance architecture. It neither imports nor modifies frozen Ground-Zero, Release Sentinel, Execute, or the conformance harness. Their test counts and qualifications do not transfer to this build.

## What exists

- An operator CLI prepares and signs an exact intent. The authority signing key stays off the runtime host.
- A gateway admits signed objectives into durable storage. A separate worker resumes the objectives after restart.
- The writer validates the signature, scope, policy, lifetime, target UID and target version; reserves the intent durably; then makes one Cloud Run v2 traffic update attempt with the approved etag.
- The observer uses a separate Google identity, reads the provider operation and target state, samples the configured candidate probe, and signs a specific observation. Exact response bytes are saved by SHA-256.
- Completion requires signed samples with the same intent, policy, operation and generation, all required checks present and true, unique challenges, an adequate time window, and fresh final evidence.
- A failed required candidate check retains its meaning if the final target read fails. Signed false required-check facts cause `NEEDS_REVIEW` even with a neutral summary verdict; restart and later passing observations do not automatically complete that objective.
- A lost response, interrupted writer, or conflicting target state cannot authorize an automatic repeat mutation. A new objective ID cannot bypass an unresolved target reservation.
- Completion is persisted before the writer reservation is released. Cleanup can resume after the approval has expired without authorizing another external action.

The worker is deterministic. No model API is called. A future model can propose intents and inspect status through the same constrained interface; it cannot mint the operator's signature or supply weaker completion criteria.

## Local verification

Python 3.11+ and `cryptography` are sufficient for the core tests:

```bash
python -m pip install -e .
python -m unittest discover -v
```

See `VALIDATION.md` for the recorded results and limits. The tests exercise the real runtime logic, SQLite stores, signatures, HTTP role interfaces, concurrency, and abrupt child-process termination. Target effects are simulated. Google authentication and the live REST path were not exercised.

`PATCH_NOTES.md` records the narrow 0.1.0 correction. The suite now contains the original 29 tests plus two targeted regressions, all passing. `validation/failure_path_probe.py` and its before/after records reproduce the original failure and corrected behavior. This patch does not requalify existing 0.1.0 objective records; see the upgrade note in `DEPLOYMENT.md`.

## One deployment shape

A dedicated Linux Docker host runs gateway, worker, writer and observer containers. Three persistent volumes retain objectives, writer intents, and observation bytes. Only the loopback gateway port is exposed. The coordinator network is internal; only writer and observer receive external networks and their respective Google credentials.

The supplied standalone-host credential profile uses distinct service-account key files. They require protected handling and rotation. A managed-identity deployment is not implemented by this compose file. Containers and key placement alone do not prove IAM isolation; verify the actual permission matrix before admitting a live objective.

Follow `DEPLOYMENT.md`. No target, identity, network rule, cloud resource, or paid service has been provisioned by this build.

## Claim limits

| Observed state | Meaning |
| --- | --- |
| `READY` | A signed objective is stored; execution has not been established. |
| `OBSERVING` | A provider operation identity is recorded; read-only checks continue. |
| `OUTCOME_UNKNOWN` | Dispatch or observation knowledge is incomplete. No new mutation is inferred to be safe. |
| `NEEDS_REVIEW` | A precondition, check, competing change, or observation budget requires operator attention; the objective is unresolved. |
| `COMPLETED` | The declared operation/state/probe criteria were satisfied at the recorded times. |

`COMPLETED` does not establish general release health, every business outcome, or the future state of the service. Health evidence is an application response under a declared probe contract. If the probe is wrong or deceptive, signing its response does not make it true. Provider operation correlation is retained, but forensic attribution still needs the live IAM and audit evidence appropriate to the deployment.

The append-only application history has hash links. It detects edits relative to retained hashes; it is not externally anchored and does not resist an administrator rewriting the entire history. Host administrators, approval signers, trusted verifier code, and policy maintainers remain within the trust boundary.

## Intentional pilot limits

One configured service; two existing explicit revisions; initial 100% base traffic; no traffic tags or floating revisions; canary ceiling 10%; one unresolved mutation per target; one coordinator worker per persistent volume. The service's current state must be stable and its observed generation current.

There is no automatic rollback, automatic promotion, in-flight remote cancellation, online per-grant revocation, autonomous planning, HA failover, or API for overriding an unknown effect. Approval expiry is checked before invocation; it is not a promise about the remote commit time. The approval's target version is the native concurrency precondition.

An operation identifier lost after acceptance can leave an unresolved reservation requiring investigation. The pilot intentionally has no convenient force-clear endpoint that would erase that uncertainty. This limits operational convenience and must be measured during the pilot.

Do not restore an old writer database and resume dispatch while old approvals may still be presented. That would roll back the replay barrier. Recovery requires preserving the complete intent history or rotating authorization and independently reconciling target effects before admission resumes.
