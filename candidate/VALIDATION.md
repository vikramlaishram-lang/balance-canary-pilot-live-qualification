# Validation record — 12 September 2026, v0.1.1

Classification: **LOCAL REGRESSION VERIFIED; DEPLOYMENT NOT RUN.**

The final local suite passed **31/31**: the original 29 tests and two targeted regressions. See `validation/unittest.log` for the exact output and `validation/results.json` for environment and qualification fields. Python 3.12.14 and installed cryptography 46.0.0 were used. Tests are independent of pytest and do not invoke a model API.

Both new regressions failed against the unpatched 0.1.0 runtime and passed after correction. The unchanged original archive reproduced the full counterexample: a failed smoke check followed by a final-read timeout produced `OBSERVING`, then `COMPLETED` after recovery and three later observation cycles. The same probe against 0.1.1 produced `NEEDS_REVIEW`, retained the signed negative check and read error, and stayed in review after coordinator restart despite three independently obtained later signed `PASS` observations. Each run made exactly one simulated mutation. The original archive SHA-256 is `38188618366b8379813717d9b2029608ef99fcbe8720210c667c26e110e5797e`; all 24 original manifest entries matched.

The second regression supplies an authentic observer signature over the old contradictory shape (`OBSERVATION_UNAVAILABLE` plus `smoke: false`). It verifies that the coordinator requires review based on the check facts. This deliberately uses a temporary trusted observer test key; it is not a forged-signature attack or live identity-isolation result. The evidence and reusable probe are in `validation/`.

The actual implementation, signature verification, SQLite transactions, completion predicates and HTTP role routing were exercised. The HTTP integration test runs separate writer and observer servers and a coordinating client over real loopback HTTP, with distinct API tokens and signing keys. Those servers share a test process; that result does not establish OS or IAM isolation. A separate child-process test exits abruptly after a simulated target mutation, demonstrating that the writer's preexisting durable reservation survives.

| Concern | Local result |
| --- | --- |
| Complete intent binding | Changing any signed intent field invalidates the authorization; a validly re-signed changed intent under the same ID is refused. |
| Memory/input laundering | Unsigned or altered authorization cannot substitute for the operator signature; request-supplied completion fields are rejected. This is not an EAL-Bench evaluation. |
| Weak completion | Empty policy checks are rejected. Missing, false, stale, wrong-revision, wrong-target, duplicate, wrong-signer and weakened signed observations cannot complete the objective. |
| Failed check followed by read outage | `CHECK_FAILED` and the subsequent read error survive together. The objective enters review and cannot automatically complete after restart and later passing observations. |
| Contradictory signed verdict | A signed false required-check fact triggers review even when the summary verdict is neutral. |
| Authority lifetime | Expired authority and expiry during preflight produce no provider dispatch. Historical result replay remains possible without new authority. |
| Target identity/concurrency | Changed etag and recreated service UID prevent dispatch; a change during observation prevents completion. |
| Process failure | Abrupt child exit after the simulated effect leaves a durable reservation and replay returns uncertainty without another mutation. |
| Concurrent duplicate requests | Sixteen same-intent calls across eight threads result in one simulated provider mutation. |
| Lost acknowledgement | Matching observed state without the provider operation identity remains attribution-unknown. |
| Competing actor | Retrying after a simulated operator rollback does not overwrite that rollback. An alternative objective ID cannot bypass the unresolved target reservation. |
| Recovery and progress | Observer outage can recover through resumed read-only checks; exhausted observation budget leads to review with uncertainty retained. Completion survives settlement interruption and cleanup resumes after approval expiry. |
| Cloud request construction | The native etag and traffic-only update mask are present; missing ProtoJSON false defaults are handled without treating an explicitly reconciling service as ready. |
| Evidence | Raw bytes can be retrieved by digest over the observer HTTP interface; ordinary history edits are detected. No external anchoring claim is made. |

Python source, TOML and YAML were parsed. Static compose inspection confirmed that the gateway and worker have only the internal network, receive no Google credential or signing private-key mounts, that no container receives the authority private key, and that writer/observer ports are unpublished. This is configuration inspection, not a running-container isolation test.

Verification used the installed cryptography runtime. No dependency installation was attempted for this patch; the original build's deployment dependency installation had been blocked. The optional google-auth, requests and gunicorn dependencies were not executed here. Dependency resolution, image build, container startup, secret mounts, Linux network isolation, live IAM, Cloud Run mutation/operation semantics, real application probe behavior and audit correlation remain unqualified. Docker and gcloud remain unavailable in this workspace.

Durable unresolved reservations are exercised locally. A supported reconciliation-and-resume workflow remains open. This patch adds no such transition and does not scan or repair historical 0.1.0 records.

No previous frozen suite or conformance result is relabeled by this build. No source in those components was edited. This candidate's 31 checks are separate from the existing 31-test Sentinel suite. This is author-performed adversarial validation, not third-party qualification.
