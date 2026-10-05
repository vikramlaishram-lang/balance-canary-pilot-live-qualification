# Canary Pilot 0.1.1 — failed-check preservation

12 September 2026. **Locally verified correction; deployment unqualified.**

The reproduced defect in 0.1.0 let a final service-read timeout replace an established `CHECK_FAILED` verdict with `OBSERVATION_UNAVAILABLE`. The signed check still said `smoke: false`, but the coordinator treated the result as a recoverable observation outage. Later passing observations could complete the same objective without review.

The correction preserves this invariant:

> A later observation failure must not erase an already established negative completion-relevant finding.

Only two runtime behaviors changed, both in `balance/engine.py`:

- The observer retains `CHECK_FAILED` and the failed check facts if subsequent target verification raises. Its existing signed `reason` records that later verification failure; absent final-read bytes are not invented.
- After verifying the observation signature, intent/challenge binding and freshness, the coordinator inspects the configured required-check facts. An explicit false fact requires `NEEDS_REVIEW` regardless of the summary verdict. It excludes the observation from passing samples before attempting completion.

The existing review state remains a stop for automatic progression. This patch adds no continuation, reconciliation, cancellation or authority mechanism. The worker remains deterministic.

## Executed qualification

| Experiment | Original 0.1.0 | Corrected 0.1.1 |
| --- | --- | --- |
| Failed smoke check followed by final-read timeout | `OBSERVING`; verdict `OBSERVATION_UNAVAILABLE`, `smoke: false` | `NEEDS_REVIEW`; verdict `CHECK_FAILED`, `smoke: false`, read error retained |
| Coordinator restarted; three later signed passing observations available | Eventually `COMPLETED` | Remains `NEEDS_REVIEW`; no completion record |
| Authentic observation with neutral verdict and false required check | Remains `OBSERVING` | Enters `NEEDS_REVIEW` |
| Simulated external mutations in the full sequence | 1 | 1 |

The two added regression tests fail against the unpatched runtime and pass after correction. The full corrected suite passes **31/31**. The original 29 tests are retained without changes to their assertions. Python 3.12.14 and cryptography 46.0.0 were used. All external target effects in these experiments are simulated; native runtime code, signatures and SQLite persistence are exercised.

Original archive SHA-256: `38188618366b8379813717d9b2029608ef99fcbe8720210c667c26e110e5797e`. Its 24 manifest-tracked files remain unchanged. That release and the earlier frozen Balance components are preserved separately.

## Evidence and reproduction

`validation/` contains baseline integrity, the two red/green regression logs, the full 31-test log, signed before/after observations and objective histories, a reusable fault probe, and the focused runtime/test diff. The probe uses the original package's simulated provider fixture; it does not alter enforcement or call Google Cloud. Only temporary test public keys and signatures are included in the evidence; private keys are discarded.

From an extracted package, with Python and cryptography installed:

```bash
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -v
PYTHONDONTWRITEBYTECODE=1 python validation/failure_path_probe.py --source . --out /tmp/balance-canary-probe.json
```

The same probe can target a separately extracted original archive by changing `--source`. Its JSON records the first state, signed negative facts, later passing observations, states after restart, final state and mutation count. The expected corrected final state is `NEEDS_REVIEW`.

## Remaining qualification

Supported reconciliation/resume remains open. Container startup and isolation, deployment dependencies, real IAM scope, real Cloud Run effects and application-probe validity remain untested. No live credentials, target mutation or deployment was used for this patch. The next empirical milestone remains the planned controlled live experiment covering authority authenticity, identity separation, consequence identity, recovery integrity and completion integrity.

This patch does not retroactively qualify jobs already processed by 0.1.0 or scan their historical observations. Review potentially affected histories before resuming an old deployment. No automatic state repair or manual database-edit procedure is supplied.

This is a correction and local qualification by the implementation's author, not an independent third-party assessment or production qualification.
