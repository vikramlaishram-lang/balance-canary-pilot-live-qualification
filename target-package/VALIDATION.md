# Target preparation validation — 12 September 2026

Status: **PREPARED; LIVE PROVISIONING NOT RUN.**

Six local fixture checks pass under Python 3.12.14. They cover distinct markers and nonce-bearing responses over actual loopback HTTP, rejection of invalid or duplicate nonces, computed checks becoming false when their underlying conditions fail, rejection of POST, capture of target fields without granting authority, and rejection of inconsistent revision/marker/initial-traffic records.

The HTTP tests run local servers in one process. Pinning tests use explicitly synthetic Cloud Run-shaped data. They establish no OS isolation, Google authentication, provider semantics, IAM boundary, or live consequence result. The provisioning command sequence has been source-reviewed against linked Google command documentation but has not been executed. No real project ID, revision name, billing account, or cloud credential was selected.

All Python sources parse. `provision.py plan` executes without a cloud call and leaves actual project and revision identifiers null. The enclosed Balance Canary Pilot v0.1.1 archive hashes exactly to `00ea748bdacab7b743bf54db2fbf6ee976ac6cdbc249cc3a8c176b80346cf74e`; its source is unchanged and its existing 31-test qualification is neither expanded nor rerun as part of this fixture preparation.

This workspace has no gcloud, Docker or Terraform executable and no detected local Google credential configuration. Available connector discovery exposed no matching authenticated GCP provisioning path. Consequently image build, project creation, billing linkage, service deployment, real identity checks and the Balance live experiment are all **NOT RUN**.

To reproduce the fixture checks:

```bash
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -v
python provision.py plan
```

`validation/unittest.log`, `validation/results.json` and `validation/prepared_plan.json` record the local outputs. Actual creation requires the operator inputs and command in `README.md`. Successful target creation will still mean only that the external fixture is prepared; the exact v0.1.1 candidate must then undergo its planned live qualification.
