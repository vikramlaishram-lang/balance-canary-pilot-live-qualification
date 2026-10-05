# Disposable target for Balance Canary Pilot v0.1.1

**Prepared on 12 September 2026. No GCP project or service has been created by this package's preparation.**

The target is fixed to a new non-customer project, region `asia-south1`, service `balance-canary-target`, and exactly two revisions. The base marker is `VERSION=baseline`; the candidate marker is `VERSION=candidate`. Provisioning leaves explicit baseline traffic at 100% and candidate traffic at 0%. The proposed 90/10 change is left to the signed-authority path in the unchanged Balance v0.1.1 candidate.

Google lists `asia-south1` as Mumbai, India. [Cloud Run locations](https://docs.cloud.google.com/run/docs/locations)

## What is ready

- `target/app.py`: a read-only, deterministic HTTP fixture using Python's standard library.
- `target/Dockerfile`: a container definition that runs the fixture as a non-root user.
- `provision.py`: creates a new project, links the selected billing account, builds and pushes one image, deploys that immutable image digest twice with different version markers, and records the actual target identifiers and baseline.
- `runtime/`: the byte-identical v0.1.1 archive, SHA-256 `00ea748bdacab7b743bf54db2fbf6ee976ac6cdbc249cc3a8c176b80346cf74e`.
- `validation/`: local fixture results. These tests are separate from the candidate's 31 tests and do not increase its qualification.

The provisioning script never submits a Balance objective, signs authority, deploys the Balance runtime, sets 90/10 traffic, or changes an existing application's configuration. It always calls project creation first; an existing project makes that operation fail. It neither retries failed commands automatically nor reuses an existing evidence directory. If creation stops partway through, inspect the recorded commands and real project before continuing, especially before another revision deployment.

## The fixture's actual claim

`GET /` returns its version marker, actual Cloud Run revision name, service name and the deterministic application result `ecnalab`.

`GET /balance-health?nonce=<32 lowercase hexadecimal characters>` returns:

```json
{
  "VERSION": "candidate",
  "revision": "<actual K_REVISION supplied by Cloud Run>",
  "nonce": "<exact request nonce>",
  "checks": {"ready": true, "smoke": true}
}
```

Those booleans are evaluated. `ready` checks the deployed marker and service/revision configuration. `smoke` executes the same string-reversal function exposed by the application, against two known inputs. They establish only these small fixture properties. They make no claim about business health or production release quality. A nonce binds a response to the request; it is not proof that a Balance dispatch caused the service's state.

Markers are loaded from revision configuration when the process starts. Revision names come from `K_REVISION`; the application does not invent them. Cloud Run supplies `PORT`, `K_SERVICE` and `K_REVISION`, and the container listens on `0.0.0.0`. [Container contract](https://docs.cloud.google.com/run/docs/container-contract)

The service requires Cloud Run invocation authentication. Authentication is supplied by Cloud Run, not implemented by this tiny local HTTP server. Local tests therefore establish no IAM boundary. Base responses remain base samples under the existing candidate semantics; they are not counted as candidate evidence.

## Operator inputs needed for actual creation

Use an authenticated operator environment with Python 3.11+, gcloud and a working Docker engine. Its principal needs permission to create the disposable project, link the selected billing account, and provision the listed resources. Supply an organization or folder if your account requires a parent.

Set `PILOT_PROJECT_ID` to an unused ID beginning `balance-canary-pilot-`, with at most 30 characters in total. Set `PILOT_BILLING_ACCOUNT_ID` to the billing account authorized for this disposable experiment. No real ID or billing account is embedded in this package. Project creation accepts an explicit immutable ID; an optional organization/folder controls its parent. [Project creation](https://docs.cloud.google.com/sdk/gcloud/reference/projects/create)

Linking billing enables paid resource usage in that project. The deployment requests zero minimum instances and a maximum of one instance per revision; this is not a spending cap. The container registry also retains the built image. [Billing link](https://docs.cloud.google.com/sdk/gcloud/reference/billing/projects/link)

From the extracted package:

```bash
python provision.py plan
python provision.py create \
  --project-id "$PILOT_PROJECT_ID" \
  --billing-account "$PILOT_BILLING_ACCOUNT_ID" \
  --out qualification-target-run
```

Add `--organization <actual ID>` or `--folder <actual ID>` when required. Use an approved operator account; no access tokens, service-account keys or other credentials should be put in this package or sent in conversation. The script uses the active gcloud account. Its read-only REST capture obtains a token internally and does not print or retain it.

The script creates a target runtime service account and grants it no project roles. Actual effective permissions, including inherited permissions, are not inferred from that fact. It configures Docker's credential helper for the Mumbai registry, builds a Linux amd64 image, pushes it, records the returned repository digest, and deploys that digest for both revisions. Baseline traffic is made explicit before the candidate is deployed with `--no-traffic`. No revision names are chosen in advance. [Deploy command](https://docs.cloud.google.com/sdk/gcloud/reference/run/deploy), [Explicit traffic allocation](https://docs.cloud.google.com/sdk/gcloud/reference/run/services/update-traffic)

The authenticated provisioning environment is the operator environment. Use the candidate's separate deployment runbook for its runtime host and role credentials; the coordinator must not receive the provisioning principal's credentials or authority.

## What gets pinned after creation succeeds

`qualification-target-run/target-record.json` captures the actual project ID and number, two returned revision names and markers, target UID, observed generation, etag, service URL, deployed image digest, operator and target runtime principal, candidate archive hash, and hashes of the raw service/revision evidence. It checks that exactly two revisions exist, that both use the expected image, and that requested and observed traffic are explicit baseline 100%.

The directory also contains the raw Cloud Run v2 responses, recorded setup command outputs, a SHA-256 for the target record, and `policy.json` prepared from the unchanged candidate's template. The writer and observer principal fields remain unset until those identities are actually provisioned and verified. A target record is a setup record, not an authority grant or a successful qualification result. Obtain a fresh service snapshot through the native candidate CLI immediately before preparing and signing a live intent.

No target record with real identifiers is included in this preparation package because no target has yet been created. Synthetic identifiers in unit tests are explicitly local fixtures.

## Qualification still to execute

After target creation, use the enclosed candidate's `DEPLOYMENT.md` to build and run the exact candidate on its dedicated host, establish the separate writer/observer identities, and collect actual IAM and audit evidence. The target preparation script does not provision these roles, create their key files, or claim identity isolation.

The live experiment still needs to establish authentic exact authority, identity separation, operation-to-intent association, interruption/intervention integrity, and completion integrity. Record image and policy identities alongside the actual principals. Keep unexpected actors or unconfirmed interventions visible in the result. A prepared target or a successful API response is not a qualification pass.

Supported reconciliation/resume remains a separate open milestone. The v0.1.1 source and its historical qualification have not changed. This package supplies only the disposable external fixture and setup procedure.

After the experiment and evidence export, retire the disposable project through your normal explicit project-deletion process. Preserve evidence outside that project first; this script performs no automatic cleanup.
