# Phase 2 execution guide

This package is a **pilot candidate**. Offline tests do not establish live AWS correctness or the scientific value of a larger cohort. No AWS execution was performed when this package was prepared.

Use a new repository and new experiment resources. Keep the Phase-1 ZIP and its checksum unchanged. Do not delete your only copy of earlier research records.

## 1. Open the package and run the offline checks

Unzip the delivery ZIP. Open a terminal in its `EphemeralTrust_Phase2` folder. The following commands assume macOS or Linux, Python 3.12, and that directory as the working directory. Install Python 3.12 first if `python3 --version` reports another version; select its executable when creating the environment.

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python ep2.py self-test
python ep2.py verify-source
python ep2.py demo --out results/offline-demo
```

Expected: all tests pass; source verification prints `PASS` and a digest; six synthetic scenarios finish with `TRACE_COMPLETE`. The demo contains artificial evidence and cannot qualify as a live pilot. Inspect `results/offline-demo/` for the raw and derived outputs. An existing output directory is intentionally not overwritten: use `results/offline-demo-2` for a second demo.

Optional SDK request-shape check (downloads dependencies but makes no AWS requests):

```bash
python -m pip install -r requirements-live.txt
python scripts/validate_sdk.py
```

Stop if any check fails. Preserve the error and output. Do not bypass `verify-source` or edit a result to make a gate pass.

## 2. Decide whether to proceed with this amended design

Read `docs/METHODOLOGY.md` and `configs/protocol.json`. In particular, equal-input B2 and T-S are expected to agree. The full-resolution T comparison alone cannot establish an algorithmic advance over B2. This package does not implement the original 3,600-second interval, universal AWS nonreachability, or a complete IAM evaluator.

A six-scenario pilot is about 12 trace-hours, plus setup, the S6 companion and collection overhead. The proposed evaluation is **55 runs / 110 trace-hours**. It uses at least 6,600 experiment-job minutes plus about 1,200 S6 companion minutes, before pilots and overhead. Check your actual GitHub Actions allowance, AWS account billing rules, credits and request/storage charges. There is no zero-cost guarantee or automatic spending cap in this package. If strict zero cost cannot be established for your account, do not authorize live runs or the cohort.

## 3. Prepare GitHub and AWS access

Install and authenticate Git, GitHub CLI (`gh`), AWS CLI and Terraform (tested parser/format version 1.12.2; configuration accepts 1.6–1.x). Use your normal local AWS administration profile for bootstrap. Do not put access keys in this repository or GitHub variables. Runtime experiments use GitHub OIDC.

Set your intended **new** repository name, retaining exact owner/repository spelling:

```bash
export EP2_REPO='YOUR_OWNER/YOUR_NEW_REPOSITORY'
gh auth status
aws sts get-caller-identity
```

Confirm that the displayed AWS account is the dedicated experiment account. It must have no external writer changing the experiment roles or bucket. Review organization SCPs, permission boundaries and account-level controls: this model does not evaluate them. A checked configuration flag is your scope declaration, not an automated proof of their absence.

Publish the candidate before the GitHub-only preflight. This creates a private repository and pushes source; it does not contact AWS:

```bash
git init -b main
git add .
git status --short
git commit -m "Phase 2 candidate before OIDC preflight"
gh repo create "$EP2_REPO" --private --source=. --remote=origin --push
```

Review staged files before committing. No local configuration, results, credentials, Terraform state or provider binaries should be staged. If you already created an empty repository, add its remote and push instead of running `gh repo create`.

Create two repository environments in GitHub Settings → Environments: `ep2-main` and `ep2-alternate`. Restrict deployment branches for **both** to `main`. Your GitHub plan must support these environments and restrictions for the chosen repository visibility; verify that before provisioning AWS. Do not silently make research records public to obtain a feature. Environment-based OIDC subjects do not themselves constrain the branch.

Run the GitHub-only preflight:

```bash
gh workflow run oidc-preflight.yml --repo "$EP2_REPO" --ref main
gh run list --repo "$EP2_REPO" --workflow oidc-preflight.yml --limit 5
```

Watch its numeric run ID and download both artifacts with `gh run download RUN_ID --repo "$EP2_REPO" --dir results/oidc-preflight`. Open the two JSON files. They must agree on `oidc_subject_repository` and differ only in their declared environment context/subject suffix. Copy that repository component exactly into Terraform in step 4. It may be `OWNER/REPOSITORY` or `OWNER@123456/REPOSITORY@789012`. New repositories can use immutable IDs; do not guess the subject or weaken the trust policy to a wildcard. This preflight records safe subject fields only, never the token, and makes no AWS call.

## 4. Validate Terraform locally; provision only after review

These commands prepare a plan and subsequently create AWS resources. They are distinct from the offline checks. First prepare ignored local configuration:

```bash
mkdir -p local
cp infra/terraform.tfvars.example local/bootstrap.tfvars
```

Edit `local/bootstrap.tfvars` with your exact repository, the preflight's `oidc_subject_repository`, 12-digit AWS account ID as a string, and a unique installation name. `create_oidc_provider = false` reuses an existing GitHub provider. Set it to true only if this account has no `token.actions.githubusercontent.com` provider. An existing provider must include audience `sts.amazonaws.com`. Do not create a duplicate or delete a shared provider.

```bash
terraform -chdir=infra init
terraform -chdir=infra validate
terraform -chdir=infra plan -var-file=../local/bootstrap.tfvars -out=../local/bootstrap.tfplan
```

**Required:** `validate` must succeed on your machine. Provider execution was blocked by the build environment's socket restriction, so the delivered HCL parse and request-shape checks do not substitute for this step. An Apple Silicon provider download/lock refresh also could not be completed in that environment. `init` may add your platform's checksum to `infra/.terraform.lock.hcl`; freeze that change in step 5 before pilots.

Read the complete plan. It should create an isolated canary bucket with private access and SSE-S3, an `ep2-controller-...` role and scoped policy, and optionally a new OIDC provider. It must not replace or destroy Phase-1/shared resources. Bootstrap credentials need permissions to create these resources; the runtime controller deliberately does not have general administrative rights.

Only after reviewing the plan and costs:

```bash
terraform -chdir=infra apply ../local/bootstrap.tfplan
terraform -chdir=infra output -json live_config > local/live.json
```

Keep `infra/terraform.tfstate` and `local/bootstrap.tfvars` securely for eventual teardown. They are ignored by Git and excluded from the source freeze. Do not commit them.

Open `local/live.json`. Verify every ARN, repository and bucket. Change `zero_cost_reviewed` and `dedicated_experiment_scope_confirmed` to true only after the corresponding reviews. Keep region `us-east-1`, `max_trace_seconds: 7200` and `max_live_runs_per_dispatch: 1`. Do not substitute credentials for these fields.

## 5. Freeze, commit and publish the source before collecting pilot results

The ZIP includes a source freeze. If Terraform changed its lock file or you made a justified pre-pilot amendment, document it in `docs/LOCAL_AMENDMENTS.md` **before any pilot**, run the tests and regenerate the freeze. The command below refuses to freeze failing tests:

```bash
python ep2.py freeze
python ep2.py verify-source
git add .
git status --short
git commit --allow-empty -m "Freeze Phase 2 pilot implementation and protocol"
git push origin main
```

Review `git status` before committing: no `local/`, `results/`, `.venv/`, Terraform state, credentials or provider binaries should be staged. The repository was created in step 3; this commit records the final pre-pilot state.

Finish the two environment restrictions in step 3. Enable Actions in the repository. Set the runtime configuration as a repository Actions variable:

```bash
gh variable set EP2_LIVE_CONFIG_JSON --repo "$EP2_REPO" < local/live.json
git rev-parse HEAD
python ep2.py verify-source
```

Record that commit and digest with your study records. All pilot jobs must use this same source freeze. GitHub records its exact commit in each run. Do not edit the implementation or protocol after inspecting pilot results and then pool the resulting runs as if unchanged; document an amendment and start a separate pilot series.

## 6. Run one pilot, download it, then proceed scenario by scenario

Start S1 only:

```bash
gh workflow run phase2-run.yml --repo "$EP2_REPO" --ref main -f scenario=s1 -f cohort=pilot -f slot=0 -f authorize_live=true
gh run list --repo "$EP2_REPO" --workflow phase2-run.yml --limit 5
```

Copy the numeric workflow run ID from the listing. Replace `123456789` below with it:

```bash
export EP2_GH_RUN_ID='123456789'
gh run watch "$EP2_GH_RUN_ID" --repo "$EP2_REPO" --exit-status
gh run download "$EP2_GH_RUN_ID" --repo "$EP2_REPO" --dir results/pilots
```

Download even when `watch` reports failure. Each run lasts roughly two hours plus setup, restoration and a ten-minute CloudTrail collection lag. Artifact retention is 14 days; preserve downloaded artifacts yourself immediately.

Inspect raw `run.json` and adjacent `*-analysis/summary.json`. Required instrumentation includes a full trace, confirmed restoration and cleanup, usable scheduled observations and sealed evidence. A missing expected effect is a research outcome, not permission to keep rerunning until it appears. S1 must demonstrate that the installation works before proceeding.

Repeat the dispatch with `scenario=s2`, then `s3`, `s4`, `s5`, `s6`, always `cohort=pilot`, `slot=0`. Run one at a time. Download each complete workflow into `results/pilots`; artifact names are unique. S6 has **two artifacts**, including the separate main-context control; download both (the command without `--name` does this).

The workflow collects management-event corroboration, reseals raw evidence and then analyzes it. Collection is not proof of complete event delivery. Missing CloudTrail records are never converted to denials; S3 data-event logging is not enabled.

Do not use GitHub's rerun button to silently replace an attempt. All attempts count in the audit trail. If code must change, preserve the failed series separately, document the reason, refreeze and begin a new pilot series. The gate intentionally rejects multiple same-scenario pilots in its input so selection cannot happen silently. Keep every prior attempt outside the new series' gate directory and include it in the study's attempt inventory.

## 7. Evaluate the pilot gate and scientific value

```bash
python ep2.py pilot-gate --root results/pilots --out local/pilot_gate.json
```

Read the output file. `BLOCKED` means a required check is missing or failed. `INSTRUMENTS_PASS_RESEARCH_REVIEW_REQUIRED` means only that the instruments meet this gate. It does **not** mean that the original research claim was proved or that 55 runs are worthwhile.

Review all six raw/derived pairs, S6 control, the S5 scoped certificate, UNKNOWNs, reference eligibility, same-input B2/T-S equality and S7 sensitivities. Decide whether the remaining comparison answers a useful, amended question. Do not interpret synthetic results as pilot evidence. Keep pilots out of evaluation estimates.

To reanalyze an individual sealed run independently:

```bash
python ep2.py analyze --run results/pilots/ARTIFACT_NAME/EXACT_RUN_FOLDER --out results/reanalysis/EXACT_RUN_FOLDER
```

Replace both placeholders with real paths. Use a new output directory. The default gate expects the workflow-created analysis folder adjacent to the raw folder. If CloudTrail collection changed a seal after analysis, the stale analysis is rejected: regenerate it from the final sealed evidence, preserving the old derivative separately.

## 8. Authorize a cohort only after the review

Generate the proposed fixed schedule without starting anything:

```bash
python ep2.py cohort-plan --out local/cohort_plan.json
cp configs/evaluation_review.example.json local/evaluation_review.json
```

Fill in the researcher's name and substantive rationale. Set each acknowledgment true only if satisfied, including scientific scope, equality, null explanation, exclusions and cost feasibility. If the original question cannot be answered, stop and revise prospectively; do not sign a form merely to bypass the gate.

```bash
python ep2.py approve-cohort --gate local/pilot_gate.json --review local/evaluation_review.json --out local/evaluation_approval.json
gh variable set EP2_EVALUATION_APPROVAL_JSON --repo "$EP2_REPO" < local/evaluation_approval.json
```

The approval embeds the frozen randomized schedule. Inspect its `plan.slots`. For each next unused slot, dispatch the exact scenario assigned to it. For example, **only if slot 1 actually says s4**:

```bash
gh workflow run phase2-run.yml --repo "$EP2_REPO" --ref main -f scenario=s4 -f cohort=evaluation -f slot=1 -f authorize_live=true
```

Watch and download each run using step 6, but use `--dir results/evaluation`. Continue sequentially through the approved slots only while instrumentation and resource limits remain acceptable. A conditional S3 claim prevents duplicate use of a slot; a failed attempt is retained, not overwritten or silently retried. Replacement runs require a documented prospective amendment and reviewed new plan. Do not delete slot claims to bypass this rule.

After collecting the cohort:

```bash
python ep2.py cohort-summary --root results/evaluation --out results/evaluation_summary.json
```

This refuses to mix source/protocol/cohort identities and averages phases within each run. At least eight qualifying independent core runs are required before the implemented descriptive bootstrap interval is emitted. The flow of every attempted run must accompany conditional witness-recovery estimates. S1 is descriptive; S5 has separate scoped candidate adjudication. No manuscript superiority claim is automatically generated.

## 9. Failure handling and cleanup

Normal execution restores configuration and removes the exact run's roles and objects in `finally`. Check `restoration` and `cleanup_confirmed`; do not assume that cancellation or a killed runner cleaned up. A hard termination, expired controller authorization or network outage can prevent cleanup.

Copy the exact run ID from the retained `run.json` or workflow environment, such as `ep2-123456789-1-s3`. If cleanup was not confirmed, dispatch the bounded cleanup workflow:

```bash
gh workflow run phase2-cleanup.yml --repo "$EP2_REPO" --ref main -f run_id=ep2-123456789-1-s3 -f authorize_cleanup=true
```

Use your real ID, watch the workflow, download its cleanup evidence and inspect it. Cleanup only addresses that run's derived resources and verifies role ownership tags. If it fails, retain the error and inspect the exact named resources using your administrator access. Do not delete roles by a broad name wildcard. Setup can fail after a server-side creation but before the client receives acknowledgment; this is another reason to inspect the exact derived names.

After the whole study, archive raw evidence, source freeze, approval, cohort plan, logs and derived results. Evaluation slot-claim objects deliberately remain. List the dedicated bucket, identify the exact `ep2-run-cohort-APPROVAL_PREFIX/` prefix from the approval ID, archive its JSON records and delete only that verified prefix when no further runs will occur. Do not empty an unrelated or shared bucket. The Terraform bucket uses `force_destroy = false`, so teardown stops if objects remain.

Then review a destruction plan for this isolated installation:

```bash
terraform -chdir=infra plan -destroy -var-file=../local/bootstrap.tfvars -out=../local/teardown.tfplan
terraform -chdir=infra apply ../local/teardown.tfplan
```

The second command deletes the resources shown in the first. Apply only after checking the plan and archive. A reused OIDC provider is a data source and is not deleted by this configuration. Preserve the final state and teardown record securely.

## What to retain

Keep the Phase-1 freeze separately. For Phase 2 retain the delivered ZIP/checksum, final committed source plus `SOURCE_FREEZE.json`, any amendments, non-secret live configuration, all attempt artifacts including failures and S6 controls, pilot review, evaluation approval/slots, raw integrity manifests, independent reanalysis outputs, and teardown evidence. The source package alone cannot replace future run evidence or your local Terraform state.
