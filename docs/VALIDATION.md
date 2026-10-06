# Validation status

This release is a locally tested Phase-2 pilot candidate. No AWS experiment, Terraform apply, GitHub workflow dispatch or cloud mutation was executed during preparation.

Completed checks:

- 60 automated tests: session persistence/expiry/lineage, explicit deny and unsupported IAM, oracle isolation, witness-time matching, integrity, six complete simulated scenario pipelines, cleanup failure handling, schedule boundaries, source freeze, cohort counts and immutable OIDC subject validation. See `validation/TEST_RESULTS.txt`.
- Six simulated 7,200-second scenarios through raw evidence → observation/reference → B0/B1/B2/B3/T/T-S → metrics/S7. Synthetic results are not live research evidence.
- 36,916 simulated runner requests checked against pinned botocore 1.43.18 API shapes across 19 operations. Conditional evaluation-slot PutObject shape also checked. See `validation/SDK_REQUEST_VALIDATION.json`.
- Python syntax, workflow YAML parsing, pinned action hash lengths, Terraform formatting and HCL parsing.
- Source freeze and extracted-archive verification.

Not established here:

- Live OIDC exchange, AWS authorization, propagation behavior, quota headroom, runtime timings or actual research effects.
- Full Terraform provider validation: provider startup was blocked by `listen unix ... socket: operation not permitted`. Run `terraform init` and `terraform validate` on your machine before provisioning. The Apple Silicon provider-lock refresh also hit a network timeout; freeze any local lock-file update before pilots.
- Zero-cost feasibility for your account and GitHub plan. No automatic financial spending cap is implemented.
- Universal IAM correctness, continuous reachability, or an algorithmic advantage of T over equal-input B2/T-S.

The included GitHub-only OIDC preflight handles legacy and immutable-ID repository subject formats. It records safe subject fields without contacting AWS. Custom subject templates outside these formats stop with an error.

The delivered source digest is recorded in `SOURCE_FREEZE.json`; the ZIP digest is in the separate readable checksum notes. A digest establishes byte identity, not scientific validity or a third-party signature.
