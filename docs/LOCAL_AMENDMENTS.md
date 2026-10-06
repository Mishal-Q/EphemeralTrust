# Local Pre-Pilot Amendments

## Terraform provider lock refresh

During Phase-2 bootstrap on macOS arm64, `terraform init` refreshed
`infra/.terraform.lock.hcl` while installing the locked HashiCorp AWS provider.

Environment:
- Terraform: 1.16.1
- Platform: darwin_arm64
- AWS provider: 6.65.0

Reason:
The packaged lock file required initialization for the local execution platform.
No experiment methodology, scenario definition, analysis logic, protocol parameter,
or scientific acceptance criterion was changed.

This amendment occurred before any Phase-2 pilot execution.

## 2026-09-30 — Transport exception handling amendment

During the S4 pilot attempt, a botocore transport exception exposed `response = None`, causing the evidence recorder itself to terminate while processing the exception.

The request recorder was amended to safely handle non-dictionary or null exception response metadata. Such transport failures are now journaled conservatively as UNKNOWN rather than crashing the recorder.

A regression test (`test_transport_exception_with_none_response_is_journaled_unknown`) was added. The amended implementation passed the complete 61-test self-test suite before refreezing.

The failed pre-amendment S4 attempt is retained separately and is not treated as a successful replacement pilot.
