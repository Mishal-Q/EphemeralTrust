# EphemeralTrust

EphemeralTrust is a research project exploring a small but important problem in cloud access analysis: **does the IAM configuration we see right now actually describe all of the access that still exists?**

With temporary AWS credentials, not always.

A role can lose the ability to issue a new session while a session issued earlier is still alive and usable. That makes access analysis more interesting than simply looking at the current policy or taking occasional configuration snapshots.

EphemeralTrust was built to explore that gap in a controlled AWS environment and see what changes when session state and observation timing are taken into account.

**Paper:** [EphemeralTrust: Session State and Observation Design in Controlled AWS Access Traces](paper/EphemeralTrust_Manuscript.pdf)

## The idea

The experimental environment combines GitHub Actions OIDC, AWS STS, IAM roles and policies, temporary credentials, role chaining, S3 canary operations and CloudTrail.

During an experiment, permissions or trust relationships can change while configuration state, session issuance and access attempts are recorded over time.

The interesting part comes afterward: reconstructing what access was possible from different amounts and types of evidence.

In other words, if two methods observe the same changing environment differently, **what does each one miss?**

## What came out of it

The clearest case was scenario S3.

A previously issued session remained usable while equivalent fresh session issuance was denied. The final dataset contains **168 paired observations** of this state.

Sampling frequency also made a noticeable difference. At a 60-second interval, the configuration-oriented B1 condition recovered the selected witness semantic tuple in **0/10** phase projections, compared with **10/10** for the session-aware B2 condition.

There is also a denser observation condition, T. One important limitation is that T-S uses the same candidate logic as B2 and simply has denser observations available. Better first-witness results therefore should not be treated as evidence of a better algorithm.

S5 explores another timing problem. If observations are combined without respecting when credentials could actually have existed, it is possible to construct a candidate path that does not fit the declared credential schedule.

These are controlled scenarios rather than population-level measurements of AWS IAM. The goal was to make the timing problem observable and test how different reconstruction conditions behave around it.

## Repository structure

- `src/` - Phase 2 implementation, experiment configuration and tests
- `experiments/infra/` - Terraform infrastructure
- `analysis/` - offline reconstruction code
- `results/` - selected derived results
- `docs/` - methodology, validation, execution and provenance material
- `paper/` - research manuscript

The repository contains the implementation used for the research, but not the entire private experiment archive. Raw runtime material, credentials, Terraform state, local environments and working copies are intentionally excluded.

## Reproducing the project

A good route through the repository is:

1. `src/configs/protocol.json`
2. `src/ephemeraltrust/`
3. `src/tests/`
4. `analysis/reconstruct.py`
5. `results/`

The final Phase 2 implementation was frozen at Git commit:

`0872d08273f5239e45cb9fb92da1aa6a70214619`

Source SHA-256:

`c2f58a037a24fc2ca403c867477d5f545de96375b7777f8d93813b52e7c39819`

Per-file hashes are recorded in `docs/SOURCE_FREEZE.json`.

The offline tests are the easiest way to check the implementation locally. The repository also contains AWS and Terraform code from the live experiments, so those parts should only be run after checking the configuration and `docs/RUNBOOK.md`.

## Documentation

For the details behind the experiments:

- `docs/METHODOLOGY.md` - experimental and analysis design
- `docs/VALIDATION.md` - validation record
- `docs/RUNBOOK.md` - execution procedure
- `docs/REPRODUCIBILITY.md` - what is included in the public artifact
- `docs/ARCHIVE_IDENTITY.txt` - frozen archive provenance

## Author

**Mishal Qadir**
