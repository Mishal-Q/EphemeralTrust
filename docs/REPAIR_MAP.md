# Phase-1 blockers → Phase-2 implementation

| Earlier blocker | Repair | Acceptance evidence |
|---|---|---|
| B2 could not retain an old session after issuance trust disappeared | Observed valid sessions are explicit starting states; current permissions remain evaluated | Persistence, no-issuance, expiry, current-deny tests |
| Temporal paths required overlapping edge windows | Exact parent-at-issuance lineage and independent child lifetime | Parent validity and child-survives-parent tests |
| S5 intermediate/hypothetical paths confused endpoints | Exact S3 endpoint, three-edge chain, ledger expiry barrier and scoped negative certificate | Three-edge/intermediate tests and full S5 simulation |
| Hidden issuance broke lineage | Successful experimental/verifier issuances journaled with parent, actor, context and actual expiry | Full-run issuance-ledger accounting test |
| Late changes/confirmations counted as valid timing | Frozen schedules, lateness gate, third completion within 300 seconds; restoration separate | 300-second inclusive and late-confirmation tests |
| Observation/reference leakage | Strict DTO bridge; outcomes only in reference builder | Unknown reference/probe fields rejected |
| Prior appearance inflated persistence detection | Primary witness-time matching distinct from historical structural recovery | Prior-structure, post-sample issuance, between-sample expiry tests |
| IAM/error ambiguity recoded as denial | Conservative supported subset; explicit deny; UNKNOWN for unsupported and transport/token errors | IAM and error classification tests |
| Repeated polling inflated denominator | One direct witness per predeclared episode | Repeated-poll and empty-reference tests |
| S6 lacked concurrent main-context evidence | Separate environment/job and sealed companion stream | Control UNKNOWN/coverage gate; live validation pending |
| Same-input comparison could overclaim novelty | T-S deliberately equals repaired B2 | Equality test; explicit scope in methodology |
| Analysis could use stale raw evidence | Raw seals and analysis input-seal check | Tamper rejection and deterministic reanalysis tests |
| Accidental mixing/scaling | Source/protocol freeze; live pilot gate; explicit review; one-use evaluation slots | Source-edit, synthetic rejection, cohort count tests; cloud slot behavior pending live validation |
| Cloud API shape assumptions | Validate simulated calls against pinned botocore service models | `validation/SDK_REQUEST_VALIDATION.json`; permissions/propagation remain live checks |

These are new acceptance tests. The historical 86-test result is not used to certify this implementation.
