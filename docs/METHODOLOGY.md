# Prospective Phase-2 methodology and limits

Status: pilot candidate. This document and `configs/protocol.json` must be frozen before observing new AWS results. Phase 1 remains a separate, closed cohort. This is a repaired and explicitly amended design, not a retrospective relabeling of Phase 1.

## Question this implementation can answer

Within a controlled same-account GitHub OIDC → entry role → optional chain role → exact S3 object experiment, how does recovery of directly witnessed access episodes vary with configuration sampling and exact observed session lineage? Can an atemporal union suggest a chain whose observed credentials and timed grants do not support execution?

The model does not enumerate every hypothetical credential an attacker might have minted. It uses the harness's actual successful issuance ledger, including exact parent linkage, context, issuance and expiry. An UNKNOWN experimental STS response marks ledger completeness unestablished, blocks the live instrument gate and excludes comparison rows; it cannot certify S5 absence. Administrative controller credentials are outside the experimental attacker lineage. Independent verifier and main-control actors are distinguished and cannot become attacker sessions. This restriction matters particularly for S5.

## Six scenarios

Times below are seconds after trace origin. Every trace is 7,200 seconds; setup precedes origin. The machine-readable protocol is authoritative.

| Scenario | Intended mechanism | Scheduled intervention |
|---|---|---|
| S1 | Stable direct control | No intervention |
| S2 | Temporary direct PutObject capability | Grant 1,800; revoke 2,400 |
| S3 | Issued session survives a blocked issuance edge | Request old session 1,740; block fresh trust 1,800; restore 3,600 |
| S4 | Executable three-edge chain | Grant chaining 1,800; chain capability 2,400; remove capability 3,000; remove chaining 3,300 |
| S5 | Incompatible chain windows | Grant chaining 1,200; remove 1,800; grant chain capability 3,600; remove 4,200 |
| S6 | Alternate OIDC context temporarily accepted | Broaden trust 1,800; restore strict trust 2,400; separate main-context companion |

S1 reference eligibility begins at 1,800 seconds, after all sampling phases have started; earlier control probes remain in the raw baseline evidence. This prospectively declared warm-up avoids interpreting an unstarted sampling phase as failure of a stable control.

Ten-second intended polling, a 30-second mutation-lateness limit and three consecutive confirmations within 300 seconds are declared before execution. Completion of the third request must be within the limit. On failed mechanism confirmation, restore immediately, stop later interventions and continue observing where possible; do not reinterpret a late success as an on-time confirmation. Restoration has its own confirmation record and budget. At 600 seconds, the last three baseline observations must meet the scenario's declared baseline.

S5 cannot enter its later grant until every observed experimental chain session has expired with the specified margin. A controller-authorized verifier confirms the later chain capability separately. The result is scoped to the controlled observed ledger and declared writer, not universal AWS nonreachability.

## Predictor/reference separation

The raw journals retain configuration readbacks, successful issuance metadata, actual canary requests and mutation/request records. The bridge creates a strict observation DTO containing configuration and issuance facts. Unexpected top-level, snapshot or credential fields are rejected; no probe outcome, witness label or reference path enters a predictor.

The reference builder uses direct, payload-verified S3 success and exact credential lineage. It takes one successful witness per predeclared episode. Repeated polls are not additional independent paths or observations for inferential sample size. S3 persistence additionally requires a fresh-issuance denial in the same cycle. The reference identifies a semantic tuple: context, ordered roles, action and exact resource. Controller/verifier paths and wrong-context credentials are excluded.

This is outcome separation, not a claim that the reference and predictors share no facts: both necessarily use the same actual issuance identifiers to establish lineage. The tests' fake cloud uses its own simple authorization rules rather than calling the analyzer, but remains a simulation, not independent AWS validation.

## Methods and information budgets

| Method | Inputs and interpretation |
|---|---|
| B0 | Final observed configuration; atemporal retrospective hypothesis |
| B1 | Periodic configuration samples; no persisted-session starting state |
| B2 | The same samples plus exact issuance ledger visible by each nominal sample; live sessions can remain starting states after issuance trust disappears |
| B3 | Union of the sampled B2 information; discards temporal ordering/expiry; atemporal retrospective hypothesis |
| T | Full-resolution configuration observations plus observed issuance ledger; sequential lineage and session validity |
| T-S | Same inputs and same session semantics as B2; equality is expected |

Intervals are 60, 300, 900 and 1,800 seconds. Ten deterministic offsets per interval are `j * interval / 10`, for j=0…9. A nominal observation uses the latest completed snapshot at or before the nominal time, with maximum staleness 15 seconds. An incomplete/failed latest snapshot is not replaced with an older favorable one. At least four interval spans and no missing scheduled observations are required for a comparison row's coverage gate. Phases share a run and are never treated as independent replications.

The original 3,600-second interval is **not** supported by this two-hour protocol; a four-hour trace with a separately frozen schedule would be needed to retain the same coverage rule. It is an explicit scope reduction.

## Time and session semantics

A child session must have an exact recorded parent that was valid at issuance. Once issued, the child's own expiry controls its lifetime; later expiry of the parent does not erase it. Removing the ability to issue a session does not itself erase an already issued session. Current identity-policy restrictions and modeled explicit denies still constrain use. Session expiry is exclusive: at `t == expires` the credential is no longer a valid starting state.

Configuration reads are bounded observations, not proof of one globally atomic IAM state. Actual authorization remains uncertain between probes. Request start/end brackets are retained; midpoint timestamps are not represented as known effective transition times. A witness crossing a sampling boundary is conservatively UNKNOWN. Full-resolution T is still observation-constrained, not continuous omniscience.

The supported IAM subset is deliberately small: the exact STS and S3 actions used here, same-account account-root chain trust restricted with `ArnEquals`, the declared identity and optional session policies, and modeled equality/like conditions. Unsupported operators/actions, unexpected managed policies/boundaries or unsupported scope become UNKNOWN. This is not a replacement for AWS's IAM evaluator. The installation review must cover unmodeled organization and account controls and exclude external writers/resource policies.

## Primary scoring and S7

For B1/B2/T/T-S, primary recovery is evaluated at each witness request time, using the latest eligible configuration sample. B2/T-S cannot see sessions issued after their nominal sample. Session expiry is evaluated at witness time. A path seen earlier in the run does not count as B1 recovering a later persistence instance. Historical structural recovery is retained separately as `historical_structure_recovery_lower`.

B0/B3 are explicitly atemporal candidate hypotheses evaluated against the witnessed semantic structures. Their scores are not online detection rates. A positive candidate absent from the reference is generally **unadjudicated**, not automatically a false positive. Only the scoped S5 certificate permits the corresponding union-candidate adjudication. Empty reference denominators remain undefined, not perfect recall.

Per-run outputs include reference instances, predictions and matches, lower/upper recall bounds for UNKNOWN states, timing brackets, observation coverage, exclusions, S5 adjudication and S7 files. `sampling_null.csv` is a predeclared hypothetical window grid: under a continuous uniform sampling phase a window of length L has hit probability `min(1,L/S)`. Its finite ten-phase hit fraction is calculated separately; the two need not agree.

`behavioral_null_sensitivity.json` is limited to S2/S6 and requires a sampled denied → allowed → denied episode with no observed internal reversal or UNKNOWN. Its onset/offset and hit bounds are conditional on a single monotone episode between probes. They are neither confidence intervals nor exact effective IAM windows. Behavioral access and configuration readback are distinct quantities; agreement with the simple sampling null does not demonstrate a novel temporal algorithm.

## Cohort and inference

The proposed evaluation has five S1 and ten each S2–S6 runs, randomized by the frozen seed. It is not automatically authorized. A complete live pilot of every retained scenario, including both S6 contexts, is required first. Scientific review must explain why more runs would answer the amended question despite equal-input B2/T-S equality and observation-frequency effects.

Keep pilot, evaluation, synthetic and Phase-1 cohorts separate. Preserve every failed attempt and reason. No outcome-driven replacement is permitted. Evaluation slots are claimed once in S3; new replacement policy requires a prospective amendment.

Within each scenario and interval, average the ten phases within a qualifying run, then compute paired run-level differences versus B1. At least eight qualifying independent core runs are required for the implemented 10,000-resample percentile bootstrap interval. It is descriptive, not a multiplicity-adjusted superiority test; the 0.10 practical margin is a proposed threshold, not proof of statistical significance. S1 remains descriptive and S5 uses separate scoped candidate adjudication. All attempted-run outcomes, unknowns, absent witnesses and exclusions must accompany conditional estimates.

## Boundaries on the resulting paper

Do not claim that this completes the unamended original study, that T beats B2 algorithmically, that S5 proves all possible AWS paths impossible, that missing CloudTrail events are denials, or that bootstrap bounds establish universal significance. A defensible paper may instead characterize sampling, session persistence, lineage correctness and failure modes within the declared experimental scope. Choose the manuscript route after live pilot review.

## Platform references

AWS documents the one-hour maximum for chained role sessions in [AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html). The runner requests durations within that limit and records returned expiry rather than assuming it.

GitHub documents environment subjects, environment protection and the newer immutable repository-ID subject format in [Configuring OIDC in AWS](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws). The supplied preflight observes the actual format before configuring trust. Reading configuration JSON from standard input follows the [GitHub CLI variable-set manual](https://cli.github.com/manual/gh_variable_set).
