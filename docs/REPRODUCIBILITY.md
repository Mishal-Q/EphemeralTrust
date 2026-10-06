# Reproducibility

This repository is a curated public artifact for the EphemeralTrust study. It preserves the Phase 2 implementation, experiment definition, analysis code, selected derived results and provenance needed to inspect how the work was carried out.

It is not a complete raw-data deposit.

## Included

The public artifact contains:

- the Phase 2 Python implementation and tests
- the frozen experiment protocol and example configuration
- Terraform infrastructure
- offline reconstruction code
- selected derived results
- methodology and validation records
- source-freeze and archive provenance

The implementation used for the final Phase 2 experiments was frozen at:

`0872d08273f5239e45cb9fb92da1aa6a70214619`

Source SHA-256:

`c2f58a037a24fc2ca403c867477d5f545de96375b7777f8d93813b52e7c39819`

Individual source-file hashes are recorded in `SOURCE_FREEZE.json`.

## Manuscript

The public manuscript is `../paper/EphemeralTrust_Manuscript.pdf`.

SHA-256:

`354b719698308bd941c3c3682122ff5ac5a3efa52f82887aca12082db8143b6f`

## Not included

The complete private research archive is not published in this repository. Raw AWS and CloudTrail traces, credential material, Terraform state, local environments, historical working copies and private archive packages are excluded.

The selected files under `results/` are derived research outputs, not the complete underlying evidence corpus.

## Checking the implementation

The main starting points are:

- `../src/configs/protocol.json`
- `../src/ephemeraltrust/`
- `../src/tests/`
- `../analysis/reconstruct.py`
- `../results/`

The public repository layout has been checked with the included offline test suite.

The documents `RUNBOOK.md` and `VALIDATION.md` are retained from the Phase 2 preparation/freeze process. Statements in those files such as pilot-candidate status and pre-live validation counts describe the state of the artifact at that stage of the research rather than the later completed study.

## Interpretation

The study uses deliberately constructed controlled scenarios. Sampling phases from the same underlying run are not independent experimental replications.

The T observation condition has denser observations available. T-S uses the same candidate logic as B2, so differences between T and periodic conditions should not be interpreted as evidence that T is a superior reconstruction algorithm.

The results are scoped to the declared experimental environment and supported IAM subset. They are not population-level measurements of AWS IAM behavior.

## Live AWS code

Live AWS execution is not required to inspect the implementation or the published derived results.

The repository still contains code used for the cloud experiments. Running it can create, modify or remove AWS resources and may incur charges. The historical runbook documents the original Phase 2 execution procedure, but its paths and preparation-state instructions should not be treated as a turn-key guide for this curated public repository.
