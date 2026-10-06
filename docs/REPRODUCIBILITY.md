# Reproducibility Notes

This repository is the cleaned public version of my EphemeralTrust Phase 2 research artifact. It contains the main code and selected results needed to understand how the experiments and analysis were carried out, but it is not a complete copy of my original research archive.

## What is included

The repository includes the Phase 2 Python implementation and tests, the experiment protocol, example configuration, Terraform infrastructure, methodology and validation documents, offline reconstruction code, and selected derived results.

The frozen source used for the final experiments is identified by:

Git commit:

`0872d08273f5239e45cb9fb92da1aa6a70214619`

Source digest:

`c2f58a037a24fc2ca403c867477d5f545de96375b7777f8d93813b52e7c39819`

Individual source-file hashes are recorded in `SOURCE_FREEZE.json`.

## What is not included

I did not put the complete raw research archive on GitHub.

The excluded material includes full raw AWS and CloudTrail traces, credential material, Terraform state, local Python environments, historical working copies and private archive packages.

Because of this, the public repository should not be treated as a complete raw-data deposit.

## Reproducing the analysis

The existing code and derived results can be inspected without running new AWS experiments.

The main places to start are:

- `../analysis/reconstruct.py`
- `../results/`
- `METHODOLOGY.md`
- `VALIDATION.md`
- `../src/configs/protocol.json`

The original research audit also used independent reconstruction and consistency checks against the frozen evidence.

## About the comparisons

The experiments use controlled scenarios rather than independent population samples. Different sampling phases derived from the same underlying run are therefore not independent experiments.

The T observation condition also has access to denser observations. T-S uses the same candidate logic as B2, so a difference between T and the periodic conditions should not be interpreted as T being a better reconstruction algorithm.

## Live AWS execution

The source contains functionality for running experiments against AWS.

Running the live workflow is not necessary to inspect the existing results. Anyone trying to reproduce the cloud experiments should first read the runbook, Terraform configuration, IAM assumptions and cleanup procedure.

Live execution can create, modify or remove AWS resources and may incur AWS charges.
