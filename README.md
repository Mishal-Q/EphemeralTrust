# EphemeralTrust

This repository contains the code and some of the results from my research project, **EphemeralTrust: Session State and Observation Design in Controlled AWS Access Traces**.

The project started from a pretty simple question. When we look at cloud permissions, are we actually seeing what a user or session could do at that point in time, or are we just looking at the IAM configuration and assuming that tells the whole story?

That became more interesting once temporary AWS credentials were involved.

For example, a role might no longer be able to issue a new session, but a session that was issued earlier can still exist and continue doing things. If we only take occasional snapshots of the IAM configuration, some of that behavior can be missed.

So I built EphemeralTrust to experiment with this in a controlled AWS environment.

## What I actually did

The setup uses GitHub Actions OIDC, AWS STS, IAM roles and policies, temporary credentials, role chaining, S3 operations and CloudTrail.

I created different scenarios where permissions or trust relationships changed while the experiment was running. The system recorded configuration snapshots, issued sessions, access attempts and other events over time.

I then compared different ways of reconstructing what was happening from those observations.

The repository includes the Python implementation, Terraform infrastructure, experiment configuration, tests, analysis code and selected results.

## What I found interesting

The clearest example is S3.

An AWS session had already been issued. Later, fresh session issuance was denied, but the existing session could still successfully perform the tested operation.

There were 168 paired observations where the existing session succeeded while fresh issuance was denied.

That is basically the problem I wanted to investigate. A configuration snapshot can tell you what can be issued *now*, but that does not necessarily describe every credential that is still alive from an earlier state.

Sampling frequency mattered too.

For one of the S3 comparisons at a 60-second sampling interval, the configuration-oriented B1 condition recovered the selected witness semantic tuple in 0/10 phase projections. The session-aware B2 condition recovered it in 10/10.

There is also a denser observation condition called T. It sometimes gets better first-witness results, but this needs an important qualification: T-S uses the same candidate logic as B2. It gets more information. So I do **not** treat that as evidence that T is a better algorithm.

S5 looked at a different problem. Combining observations without respecting when credentials could actually have existed can produce a path that looks possible when the observations are viewed together, even though that path does not fit the declared credential schedule.

## Repository layout

`src/` contains the Phase 2 implementation and tests.

`experiments/` contains the protocol, example configuration and Terraform infrastructure.

`analysis/` contains the offline reconstruction code.

`results/` contains selected derived results.

`docs/` contains the methodology, validation notes, runbook and provenance information.

`paper/` is reserved for the final manuscript artifact.

## About the data

I am not uploading my entire research directory or every raw AWS trace to GitHub.

The original experiments produced things like CloudTrail records, session records, probes and other runtime data. The public repository instead contains selected derived results that are useful for understanding the experiments without publishing the complete raw environment.

It also does not contain AWS credentials, Terraform state, local environments or my old working copies.

## Reproducing the work

If you are trying to understand the project rather than immediately run it, I would start with:

1. `docs/METHODOLOGY.md`
2. `src/configs/protocol.json`
3. `src/ephemeraltrust/`
4. `analysis/reconstruct.py`
5. `results/`

`docs/VALIDATION.md` and `docs/RUNBOOK.md` contain more detail about validation and execution.

The source used for the final Phase 2 experiments was frozen at Git commit:

`0872d08273f5239e45cb9fb92da1aa6a70214619`

with source digest:

`c2f58a037a24fc2ca403c867477d5f545de96375b7777f8d93813b52e7c39819`

The per-file hashes are in `docs/SOURCE_FREEZE.json`, and the archive identity is preserved in `docs/ARCHIVE_IDENTITY.txt`.

One thing to keep in mind is that this GitHub repository is a cleaned public version of the research artifact. It is not supposed to be a byte-for-byte copy of the full private archive.

## Running it yourself

The offline code and tests are the safest place to start.

The project also contains code that can interact with AWS and Terraform. I would not recommend just running the live experiment commands without reading the configuration first. They were written for a controlled research environment and can create, modify or remove AWS resources.

## Scope

This was a controlled study with a small set of deliberately constructed scenarios.

So the results should not be read as something like "AWS IAM always behaves this way" or as population-level measurements of AWS. The point was to create concrete cases where session lifetime and observation timing matter, then see how different reconstruction conditions handle those cases.

## Author

Mishal Qadir
