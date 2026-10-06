"""GitHub-only subject discovery. Never prints tokens or contacts AWS."""

import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ephemeraltrust.transport import github_token
from ephemeraltrust.common import write_json


def main():
    context = os.environ["EP2_CONTEXT"]
    if context not in ("main", "alternate"):
        raise ValueError("Unexpected environment")
    repository = os.environ["GITHUB_REPOSITORY"]
    _, claims = github_token(None, repository)
    owner, repo = repository.split("/")
    suffix = ":environment:ep2-" + context
    subject = claims["sub"]
    if not subject.endswith(suffix):
        raise ValueError("Custom OIDC subject is outside the supported format")
    component = subject[len("repo:") : -len(suffix)]
    if component != repository and not re.fullmatch(
        re.escape(owner) + r"@[0-9]+/" + re.escape(repo) + r"@[0-9]+", component
    ):
        raise ValueError("Custom OIDC subject is outside the supported format")
    result = {
        "repository": repository,
        "context": context,
        "subject": subject,
        "oidc_subject_repository": component,
        "audience": claims["aud"],
        "sha": claims["sha"],
        "aws_requests_executed": 0,
    }
    write_json(Path("results") / ("oidc-" + context + ".json"), result)
    print("OIDC repository component: " + component)
    print("OIDC subject: " + subject)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(
            "OIDC preflight failed ("
            + type(exc).__name__
            + "). Check environment and repository settings; no token logged.",
            file=sys.stderr,
        )
        raise SystemExit(2)
