"""Explicit simulation adapter for integration checks; never live evidence."""

from pathlib import Path
from .runner import Runner, SCENARIOS
from .analysis import analyze
from .common import write_json, seal_run


def demo(out, protocol, source_digest="SYNTHETIC"):
    from tests.fake_aws import Clock, FakeAWS

    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    cfg = {
        "account_id": "123456789012",
        "repository": "example/research",
        "region": "us-east-1",
        "bucket": "ep2-simulation",
        "provider_arn": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
        "controller_role_arn": "arn:aws:iam::123456789012:role/ep2-controller",
        "subjects": {
            "main": "repo:example/research:environment:ep2-main",
            "alternate": "repo:example/research:environment:ep2-alternate",
        },
    }
    summaries = []
    for scenario in SCENARIOS:
        clock = Clock()
        aws = FakeAWS(cfg, clock)
        r = Runner(
            aws,
            cfg,
            protocol,
            scenario,
            "synthetic-" + scenario,
            out / scenario,
            source_digest,
            "synthetic",
            clock.now,
            clock.sleep,
            clock.wall,
        )
        meta = r.run()
        meta["synthetic"] = True
        write_json(out / scenario / "run.json", meta)
        seal_run(out / scenario)
        summaries.append(
            analyze(out / scenario, out / (scenario + "-analysis"), protocol)
        )
    write_json(
        out / "DEMO_SUMMARY.json",
        {
            "synthetic": True,
            "summaries": summaries,
            "warning": "No AWS measurements. This is not a pilot or evidence of the hypothesis.",
        },
    )
    return summaries
