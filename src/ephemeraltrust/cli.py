import argparse, json, os, signal, sys, subprocess
from pathlib import Path
from .common import GuardError, InvalidEvidence, read_json, write_json, digest
from .operations import (
    verify_source,
    freeze,
    validate_protocol,
    validate_live,
    pilot_gate,
    make_cohort,
    collect_cloudtrail,
    emergency_cleanup,
)

ROOT = Path(__file__).resolve().parents[1]


def configure_review(gate, review, protocol, source, out):
    g = read_json(gate)
    r = read_json(review)
    if (
        g["status"] != "INSTRUMENTS_PASS_RESEARCH_REVIEW_REQUIRED"
        or g["source_digest"] != source
        or g["protocol_digest"] != digest(protocol)
    ):
        raise GuardError("Current, passing live instrument gate is required")
    for key in (
        "scientific_scope_accepted",
        "same_input_equality_reviewed",
        "sampling_null_reviewed",
        "s5_scope_reviewed",
        "unknowns_and_exclusions_reviewed",
        "zero_cost_feasibility_confirmed",
        "full_cohort_execution_authorized",
    ):
        if r.get(key) is not True:
            raise GuardError("Evaluation review incomplete: " + key)
    if not r.get("researcher_name") or len(r.get("rationale", "")) < 40:
        raise GuardError("Named researcher and written rationale required")
    plan = make_cohort(protocol, source, out)
    a = {
        "status": "EVALUATION_AUTHORIZED_BY_RESEARCHER",
        "source_digest": source,
        "protocol_digest": digest(protocol),
        "pilot_gate": g,
        "review": r,
        "plan": plan,
    }
    a["approval_id"] = digest(a)
    write_json(out, a)
    return a


def main(argv=None):
    p = argparse.ArgumentParser(
        description="EphemeralTrust Phase 2 — offline first; explicit live pilot gate."
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("self-test")
    sub.add_parser("freeze")
    sub.add_parser("verify-source")
    a = sub.add_parser("demo")
    a.add_argument("--out", required=True)
    a = sub.add_parser("analyze")
    a.add_argument("--run", required=True)
    a.add_argument("--out")
    a = sub.add_parser("pilot-gate")
    a.add_argument("--root", required=True)
    a.add_argument("--out", required=True)
    a = sub.add_parser("cohort-plan")
    a.add_argument("--out", required=True)
    a = sub.add_parser("approve-cohort")
    a.add_argument("--gate", required=True)
    a.add_argument("--review", required=True)
    a.add_argument("--out", required=True)
    a = sub.add_parser("cohort-summary")
    a.add_argument("--root", required=True)
    a.add_argument("--out", required=True)
    a = sub.add_parser("workflow-config")
    a.add_argument("--out", default="local/live.json")
    for command in ("run", "control", "collect", "cleanup"):
        a = sub.add_parser(command)
        a.add_argument("--config", default="local/live.json")
        a.add_argument("--allow-live", action="store_true")
        if command in ("run", "control", "cleanup"):
            a.add_argument("--run-id", required=True)
        if command in ("run", "control"):
            a.add_argument("--out", required=True)
        if command == "run":
            a.add_argument(
                "--scenario",
                required=True,
                choices=["s1", "s2", "s3", "s4", "s5", "s6"],
            )
            a.add_argument("--cohort", choices=["pilot", "evaluation"], default="pilot")
            a.add_argument("--approval")
            a.add_argument("--slot", type=int)
        if command == "collect":
            a.add_argument("--run", required=True)
        if command == "cleanup":
            a.add_argument("--out", required=True)
    args = p.parse_args(argv)
    protocol = read_json(ROOT / "configs/protocol.json")
    validate_protocol(protocol)
    try:
        if args.cmd == "self-test":
            result = subprocess.run(
                [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                cwd=ROOT,
            )
            raise SystemExit(result.returncode)
        if args.cmd == "freeze":
            result = subprocess.run(
                [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"],
                cwd=ROOT,
            )
            if result.returncode:
                raise GuardError("Tests failed; freeze refused")
            print(json.dumps(freeze(ROOT, protocol), indent=2))
            return
        if args.cmd == "verify-source":
            print("PASS " + verify_source(ROOT, protocol))
            return
        if args.cmd == "demo":
            from .synthetic import demo

            ss = demo(args.out, protocol)
            print(
                json.dumps(
                    {
                        "synthetic": True,
                        "scenarios": [
                            {
                                "scenario": s["scenario"],
                                "status": s["instrument_status"],
                                "witnesses": s["reference_instances"],
                            }
                            for s in ss
                        ],
                    },
                    indent=2,
                )
            )
            return
        if args.cmd == "analyze":
            from .analysis import analyze

            print(
                json.dumps(
                    analyze(args.run, args.out or args.run + "-analysis", protocol),
                    indent=2,
                )
            )
            return
        if args.cmd == "cohort-summary":
            from .analysis import cohort_summary

            ds = [
                p.parent
                for p in Path(args.root).rglob("summary.json")
                if read_json(p).get("schema") == "ep2-analysis-1"
            ]
            print(json.dumps(cohort_summary(ds, args.out, protocol), indent=2))
            return
        if args.cmd == "workflow-config":
            raw = os.environ.get("EP2_LIVE_CONFIG_JSON", "")
            if not raw:
                raise GuardError("Repository variable EP2_LIVE_CONFIG_JSON is empty")
            cfg = json.loads(raw)
            write_json(args.out, cfg)
            approval = os.environ.get("EP2_EVALUATION_APPROVAL_JSON", "")
            if approval:
                write_json(
                    Path(args.out).parent / "evaluation_approval.json",
                    json.loads(approval),
                )
            print("Wrote local runtime configuration; no credentials included.")
            return
        source = verify_source(ROOT, protocol)
        if args.cmd == "pilot-gate":
            ds = [p.parent for p in Path(args.root).rglob("run.json")]
            g = pilot_gate(
                ds,
                source,
                protocol,
                args.out,
                [p.parent for p in Path(args.root).rglob("control_summary.json")],
            )
            print(json.dumps(g, indent=2))
            return
        if args.cmd == "cohort-plan":
            print(json.dumps(make_cohort(protocol, source, args.out), indent=2))
            return
        if args.cmd == "approve-cohort":
            print(
                json.dumps(
                    configure_review(
                        args.gate, args.review, protocol, source, args.out
                    ),
                    indent=2,
                )
            )
            return
        cfg = read_json(args.config)
        validate_live(cfg, protocol, args.allow_live)
        from .transport import AWS

        context = (
            "alternate" if (args.cmd == "run" and args.scenario == "s6") else "main"
        )
        if args.cmd == "collect":
            context = (
                "alternate"
                if read_json(Path(args.run) / "run.json")["scenario"] == "s6"
                else "main"
            )
        aws = AWS(cfg, context)
        if args.cmd == "collect":
            print(
                json.dumps(
                    collect_cloudtrail(
                        aws, args.run, protocol["cloudtrail_lag_seconds"]
                    ),
                    indent=2,
                )
            )
            return
        if args.cmd == "cleanup":
            write_json(args.out, emergency_cleanup(aws, cfg, args.run_id))
            print("Cleanup evidence written to " + args.out)
            return
        if args.cmd == "control":
            from .control import run_control

            print(run_control(aws, cfg, args.run_id, args.out))
            return
        if args.cmd == "run":
            if (
                not args.run_id
                or len(args.run_id) > 120
                or not all(c.isalnum() or c in "-_" for c in args.run_id)
            ):
                raise GuardError(
                    "Run ID must be <=120 alphanumeric/hyphen/underscore characters"
                )
            if args.cohort == "evaluation":
                if not args.approval or not args.slot:
                    raise GuardError(
                        "Evaluation requires reviewed approval and a planned slot"
                    )
                a = read_json(args.approval)
                if (
                    a["status"] != "EVALUATION_AUTHORIZED_BY_RESEARCHER"
                    or a["source_digest"] != source
                    or a["protocol_digest"] != digest(protocol)
                ):
                    raise GuardError("Evaluation approval differs from this freeze")
                slots = {x["slot"]: x for x in a["plan"]["slots"]}
                if (
                    args.slot not in slots
                    or slots[args.slot]["scenario"] != args.scenario
                ):
                    raise GuardError("Scenario differs from planned slot")
                # A persistent conditional claim prevents accidental duplicate evaluation slots.
                key = (
                    "ep2-run-cohort-"
                    + a["approval_id"][:20]
                    + "/slot-"
                    + str(args.slot)
                    + ".json"
                )
                aws.call(
                    "s3",
                    "put_object",
                    {
                        "Bucket": cfg["bucket"],
                        "Key": key,
                        "Body": json.dumps(
                            {
                                "run_id": args.run_id,
                                "slot": args.slot,
                                "approval_id": a["approval_id"],
                            }
                        ).encode(),
                        "IfNoneMatch": "*",
                        "ServerSideEncryption": "AES256",
                    },
                )
            from .runner import Runner, StopRun

            runner = Runner(
                aws,
                cfg,
                protocol,
                args.scenario,
                args.run_id,
                args.out,
                source,
                args.cohort,
            )

            def stop(signum, frame):
                signal.signal(signum, signal.SIG_IGN)
                raise StopRun("Signal received; preserving evidence and restoring")

            for sig in (signal.SIGINT, signal.SIGTERM):
                signal.signal(sig, stop)
            result = runner.run()
            print(json.dumps(result, indent=2))
            if (
                result["status"] != "TRACE_COMPLETE"
                or result["restoration"] != "CONFIRMED"
                or not result["cleanup_confirmed"]
            ):
                raise SystemExit(2)
    except (GuardError, InvalidEvidence, FileNotFoundError, ValueError, KeyError) as e:
        print("STOP: " + str(e), file=sys.stderr)
        raise SystemExit(2)
