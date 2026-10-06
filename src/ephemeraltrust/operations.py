"""Freeze, offline gates, audit collection and bounded emergency cleanup."""

import hashlib, json, os, re, time, random
from pathlib import Path
from datetime import datetime, timezone
from .common import (
    GuardError,
    InvalidEvidence,
    read_json,
    read_lines,
    write_json,
    digest,
    verify_run,
    seal_run,
    epoch,
)

EXCLUDED = {
    ".git",
    ".venv",
    "__pycache__",
    "results",
    "local",
    "validation",
    ".terraform",
}


def source_files(root):
    out = {}
    for p in sorted(Path(root).rglob("*")):
        rel = p.relative_to(root)
        if (
            not p.is_file()
            or any(x in EXCLUDED for x in rel.parts)
            or p.name in {"SOURCE_FREEZE.json"}
            or p.suffix == ".pyc"
        ):
            continue
        if p.name.endswith((".tfstate", ".tfplan")) or ".tfstate." in p.name:
            continue
        out[str(rel)] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def freeze(root, protocol):
    m = {
        "format": "ep2-source-freeze-1",
        "files": source_files(root),
        "protocol_digest": digest(protocol),
    }
    m["source_digest"] = digest(m["files"])
    write_json(Path(root) / "SOURCE_FREEZE.json", m)
    return m


def verify_source(root, protocol):
    m = read_json(Path(root) / "SOURCE_FREEZE.json")
    if (
        m["files"] != source_files(root)
        or m["source_digest"] != digest(m["files"])
        or m["protocol_digest"] != digest(protocol)
    ):
        raise GuardError(
            "Source/protocol changed since freeze. Re-test, document amendment and refreeze before a new pilot cohort."
        )
    return m["source_digest"]


def validate_protocol(p):
    if p.get("schema") != "ep2-protocol-1":
        raise GuardError("Unsupported protocol")
    fixed = {
        "duration": 7200,
        "intervals": [60, 300, 900, 1800],
        "phases": 10,
        "tick_seconds": 10,
        "max_snapshot_staleness": 15,
        "confirmation_seconds": 300,
        "confirmation_count": 3,
        "max_schedule_lateness": 30,
    }
    for k, v in fixed.items():
        if p.get(k) != v:
            raise GuardError(
                "This candidate implements the documented fixed protocol; changing "
                + k
                + " requires corresponding code/tests and an amendment"
            )
    if p["duration"] < 4 * max(p["intervals"]):
        raise GuardError("Trace too short")
    for sid, items in p["schedules"].items():
        if [x[0] for x in items] != sorted(x[0] for x in items) or any(
            not 0 <= x[0] < p["duration"] for x in items
        ):
            raise GuardError("Invalid schedule")


def validate_live(cfg, p, allow_live):
    if not allow_live:
        raise GuardError("Explicit --allow-live required")
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise GuardError("Live runner requires the supplied GitHub workflow")
    if cfg.get("zero_cost_reviewed") is not True:
        raise GuardError(
            "Zero-cost account/runner feasibility review has not been acknowledged"
        )
    if cfg.get("dedicated_experiment_scope_confirmed") is not True:
        raise GuardError(
            "Dedicated, supported experiment scope has not been acknowledged"
        )
    if cfg.get("region") != "us-east-1" or not re.fullmatch(
        r"\d{12}", cfg.get("account_id", "")
    ):
        raise GuardError("Expected account and us-east-1 required")
    if not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", cfg.get("repository", "")
    ) or cfg["repository"] != os.environ.get("GITHUB_REPOSITORY"):
        raise GuardError("Repository mismatch")
    owner, repo = cfg["repository"].split("/")
    subjects = cfg.get("subjects", {})
    if set(subjects) != {"main", "alternate"}:
        raise GuardError("Both exact environment subjects are required")
    prefix = None
    for context in ("main", "alternate"):
        suffix = ":environment:ep2-" + context
        value = subjects[context]
        if not isinstance(value, str) or not value.endswith(suffix):
            raise GuardError("Exact environment subject required")
        current = value[: -len(suffix)]
        legacy = "repo:" + cfg["repository"]
        immutable = (
            r"repo:" + re.escape(owner) + r"@[0-9]+/" + re.escape(repo) + r"@[0-9]+"
        )
        if current != legacy and not re.fullmatch(immutable, current):
            raise GuardError(
                "OIDC subject must match this repository's legacy or immutable-ID format"
            )
        if prefix is not None and prefix != current:
            raise GuardError(
                "Environment subjects refer to different repository identities"
            )
        prefix = current
    if (
        cfg.get("provider_arn")
        != "arn:aws:iam::"
        + cfg["account_id"]
        + ":oidc-provider/token.actions.githubusercontent.com"
    ):
        raise GuardError("OIDC provider/account mismatch")
    if not cfg.get("controller_role_arn", "").startswith(
        "arn:aws:iam::" + cfg["account_id"] + ":role/ep2-controller-"
    ):
        raise GuardError("Controller scope mismatch")
    if not cfg.get("bucket", "").startswith("ep2-canary-"):
        raise GuardError("Canary bucket scope mismatch")
    if (
        cfg.get("max_live_runs_per_dispatch") != 1
        or cfg.get("max_trace_seconds", 0) < p["duration"]
    ):
        raise GuardError("Run budget/duration guard failed")
    validate_protocol(p)


def pilot_gate(run_dirs, source, protocol, out, control_dirs=()):
    from .analysis import bridge, reference, s5_certificate, projected
    from .model import snapshot_edges

    runs = []
    seen = set()
    for path in run_dirs:
        m, o, _ = bridge(path)
        if m["cohort"] != "pilot" or m.get("synthetic"):
            raise GuardError("Only real Phase-2 pilots qualify")
        if m["source_digest"] != source or m["protocol_digest"] != digest(protocol):
            raise GuardError("Pilot source/protocol differs from current freeze")
        if o.scenario in seen:
            raise GuardError(
                "Multiple same-scenario pilots: review the attempt history; do not select a favorable one silently"
            )
        seen.add(o.scenario)
        probes = read_lines(Path(path) / "probes.jsonl")
        events = read_lines(Path(path) / "events.jsonl")
        ref = reference(m, o, probes)
        coverage = all(
            all(
                s is not None and snapshot_edges(o, s) is not None
                for _, s in projected(o, S, j * S / 10)
            )
            for S in protocol["intervals"]
            for j in range(10)
        )
        checks = {
            "complete_trace": m["status"] == "TRACE_COMPLETE"
            and m["duration"] >= protocol["duration"],
            "restoration": m.get("restoration") == "CONFIRMED",
            "cleanup": m.get("cleanup_confirmed") is True,
            "coverage": coverage,
            "credential_ledger_complete": m.get("credential_ledger_complete") is True,
            "clock": m.get("clock_check") is not None,
            "analysis_present": (
                Path(path).parent / (Path(path).name + "-analysis") / "summary.json"
            ).exists(),
        }
        summary_path = (
            Path(path).parent / (Path(path).name + "-analysis") / "summary.json"
        )
        if summary_path.exists():
            analyzed = read_json(summary_path)
            checks["analysis_matches_evidence"] = (
                analyzed.get("run_id") == o.run_id
                and analyzed.get("source_digest") == source
                and analyzed.get("input_seal")
                == digest(read_json(Path(path) / "SHA256.json"))
            )
        else:
            checks["analysis_matches_evidence"] = False
        control_result = None
        if o.scenario == "s6":
            controls = [
                Path(d)
                for d in control_dirs
                if read_json(Path(d) / "control_summary.json").get("run_id") == o.run_id
            ]
            checks["main_control"] = (
                len(controls) == 1
                and validate_control(controls[0], m)["instrument_complete"]
                if controls
                else False
            )
            if len(controls) == 1:
                control_result = validate_control(controls[0], m)
        # Null/absent effects are retained. Their ability to answer the comparison needs review.
        runs.append(
            {
                "run_id": o.run_id,
                "scenario": o.scenario,
                "checks": checks,
                "reference_instances": len(ref),
                "main_control": control_result,
                "s5_certificate": s5_certificate(m, o, probes, events),
                "input_seal": digest(read_json(Path(path) / "SHA256.json")),
            }
        )
    complete = seen == {"s1", "s2", "s3", "s4", "s5", "s6"} and all(
        all(x["checks"].values()) for x in runs
    )
    g = {
        "status": (
            "INSTRUMENTS_PASS_RESEARCH_REVIEW_REQUIRED" if complete else "BLOCKED"
        ),
        "source_digest": source,
        "protocol_digest": digest(protocol),
        "runs": runs,
        "automatic_scaling_authorized": False,
        "reason": "An instrument pass is not evidence of a useful comparative effect. Review null explanation, same-input equality, endpoint eligibility and zero-cost feasibility before an evaluation freeze.",
    }
    write_json(out, g)
    return g


def make_cohort(protocol, source, out):
    slots = [{"scenario": "s1", "replicate": i} for i in range(1, 6)]
    slots += [
        {"scenario": "s" + str(s), "replicate": i}
        for s in range(2, 7)
        for i in range(1, 11)
    ]
    random.Random(protocol["seed"]).shuffle(slots)
    for i, x in enumerate(slots, 1):
        x["slot"] = i
    result = {
        "source_digest": source,
        "protocol_digest": digest(protocol),
        "status": "PROPOSED_NOT_AUTHORIZED",
        "trace_hours": len(slots) * protocol["duration"] / 3600,
        "slots": slots,
        "replacement_policy": "No outcome-driven replacement; retain every attempt.",
    }
    write_json(out, result)
    return result


def collect_cloudtrail(aws, run_dir, lag=600, sleep=time.sleep, wall=time.time):
    p = Path(run_dir)
    verify_run(p)
    m = read_json(p / "run.json")
    end = epoch(m["finished_utc"])
    start = epoch(m["start_utc"])
    while wall() < end + lag:
        sleep(min(30, end + lag - wall()))
    request_ids = {
        r.get("request_id")
        for r in read_lines(p / "events.jsonl")
        if r.get("event") == "request"
    } - {None}
    token = None
    events = {}
    pages = 0
    complete = False
    error = None
    try:
        for _ in range(1000):
            args = {
                "StartTime": datetime.fromtimestamp(start, timezone.utc),
                "EndTime": datetime.fromtimestamp(end, timezone.utc),
                "MaxResults": 50,
            }
            if token:
                args["NextToken"] = token
            page = aws.call("cloudtrail", "lookup_events", args)
            pages += 1
            for wrapper in page.get("Events", []):
                try:
                    e = json.loads(wrapper["CloudTrailEvent"])
                except (KeyError, ValueError):
                    continue
                if e.get("requestID") not in request_ids:
                    continue
                # Whitelist, never store raw request/response credentials or identity tokens.
                events[e["eventID"]] = {
                    k: e.get(k)
                    for k in (
                        "eventID",
                        "eventTime",
                        "eventName",
                        "eventSource",
                        "requestID",
                        "errorCode",
                        "awsRegion",
                    )
                }
            token = page.get("NextToken")
            if not token:
                complete = True
                break
            sleep(0.6)
    except Exception as e:
        error = (
            getattr(e, "response", {}).get("Error", {}).get("Code", type(e).__name__)
        )
    result = {
        "query_start": start,
        "query_end": end,
        "collected_at": wall(),
        "pages": pages,
        "pagination_complete": complete,
        "error_code": error,
        "events": list(events.values()),
        "correlation": "exact requestID only",
        "absence_means_denial": False,
        "delivery_completeness": "NOT_GUARANTEED",
        "s3_data_events_enabled": False,
    }
    write_json(p / "cloudtrail.json", result)
    seal_run(p)
    return result


def emergency_cleanup(aws, cfg, run_id):
    prefix = "ep2-run-" + hashlib.sha256(run_id.encode()).hexdigest()[:20]
    roles = [prefix + "-chain", prefix + "-entry"]
    results = {}
    for role in roles:
        try:
            r = aws.call("iam", "get_role", {"RoleName": role})
            tags = r["Role"].get("Tags", [])
            if {"Key": "EphemeralTrustRun", "Value": run_id} not in tags:
                raise GuardError("Role ownership tag mismatch")
            names = aws.call("iam", "list_role_policies", {"RoleName": role})
            if names.get("IsTruncated") or set(names["PolicyNames"]) - {
                "ep2-experiment"
            }:
                raise GuardError("Unexpected policies; manual review needed")
            for n in names["PolicyNames"]:
                aws.call(
                    "iam", "delete_role_policy", {"RoleName": role, "PolicyName": n}
                )
            aws.call("iam", "delete_role", {"RoleName": role})
            try:
                aws.call("iam", "get_role", {"RoleName": role})
                results[role] = "STILL_PRESENT"
            except Exception as e:
                results[role] = (
                    "ABSENT"
                    if getattr(e, "response", {}).get("Error", {}).get("Code")
                    == "NoSuchEntity"
                    else "UNKNOWN"
                )
        except GuardError:
            raise
        except Exception as e:
            results[role] = (
                "ABSENT"
                if getattr(e, "response", {}).get("Error", {}).get("Code")
                == "NoSuchEntity"
                else "UNKNOWN"
            )
    for name in ("canary.txt", "ready.json"):
        try:
            aws.call(
                "s3",
                "delete_object",
                {"Bucket": cfg["bucket"], "Key": prefix + "/" + name},
            )
            results[name] = "DELETE_ACKNOWLEDGED"
        except Exception:
            results[name] = "UNKNOWN"
    return {
        "run_id": run_id,
        "results": results,
        "scope": "Exact derived roles/keys only; no wildcard resource enumeration/deletion.",
    }


def validate_control(path, run):
    p = Path(path)
    checks = read_json(p / "SHA256.json")
    for n, h in checks.items():
        if Path(n).name != n or hashlib.sha256((p / n).read_bytes()).hexdigest() != h:
            raise InvalidEvidence("Control integrity failed")
    if not {"main_control.jsonl", "control_summary.json"} <= set(checks):
        raise InvalidEvidence("Unsealed control stream")
    rows = read_lines(p / "main_control.jsonl")
    start = epoch(run["trace_start_utc"])
    end = epoch(run["trace_end_utc"])
    points = [
        (epoch(x["request_end"]), x["state"])
        for x in rows
        if x.get("kind") == "canary"
        and x.get("request_end")
        and start <= epoch(x["request_end"]) <= end
    ]
    times = sorted(t for t, _ in points)
    coverage = (
        bool(times)
        and times[0] - start <= 30
        and end - times[-1] <= 30
        and all(b - a <= 30 for a, b in zip(times, times[1:]))
    )
    return {
        "samples_in_trace": len(points),
        "allowed": sum(s == "ALLOW" for _, s in points),
        "denied": sum(s == "DENY" for _, s in points),
        "unknown": sum(s == "UNKNOWN" for _, s in points),
        "sample_coverage": coverage,
        "instrument_complete": coverage and all(s != "UNKNOWN" for _, s in points),
        "all_sampled_main_allowed": bool(points)
        and all(s == "ALLOW" for _, s in points),
        "continuous_availability_proven": False,
    }
