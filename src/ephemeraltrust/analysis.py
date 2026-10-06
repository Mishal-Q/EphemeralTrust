"""Offline evidence bridge, witness-based reference and S7 comparisons."""

import csv, json, math, statistics, random
from pathlib import Path
from .common import (
    InvalidEvidence,
    read_json,
    read_lines,
    write_json,
    verify_run,
    digest,
)
from .model import (
    from_observation_dict,
    lineage,
    semantic,
    snapshot_edges,
    candidates,
    union_edges,
)
from .iam import ALLOW, DENY, UNKNOWN

METHODS = ("B0", "B1", "B2", "B3", "T", "T-S")


def bridge(path):
    p = Path(path)
    verify_run(p)
    m = read_json(p / "run.json")
    origin = m["trace_origin"]
    if m["schema"] != "ep2-run-1":
        raise InvalidEvidence("Phase-1 and unknown schemas cannot enter Phase 2")
    d = {
        k: m[k]
        for k in (
            "run_id",
            "scenario",
            "duration",
            "target_context",
            "contexts",
            "entry",
            "chain",
            "provider",
            "account",
            "action",
            "resource",
        )
    }
    d["schema"] = "ep2-observations-1"
    d["snapshots"] = [
        {
            "start": s["start"] - origin,
            "end": s["end"] - origin,
            "config": s["config"],
            "complete": s["complete"],
        }
        for s in read_lines(p / "snapshots.jsonl")
        if s["end"] - origin <= m["duration"] + 0.001
    ]
    d["credentials"] = []
    for c in read_lines(p / "sessions.jsonl"):
        d["credentials"].append(
            {
                k: (
                    c[k] - origin
                    if c[k] is not None
                    and k in {"start", "issued", "expires", "revoked"}
                    else c[k]
                )
                for k in (
                    "sid",
                    "role",
                    "context",
                    "parent",
                    "start",
                    "issued",
                    "expires",
                    "actor",
                    "session_policy",
                    "revoked",
                )
            }
        )
    o = from_observation_dict(d)
    for c in o.credentials:
        if c.actor == "experiment" and lineage(o, c) is None:
            raise InvalidEvidence("Invalid/missing credential ancestry: " + c.sid)
    return m, o, d


def reference(m, o, probes):
    """Independent direct-witness reference; never invokes candidates or T."""
    found = {}
    by = {c.sid: c for c in o.credentials}
    fresh = {}
    for p in probes:
        if p.get("purpose") == "fresh_issuance":
            fresh[p["cycle"]] = p
    for p in sorted(probes, key=lambda x: x["end"]):
        t = p["end"] - m["trace_origin"]
        start = p["start"] - m["trace_origin"]
        if (
            not (0 <= start <= t <= o.duration)
            or p.get("kind") != "canary"
            or p.get("state") != ALLOW
        ):
            continue
        if p.get("actor") != "experiment" or p.get("context") != o.target_context:
            continue
        if (
            p.get("action") != o.action
            or p.get("resource") != o.resource
            or not p.get("payload_verified")
        ):
            continue
        c = by.get(p.get("sid"))
        roles = lineage(o, c) if c else None
        if (
            not roles
            or c.context != p["context"]
            or not (c.issued <= start and t < c.expires)
        ):
            continue
        ep = p.get("episode")
        if ep not in m["episodes"]:
            continue
        bounds = m["episodes"][ep]
        if not (bounds[0] <= start and t < bounds[1]):
            continue
        if o.scenario == "s3":
            f = fresh.get(p.get("cycle"), {})
            if f.get("state") != DENY:
                continue
        if ep not in found:
            found[ep] = {
                "reference_instance_id": digest([o.run_id, ep, p["probe_id"]]),
                "episode": ep,
                "semantic_id": semantic(o.target_context, roles, o.action, o.resource),
                "request_start": start,
                "request_end": t,
                "probe_id": p["probe_id"],
                "credential_id": c.sid,
            }
    return list(found.values())


def projected(o, interval, phase, staleness=15):
    result = []
    idx = -1
    t = phase
    while t <= o.duration + 1e-9:
        while idx + 1 < len(o.snapshots) and o.snapshots[idx + 1].end <= t + 1e-9:
            idx += 1
        s = o.snapshots[idx] if idx >= 0 else None
        # A failed latest snapshot invalidates the slot; never reach backward through it.
        if not s or t - s.end > staleness or not s.complete:
            result.append((t, None))
        else:
            result.append((t, s))
        t += interval
    return result


def merge_predictions(parts):
    out = {}
    unknown = False
    for pred, u in parts:
        unknown |= u
        for k, v in pred.items():
            if out.get(k) != ALLOW:
                out[k] = v
    return out, unknown


def methods(o, interval, phase, static=None):
    samples = projected(o, interval, phase)

    def at(s, t, sessions):
        return candidates(o, snapshot_edges(o, s) if s else None, t, sessions)

    full = [s for s in o.snapshots if 0 <= s.end <= o.duration]
    initial = [s for s in o.snapshots if s.end <= 0]
    if initial:
        full = [initial[-1]] + full
    last = o.snapshots[-1] if o.snapshots else None
    if last and o.duration - last.end > 15:
        last = None
    b0 = at(last, o.duration, False)
    b1 = merge_predictions(at(s, t, False) for t, s in samples)
    b2 = merge_predictions(at(s, t, True) for t, s in samples)
    # T-S is deliberately equivalent to B2 under the observed-issuance contract.
    # Equality is reported, not hidden or engineered away.
    temporal = (
        static["T"]
        if static
        else merge_predictions(at(s, max(0, s.end), True) for s in full)
    )
    if any(b.end - a.end > 15 for a, b in zip(full, full[1:])):
        temporal = (temporal[0], True)
    uedges = union_edges([snapshot_edges(o, s) if s else None for _, s in samples])
    b3 = candidates(o, uedges, o.duration, True, True)
    b3 = (
        b3[0],
        b3[1] or any(s is None or snapshot_edges(o, s) is None for _, s in samples),
    )
    return dict(zip(METHODS, (b0, b1, b2, b3, temporal, b2))), samples


def score(ref, pred, unknown):
    ids = [r["semantic_id"] for r in ref]
    n = len(ids)
    yes = sum(pred.get(k) == ALLOW for k in ids)
    maybe = sum(
        pred.get(k) != ALLOW and (unknown or pred.get(k) == UNKNOWN) for k in ids
    )
    return {
        "instances": n,
        "recovered": yes,
        "unknown": maybe,
        "recall_lower": yes / n if n else None,
        "recall_upper": (yes + maybe) / n if n else None,
        "distinct_reference_structures": len(set(ids)),
        "structure_recovered": len(
            set(ids) & {k for k, v in pred.items() if v == ALLOW}
        ),
        "unadjudicated_candidates": len(set(pred) - set(ids)),
    }


def s5_certificate(m, o, probes, events):
    if o.scenario != "s5":
        return {"status": "NOT_APPLICABLE"}
    # No finite probe set proves universal absence. This certifies only the ledger-
    # closed, declared experiment actor and the scheduled separated-phase model.
    cs = [c for c in o.credentials if c.actor == "experiment" and c.role == o.chain]
    phase2 = [e for e in events if e.get("event") == "s5_phase2_gate"]
    phase1deny = any(
        p.get("kind") == "canary"
        and p.get("sid") in {c.sid for c in cs}
        and p.get("state") == DENY
        and 1200 <= p["end"] - m["trace_origin"] < 1800
        for p in probes
    )
    verifier = any(
        p.get("actor") == "verifier"
        and p.get("state") == ALLOW
        and p.get("payload_verified")
        and 3600 <= p["end"] - m["trace_origin"] < 4200
        for p in probes
    )
    checks = {
        "credential_ledger_complete": m.get("credential_ledger_complete") is True,
        "issued_phase1_session": bool(cs),
        "phase1_capability_denied": phase1deny,
        "recorded_expiry_gate": bool(phase2) and phase2[0].get("passed") is True,
        "all_experiment_chain_expiries_before_phase2": bool(cs)
        and max(c.expires for c in cs) + 30 < 3600,
        "phase2_independent_verifier_success": verifier,
        "complete_trace": m["status"] == "TRACE_COMPLETE",
        "supported_readbacks": bool(o.snapshots)
        and all(s.complete and snapshot_edges(o, s) is not None for s in o.snapshots),
    }
    return {
        "status": (
            "SCOPED_LEDGER_CERTIFIED" if all(checks.values()) else "UNESTABLISHED"
        ),
        "checks": checks,
        "scope": "Only declared experiment actor, complete harness issuance ledger and frozen phase schedule. Not universal AWS nonreachability.",
    }


def temporal_witness_checks(o, ref, samples, with_sessions, full_resolution=False):
    rows = []
    for r in ref:
        eligible = [(t, s) for t, s in samples if t <= r["request_start"]]
        following = [t for t, s in samples if r["request_start"] < t < r["request_end"]]
        if not eligible or following:
            state = UNKNOWN
        else:
            t, s = eligible[-1]
            if full_resolution and r["request_start"] - t > 15:
                s = None
            available = r["request_start"] if full_resolution else t
            pred, u = candidates(
                o,
                snapshot_edges(o, s) if s else None,
                r["request_start"],
                with_sessions,
                available_at=available,
            )
            state = pred.get(r["semantic_id"], UNKNOWN if u else DENY)
        rows.append(
            {
                "reference_instance_id": r["reference_instance_id"],
                "predicted_state_at_witness": state,
                "meaning": "Configuration sample-and-hold; session issuance visibility and expiry evaluated at witness time.",
            }
        )
    return rows


def csv_out(path, rows):
    if not rows:
        return
    with Path(path).open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def analyze(path, out, protocol):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    m, o, obs = bridge(path)
    probes = read_lines(Path(path) / "probes.jsonl")
    events = read_lines(Path(path) / "events.jsonl")
    ref = reference(m, o, probes)
    rows = []
    predictions = []
    matches = []
    schedule = []
    timing = []
    static = None
    for interval in protocol["intervals"]:
        for j in range(protocol["phases"]):
            phase = j * interval / protocol["phases"]
            results, samples = methods(o, interval, phase, static)
            if static is None:
                static = results
            missing = sum(s is None or snapshot_edges(o, s) is None for _, s in samples)
            coverage = (
                o.duration >= 4 * interval
                and missing == 0
                and m["status"] == "TRACE_COMPLETE"
                and m.get("credential_ledger_complete") is True
            )
            for t, s in samples:
                schedule.append(
                    {
                        "interval": interval,
                        "phase": j,
                        "nominal": t,
                        "observed_start": s.start if s else None,
                        "observed_end": s.end if s else None,
                        "usable": bool(
                            s is not None and snapshot_edges(o, s) is not None
                        ),
                    }
                )
            for method, (pred, u) in results.items():
                # Uniform schedule eligibility permits paired comparisons; T/B0 are repeated
                # for reporting only, never treated as independent phase observations.
                historical = score(ref, pred, u)
                if method in ("B0", "B3"):
                    wm = [
                        {
                            "reference_instance_id": r["reference_instance_id"],
                            "predicted_state_at_witness": pred.get(
                                r["semantic_id"], UNKNOWN if u else DENY
                            ),
                            "meaning": "Atemporal hypothesis applied retrospectively; not online detection.",
                        }
                        for r in ref
                    ]
                else:
                    ws = (
                        [(max(0, s.end), s) for s in o.snapshots]
                        if method == "T"
                        else samples
                    )
                    wm = temporal_witness_checks(
                        o, ref, ws, method != "B1", method == "T"
                    )
                yes = sum(w["predicted_state_at_witness"] == ALLOW for w in wm)
                maybe = sum(w["predicted_state_at_witness"] == UNKNOWN for w in wm)
                n = len(ref)
                primary = {
                    **historical,
                    "recovered": yes,
                    "unknown": maybe,
                    "recall_lower": yes / n if n else None,
                    "recall_upper": (yes + maybe) / n if n else None,
                    "historical_structure_recovery_lower": historical["recall_lower"],
                    "evaluation_mode": (
                        "atemporal retrospective hypothesis"
                        if method in ("B0", "B3")
                        else "witness-time sample-and-hold"
                    ),
                }
                timing.extend(
                    {"interval": interval, "phase": j, "method": method, **x}
                    for x in wm
                )
                row = {
                    "run_id": o.run_id,
                    "scenario": o.scenario,
                    "interval": interval,
                    "phase": j,
                    "method": method,
                    "coverage_eligible": coverage,
                    "missing_snapshots": missing,
                    **primary,
                }
                rows.append(row)
                predictions.append(
                    {
                        "interval": interval,
                        "phase": j,
                        "method": method,
                        "candidates": pred,
                        "has_unknown": u,
                    }
                )
                for r, w in zip(ref, wm):
                    matches.append(
                        {
                            "interval": interval,
                            "phase": j,
                            "method": method,
                            "reference_instance_id": r["reference_instance_id"],
                            "semantic_id": r["semantic_id"],
                            "state": w["predicted_state_at_witness"],
                        }
                    )

    certificate = s5_certificate(m, o, probes, events)
    s5sid = semantic(o.target_context, (o.entry, o.chain), o.action, o.resource)
    adjudication = (
        [
            {
                "interval": x["interval"],
                "phase": x["phase"],
                "method": x["method"],
                "candidate": s5sid,
                "classification": (
                    "SCOPED_INVALID_UNION_CANDIDATE"
                    if certificate["status"] == "SCOPED_LEDGER_CERTIFIED"
                    and x["candidates"].get(s5sid) == ALLOW
                    else "NO_CERTIFIED_FALSE_POSITIVE"
                ),
            }
            for x in predictions
        ]
        if o.scenario == "s5"
        else []
    )
    write_json(out / "s5_adjudication.json", adjudication)
    summary = {
        "input_seal": digest(read_json(Path(path) / "SHA256.json")),
        "schema": "ep2-analysis-1",
        "run_id": o.run_id,
        "scenario": o.scenario,
        "cohort": m["cohort"],
        "source_digest": m["source_digest"],
        "protocol_digest": m["protocol_digest"],
        "instrument_status": m["status"],
        "reference_instances": len(ref),
        "reference_structures": len({r["semantic_id"] for r in ref}),
        "s5_certificate": certificate,
        "eligible_rows": sum(r["coverage_eligible"] for r in rows),
        "attempt_included": True,
        "t_s_equals_b2_by_contract": True,
        "inference": "DESCRIPTIVE_SINGLE_RUN",
        "uncertainty": "Readback time is not data-plane effective time; no precision or universal false-positive rate is inferred.",
    }
    for name, data in [
        ("observations.json", obs),
        ("reference.json", ref),
        ("predictions.json", predictions),
        ("matches.json", matches),
        ("temporal_witness_checks.json", timing),
        ("summary.json", summary),
    ]:
        write_json(out / name, data)
    csv_out(out / "metrics.csv", rows)
    csv_out(out / "sampling_schedule.csv", schedule)
    # The null is supplied as a deterministic grid, not fitted to reference successes.
    null = []
    for S in protocol["intervals"]:
        for L in [0, 30, 60, 120, 300, 600, 900, 1800]:
            hit = sum(
                any(
                    1800 <= j * S / protocol["phases"] + k * S < 1800 + L
                    for k in range(math.ceil((1800 + L) / S) + 1)
                )
                for j in range(protocol["phases"])
            )
            null.append(
                {
                    "interval": S,
                    "hypothetical_window_start": 1800,
                    "hypothetical_window_length": L,
                    "continuous_uniform_phase_hit_probability": min(1, L / S),
                    "ten_phase_hit_fraction": hit / protocol["phases"],
                    "is_empirical_window": False,
                }
            )
    csv_out(out / "sampling_null.csv", null)
    write_json(
        out / "behavioral_null_sensitivity.json",
        behavioral_null(m, o, probes, protocol),
    )
    return summary


def behavioral_null(m, o, probes, protocol):
    """Bounds conditional on one denied/allowed/denied episode; not a latency CI."""
    if o.scenario not in ("s2", "s6"):
        return {"status": "NOT_APPLICABLE", "rows": []}
    selected = []
    for p in probes:
        if p.get("context") != o.target_context or p.get("actor") != "experiment":
            continue
        if (o.scenario == "s2" and p.get("kind") != "canary") or (
            o.scenario == "s6" and p.get("purpose") != "fresh_issuance"
        ):
            continue
        start, end = p["start"] - m["trace_origin"], p["end"] - m["trace_origin"]
        if not 0 <= start <= end <= o.duration:
            continue
        state = p["state"]
        if o.scenario == "s2" and state == ALLOW and not p.get("payload_verified"):
            state = UNKNOWN
        selected.append((start, end, state))
    selected.sort()
    allowed = [i for i, x in enumerate(selected) if x[2] == ALLOW]
    if not allowed:
        return {"status": "NO_OBSERVED_ALLOW_EPISODE", "rows": []}
    first, last = allowed[0], allowed[-1]
    before = [x for x in selected[:first] if x[2] == DENY]
    after = [x for x in selected[last + 1 :] if x[2] == DENY]
    monotone = all(x[2] == ALLOW for x in selected[first : last + 1])
    if not before or not after or not monotone:
        return {"status": "SINGLE_EPISODE_BOUNDS_UNESTABLISHED", "rows": []}
    on = [before[-1][0], selected[first][1]]
    off = [selected[last][0], after[0][1]]
    low = max(0, off[0] - on[1])
    high = max(0, off[1] - on[0])
    rows = []
    for S in protocol["intervals"]:

        def hit(a, b):
            if b <= a:
                return 0
            return (
                sum(
                    any(
                        a <= j * S / 10 + k * S < b
                        for k in range(math.ceil(o.duration / S) + 1)
                    )
                    for j in range(10)
                )
                / 10
            )

        rows.append(
            {
                "interval": S,
                "length_lower_conditional": low,
                "length_upper_conditional": high,
                "continuous_phase_hit_lower": min(1, low / S),
                "continuous_phase_hit_upper": min(1, high / S),
                "ten_phase_hit_lower": hit(on[1], off[0]),
                "ten_phase_hit_upper": hit(on[0], off[1]),
            }
        )
    return {
        "status": "CONDITIONAL_SINGLE_EPISODE_SENSITIVITY",
        "on_request_bracket": on,
        "off_request_bracket": off,
        "assumption": "One monotone behavioral allowance episode between probes. Not continuous observation, an effective IAM timestamp, or a confidence interval. Configuration-sampling detection is a separate quantity.",
        "rows": rows,
    }


def cohort_summary(analysis_dirs, out, protocol):
    """Cluster at run level; never resample phases/probes."""
    groups = {}
    seen = set()
    identities = set()
    flow = []
    s5 = []
    for d in analysis_dirs:
        d = Path(d)
        s = read_json(d / "summary.json")
        if s["run_id"] in seen:
            raise InvalidEvidence("Duplicate run in cohort")
        seen.add(s["run_id"])
        identities.add((s["source_digest"], s["protocol_digest"], s["cohort"]))
        flow.append(s)
        rows = list(csv.DictReader((d / "metrics.csv").open()))
        for S in protocol["intervals"]:
            selected = [r for r in rows if int(r["interval"]) == S]
            if len(selected) != protocol["phases"] * len(METHODS):
                raise InvalidEvidence("Incomplete phase/method result table")
            if (
                s["scenario"] == "s5"
                and s["s5_certificate"]["status"] == "SCOPED_LEDGER_CERTIFIED"
                and all(r["coverage_eligible"] == "True" for r in selected)
            ):
                adj = read_json(d / "s5_adjudication.json")
                for method in METHODS:
                    aa = [
                        x for x in adj if x["interval"] == S and x["method"] == method
                    ]
                    s5.append(
                        {
                            "run_id": s["run_id"],
                            "interval": S,
                            "method": method,
                            "scoped_invalid_candidate_phase_fraction": sum(
                                x["classification"] == "SCOPED_INVALID_UNION_CANDIDATE"
                                for x in aa
                            )
                            / protocol["phases"],
                        }
                    )
            valid = all(
                r["coverage_eligible"] == "True"
                and r["recall_lower"] != ""
                and r["unknown"] == "0"
                for r in selected
            )
            if not valid:
                continue
            vals = {
                method: statistics.mean(
                    float(r["recall_lower"]) for r in selected if r["method"] == method
                )
                for method in METHODS
            }
            groups.setdefault((s["scenario"], S), []).append((s["run_id"], vals))
    if len(identities) > 1:
        raise InvalidEvidence("Cannot pool differing source/protocol/cohort identities")
    result = []
    for (scenario, S), runs in sorted(groups.items()):
        for method in ("B2", "T", "T-S"):
            xs = [v[method] - v["B1"] for _, v in runs]
            ci = None
            if len(xs) >= protocol["minimum_core_runs"] and scenario != "s1":
                rng = random.Random(protocol["seed"])
                draws = sorted(
                    statistics.mean(rng.choices(xs, k=len(xs)))
                    for _ in range(protocol["bootstrap_resamples"])
                )
                ci = [
                    draws[int(0.025 * (len(draws) - 1))],
                    draws[int(0.975 * (len(draws) - 1))],
                ]
            result.append(
                {
                    "scenario": scenario,
                    "interval": S,
                    "method": method,
                    "n_independent_runs": len(xs),
                    "paired_mean_difference_vs_B1": statistics.mean(xs),
                    "descriptive_95_percentile_interval": ci,
                    "meets_proposed_practical_margin": statistics.mean(xs)
                    >= protocol["practical_margin"],
                    "multiple_comparison_superiority_claim": False,
                }
            )
    write_json(
        out,
        {
            "flow": flow,
            "comparisons": result,
            "s5_run_level_adjudication": s5,
            "unit": "independent run; phases averaged within run",
            "warning": "Conditional recovery among qualifying witnesses; all attempted-run outcomes must accompany it.",
        },
    )
    return result
