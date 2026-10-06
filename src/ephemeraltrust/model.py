"""Typed observation boundary and sequential, exact-lineage candidate construction."""

from dataclasses import dataclass
from .common import InvalidEvidence, finite
from .iam import evaluate, combine, ALLOW, DENY, UNKNOWN


@dataclass(frozen=True)
class Credential:
    sid: str
    role: str
    context: str
    parent: str | None
    start: float
    issued: float
    expires: float
    actor: str
    session_policy: dict | None
    revoked: float | None


@dataclass(frozen=True)
class Snapshot:
    start: float
    end: float
    config: dict
    complete: bool


@dataclass(frozen=True)
class Observation:
    run_id: str
    scenario: str
    duration: float
    target_context: str
    contexts: dict
    entry: str
    chain: str
    provider: str
    account: str
    action: str
    resource: str
    snapshots: tuple
    credentials: tuple


OBS_FIELDS = {
    "schema",
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
    "snapshots",
    "credentials",
}
CRED_FIELDS = {
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
}
SNAP_FIELDS = {"start", "end", "config", "complete"}


def from_observation_dict(d):
    if set(d) != OBS_FIELDS or d["schema"] != "ep2-observations-1":
        raise InvalidEvidence(
            "Observation boundary fields differ; reference fields are forbidden"
        )
    ss = []
    cs = []
    for s in d["snapshots"]:
        if set(s) != SNAP_FIELDS:
            raise InvalidEvidence("Unexpected snapshot fields")
        start, end = finite(s["start"]), finite(s["end"])
        if end < start:
            raise InvalidEvidence("Backwards request")
        ss.append(Snapshot(start, end, s["config"], s["complete"]))
    for c in d["credentials"]:
        if set(c) != CRED_FIELDS:
            raise InvalidEvidence("Unexpected credential fields")
        for k in ("start", "issued", "expires"):
            finite(c[k])
        if c["start"] > c["issued"] or c["expires"] <= c["issued"]:
            raise InvalidEvidence("Invalid credential interval")
        if c["actor"] not in {"experiment", "verifier", "control"}:
            raise InvalidEvidence("Unknown credential actor")
        cs.append(Credential(**c))
    if len({c.sid for c in cs}) != len(cs):
        raise InvalidEvidence("Duplicate credential identity")
    if [s.end for s in ss] != sorted(s.end for s in ss):
        raise InvalidEvidence("Unordered observations")
    o = Observation(
        **{
            k: d[k]
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
        },
        snapshots=tuple(ss),
        credentials=tuple(cs)
    )
    finite(o.duration)
    if o.duration <= 0:
        raise InvalidEvidence("Empty trace")
    return o


def lineage(o, c, by=None):
    by = by if by is not None else {x.sid: x for x in o.credentials}
    seen = set()
    chain = []
    cur = c
    while cur:
        if cur.sid in seen or cur.actor != "experiment" or cur.context != c.context:
            return None
        seen.add(cur.sid)
        chain.append(cur.role)
        if cur.parent is None:
            if cur.role != o.entry:
                return None
            break
        par = by.get(cur.parent)
        if par is None or par.role != o.entry or cur.role != o.chain:
            return None
        if not (par.issued <= cur.start and cur.issued < par.expires):
            return None
        if par.revoked is not None and cur.issued >= par.revoked:
            return None
        cur = par
    return tuple(reversed(chain))


def semantic(context, roles, action, resource):
    return "|".join((context, ">".join(roles), action, resource))


def snapshot_edges(o, s):
    """Edges include explicit unknowns. Policies are evaluated at use, not issue."""
    if not s.complete or s.config.get("scope") != "supported":
        return None
    cfg = s.config
    try:
        if set(cfg) != {
            "scope",
            "entry_trust",
            "chain_trust",
            "entry_policies",
            "chain_policies",
        }:
            return None
        # Only the generated account-root delegation form is supported for role chaining.
        for st in cfg["chain_trust"].get("Statement", []):
            if st.get("Principal") != {"AWS": "arn:aws:iam::" + o.account + ":root"}:
                return None
        out = {}
        for ctx, claims in o.contexts.items():
            out[("root:" + ctx, o.entry)] = evaluate(
                [cfg["entry_trust"]],
                "sts:AssumeRoleWithWebIdentity",
                o.entry,
                claims,
                ("Federated", o.provider),
            )
        out[(o.entry, o.chain)] = combine(
            evaluate(cfg["entry_policies"], "sts:AssumeRole", o.chain, {}),
            evaluate(
                [cfg["chain_trust"]],
                "sts:AssumeRole",
                o.chain,
                {"aws:PrincipalArn": o.entry},
                ("AWS", "arn:aws:iam::" + o.account + ":root"),
            ),
        )
        out[(o.entry, "canary")] = evaluate(
            cfg["entry_policies"], o.action, o.resource, {}
        )
        out[(o.chain, "canary")] = evaluate(
            cfg["chain_policies"], o.action, o.resource, {}
        )
        return out
    except (KeyError, TypeError, AttributeError):
        return None


def candidates(o, edges, at, with_sessions=False, ignore_time=False, available_at=None):
    """Return protected endpoints only. Sessions form starting states with ancestry.
    A child remains valid after its parent expires: ancestry is checked at issuance.
    """
    if edges is None:
        return {}, True
    starts = [("root:" + o.target_context, (), ALLOW, None)]
    by = {x.sid: x for x in o.credentials}
    if with_sessions:
        for c in o.credentials:
            if c.context != o.target_context or c.actor != "experiment":
                continue
            if available_at is not None and c.issued > available_at:
                continue
            if not ignore_time and not (
                c.issued <= at < c.expires and (c.revoked is None or at < c.revoked)
            ):
                continue
            if ignore_time and c.issued > at:
                continue
            roles = lineage(o, c, by)
            if roles:
                starts.append((c.role, roles, ALLOW, c))
    out = {}
    unknown = False
    for node, roles, state, credential in starts:
        todo = [(node, roles, state, credential)]
        while todo:
            node, roles, state, credential = todo.pop()
            for (a, b), edge in edges.items():
                if a != node or edge == DENY:
                    continue
                st = combine(state, edge)
                if credential and credential.session_policy:
                    act = o.action if b == "canary" else "sts:AssumeRole"
                    res = o.resource if b == "canary" else b
                    st = combine(
                        st, evaluate([credential.session_policy], act, res, {})
                    )
                if st == DENY:
                    continue
                if b == "canary":
                    if not roles:
                        continue
                    sid = semantic(o.target_context, roles, o.action, o.resource)
                    if out.get(sid) != ALLOW:
                        out[sid] = st
                    unknown |= st == UNKNOWN
                elif b not in roles and len(roles) < 2:
                    todo.append((b, roles + (b,), st, None))
    return out, unknown


def union_edges(all_edges):
    out = {}
    for edges in all_edges:
        if edges is None:
            continue
        for e, state in edges.items():
            if state == ALLOW:
                out[e] = ALLOW
            elif state == UNKNOWN and out.get(e) != ALLOW:
                out[e] = UNKNOWN
            elif e not in out:
                out[e] = DENY
    return out
