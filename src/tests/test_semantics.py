import unittest, copy
from ephemeraltrust.iam import *
from ephemeraltrust.model import *
from ephemeraltrust.analysis import methods, score, reference, projected
from ephemeraltrust.common import InvalidEvidence, no_secrets
from ephemeraltrust.transport import classification

A = "arn:aws:iam::123456789012:role/A"
B = "arn:aws:iam::123456789012:role/B"
C = "arn:aws:iam::123456789012:role/controller"
P = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
R = "arn:aws:s3:::canary/object"
SUB = "repo:x/y:environment:ep2-main"


def config(open_trust=False, cap=True, chain=False):
    return {
        "scope": "supported",
        "entry_trust": trust(P, SUB if open_trust else "blocked"),
        "chain_trust": chain_trust("123456789012", A, C),
        "entry_policies": ([identity("s3:GetObject", R)] if cap else [])
        + ([identity("sts:AssumeRole", B)] if chain else []),
        "chain_policies": [],
    }


def cred(
    sid="a",
    role=A,
    parent=None,
    issued=5,
    expires=30,
    context="main",
    actor="experiment",
    sp=None,
):
    return {
        "sid": sid,
        "role": role,
        "context": context,
        "parent": parent,
        "start": issued - 0.1,
        "issued": issued,
        "expires": expires,
        "actor": actor,
        "session_policy": sp,
        "revoked": None,
    }


def obs(cfg=None, creds=None):
    return {
        "schema": "ep2-observations-1",
        "run_id": "test",
        "scenario": "s3",
        "duration": 60,
        "target_context": "main",
        "contexts": {
            "main": {
                "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                "token.actions.githubusercontent.com:sub": SUB,
            }
        },
        "entry": A,
        "chain": B,
        "provider": P,
        "account": "123456789012",
        "action": "s3:GetObject",
        "resource": R,
        "snapshots": [
            {"start": 14, "end": 15, "config": cfg or config(), "complete": True}
        ],
        "credentials": creds if creds is not None else [cred()],
    }


def predict(d, t=20, sessions=True):
    o = from_observation_dict(d)
    return candidates(o, snapshot_edges(o, o.snapshots[0]), t, sessions)


class Semantics(unittest.TestCase):
    def test_persistence_after_trust_removal(self):
        d = obs()
        self.assertFalse(predict(d, sessions=False)[0])
        self.assertIn(ALLOW, predict(d)[0].values())

    def test_no_issuance_no_persistence(self):
        self.assertFalse(predict(obs(creds=[]))[0])

    def test_expiry_boundary(self):
        self.assertFalse(predict(obs(), t=30)[0])

    def test_future_issuance_not_visible(self):
        self.assertFalse(predict(obs(), t=4)[0])

    def test_other_context_not_substituted(self):
        self.assertFalse(predict(obs(creds=[cred(context="alternate")]))[0])

    def test_verifier_not_attacker(self):
        self.assertFalse(predict(obs(creds=[cred(actor="verifier")]))[0])

    def test_missing_parent(self):
        c = config(cap=False)
        c["chain_policies"] = [identity("s3:GetObject", R)]
        self.assertFalse(predict(obs(c, [cred("b", B, "absent")]))[0])

    def test_parent_invalid_at_issue(self):
        c = config(cap=False)
        c["chain_policies"] = [identity("s3:GetObject", R)]
        self.assertFalse(
            predict(obs(c, [cred(expires=7), cred("b", B, "a", 10, 40)]))[0]
        )

    def test_child_survives_parent_expiry(self):
        c = config(cap=False)
        c["chain_policies"] = [identity("s3:GetObject", R)]
        self.assertIn(
            semantic("main", (A, B), "s3:GetObject", R),
            predict(obs(c, [cred(expires=10), cred("b", B, "a", 8, 40)]))[0],
        )

    def test_three_edge_endpoint(self):
        c = config(True, False, True)
        c["chain_policies"] = [identity("s3:GetObject", R)]
        self.assertEqual(
            set(predict(obs(c, []))[0]), {semantic("main", (A, B), "s3:GetObject", R)}
        )

    def test_intermediate_not_endpoint(self):
        self.assertFalse(predict(obs(config(True, False, True), []))[0])

    def test_current_explicit_deny(self):
        c = config()
        d = identity("s3:GetObject", R)
        d["Statement"][0]["Effect"] = "Deny"
        c["entry_policies"].append(d)
        self.assertFalse(predict(obs(c))[0])

    def test_session_policy_restriction(self):
        p = identity("s3:GetObject", R)
        p["Statement"][0]["Effect"] = "Deny"
        self.assertFalse(predict(obs(creds=[cred(sp=p)]))[0])

    def test_unsupported_condition_unknown(self):
        c = config()
        c["entry_policies"][0]["Statement"][0]["Condition"] = {
            "NumericLessThan": {"x": 1}
        }
        pred, u = predict(obs(c))
        self.assertTrue(u)
        self.assertIn(UNKNOWN, pred.values())

    def test_unsupported_scope_unknown(self):
        c = config()
        c["scope"] = "unsupported"
        self.assertEqual(predict(obs(c)), ({}, True))

    def test_direct_role_principal_out_of_scope(self):
        c = config()
        c["chain_trust"]["Statement"][0]["Principal"] = {"AWS": A}
        self.assertEqual(predict(obs(c)), ({}, True))

    def test_subject_and_audience(self):
        self.assertEqual(
            evaluate(
                [trust(P, SUB)],
                "sts:AssumeRoleWithWebIdentity",
                A,
                {
                    "token.actions.githubusercontent.com:sub": SUB,
                    "token.actions.githubusercontent.com:aud": "wrong",
                },
                ("Federated", P),
            ),
            DENY,
        )

    def test_resource_scope(self):
        self.assertEqual(
            evaluate([identity("s3:GetObject", R)], "s3:GetObject", R + "2", {}), DENY
        )

    def test_resource_wildcard(self):
        self.assertEqual(
            evaluate(
                [identity("s3:GetObject", "arn:aws:s3:::canary/*")],
                "s3:GetObject",
                R,
                {},
            ),
            ALLOW,
        )

    def test_missing_condition_value(self):
        self.assertEqual(
            evaluate(
                [trust(P, SUB)],
                "sts:AssumeRoleWithWebIdentity",
                A,
                {},
                ("Federated", P),
            ),
            UNKNOWN,
        )

    def test_unsupported_action(self):
        self.assertEqual(
            evaluate([identity("iam:*", "*")], "iam:DeleteRole", "*", {}), UNKNOWN
        )

    def test_errors_are_not_denials(self):
        for code in (
            "ExpiredToken",
            "Throttling",
            "InvalidIdentityToken",
            "TimeoutError",
            "NoSuchKey",
        ):
            self.assertEqual(classification(code), UNKNOWN)

    def test_access_denied(self):
        self.assertEqual(classification("AccessDenied"), DENY)

    def test_oracle_rejected(self):
        for target, key in [
            ("top", "reference_paths"),
            ("snapshot", "probe_state"),
            ("credential", "canary_success"),
        ]:
            d = obs()
            obj = (
                d
                if target == "top"
                else d["snapshots"][0] if target == "snapshot" else d["credentials"][0]
            )
            obj[key] = []
            with self.assertRaises(InvalidEvidence):
                from_observation_dict(d)

    def test_secrets_rejected(self):
        for key in ("SecretAccessKey", "SessionToken", "WebIdentityToken"):
            with self.assertRaises(InvalidEvidence):
                no_secrets({key: "abc"})

    def test_duplicate_sessions(self):
        with self.assertRaises(InvalidEvidence):
            from_observation_dict(obs(creds=[cred(), cred()]))

    def test_backwards_time(self):
        d = obs()
        d["snapshots"][0]["start"] = 16
        with self.assertRaises(InvalidEvidence):
            from_observation_dict(d)

    def test_nonfinite_time(self):
        d = obs()
        d["credentials"][0]["expires"] = float("inf")
        with self.assertRaises(InvalidEvidence):
            from_observation_dict(d)

    def test_stale_snapshot(self):
        self.assertIsNone(projected(from_observation_dict(obs()), 60, 45)[0][1])

    def test_no_hindsight(self):
        self.assertIsNone(projected(from_observation_dict(obs()), 60, 0)[0][1])

    def test_no_failed_snapshot_backfill(self):
        d = obs()
        d["snapshots"].append(
            {"start": 19, "end": 20, "config": config(), "complete": False}
        )
        self.assertIsNone(projected(from_observation_dict(d), 60, 21)[0][1])

    def test_static_union_incompatible_windows(self):
        c1 = config(True, False, True)
        c2 = config(False, False, False)
        c2["chain_policies"] = [identity("s3:GetObject", R)]
        d = obs(c1, [cred(expires=9), cred("b", B, "a", 6, 10)])
        d["scenario"] = "s5"
        d["snapshots"] = [
            {"start": 0, "end": 0, "config": c1, "complete": True},
            {"start": 14, "end": 15, "config": c2, "complete": True},
        ]
        o = from_observation_dict(d)
        e = union_edges([snapshot_edges(o, s) for s in o.snapshots])
        self.assertIn(ALLOW, candidates(o, e, 30, True, True)[0].values())
        self.assertFalse(candidates(o, snapshot_edges(o, o.snapshots[1]), 20, True)[0])

    def test_same_input_equality(self):
        r, _ = methods(from_observation_dict(obs()), 10, 0)
        self.assertEqual(r["B2"], r["T-S"])

    def test_empty_reference_undefined(self):
        self.assertIsNone(score([], {}, False)["recall_lower"])

    def test_unknown_bounds(self):
        s = score([{"semantic_id": "x"}], {}, True)
        self.assertEqual((s["recall_lower"], s["recall_upper"]), (0, 1))

    def test_repeated_polls_not_extra_instances(self):
        o = from_observation_dict(obs())
        o = Observation(**{**o.__dict__, "scenario": "s1"})
        m = {"trace_origin": 0, "episodes": {"x": [0, 30]}}
        ps = [
            {
                "kind": "canary",
                "state": ALLOW,
                "actor": "experiment",
                "context": "main",
                "action": o.action,
                "resource": o.resource,
                "payload_verified": True,
                "sid": "a",
                "episode": "x",
                "start": t,
                "end": t + 0.1,
                "probe_id": str(t),
            }
            for t in (10, 12, 14)
        ]
        self.assertEqual(len(reference(m, o, ps)), 1)

    def test_persistence_reference_requires_fresh_denial(self):
        o = from_observation_dict(obs())
        m = {"trace_origin": 0, "episodes": {"x": [0, 30]}}
        p = {
            "kind": "canary",
            "state": ALLOW,
            "actor": "experiment",
            "context": "main",
            "action": o.action,
            "resource": o.resource,
            "payload_verified": True,
            "sid": "a",
            "episode": "x",
            "start": 10,
            "end": 10.1,
            "probe_id": "x",
            "cycle": 1,
        }
        self.assertEqual(reference(m, o, [p]), [])
        self.assertEqual(
            len(
                reference(
                    m,
                    o,
                    [
                        p,
                        {
                            "purpose": "fresh_issuance",
                            "cycle": 1,
                            "state": DENY,
                            "start": 9.9,
                            "end": 10,
                        },
                    ],
                )
            ),
            1,
        )
