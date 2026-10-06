import tempfile
import unittest
from pathlib import Path
from ephemeraltrust.analysis import temporal_witness_checks, behavioral_null
from ephemeraltrust.model import from_observation_dict, semantic
from ephemeraltrust.iam import ALLOW, DENY, UNKNOWN
from ephemeraltrust.operations import (
    freeze,
    verify_source,
    make_cohort,
    validate_control,
)
from ephemeraltrust.common import GuardError, write_json, seal_run, utc
from tests.test_semantics import obs, config, cred, A, R


class FinalGates(unittest.TestCase):
    def witness(self, start=20, end=20.1):
        return [
            {
                "reference_instance_id": "w",
                "semantic_id": semantic("main", (A,), "s3:GetObject", R),
                "request_start": start,
                "request_end": end,
            }
        ]

    def test_prior_structure_does_not_recover_later_persistence(self):
        d = obs()
        d["snapshots"].insert(
            0, {"start": 0, "end": 0, "complete": True, "config": config(True)}
        )
        o = from_observation_dict(d)
        samples = [(0, o.snapshots[0]), (15, o.snapshots[1])]
        self.assertEqual(
            temporal_witness_checks(o, self.witness(), samples, False)[0][
                "predicted_state_at_witness"
            ],
            DENY,
        )
        self.assertEqual(
            temporal_witness_checks(o, self.witness(), samples, True)[0][
                "predicted_state_at_witness"
            ],
            ALLOW,
        )

    def test_post_sample_session_not_visible_to_sampled_method(self):
        o = from_observation_dict(obs(creds=[cred(issued=18)]))
        samples = [(15, o.snapshots[0])]
        self.assertEqual(
            temporal_witness_checks(o, self.witness(), samples, True)[0][
                "predicted_state_at_witness"
            ],
            DENY,
        )
        self.assertEqual(
            temporal_witness_checks(o, self.witness(), samples, True, True)[0][
                "predicted_state_at_witness"
            ],
            ALLOW,
        )

    def test_expiry_between_sample_and_witness(self):
        o = from_observation_dict(obs(creds=[cred(expires=19)]))
        self.assertEqual(
            temporal_witness_checks(o, self.witness(), [(15, o.snapshots[0])], True)[0][
                "predicted_state_at_witness"
            ],
            DENY,
        )

    def test_witness_crossing_sample_boundary_unknown(self):
        o = from_observation_dict(obs())
        self.assertEqual(
            temporal_witness_checks(
                o,
                self.witness(19.9, 20.1),
                [(15, o.snapshots[0]), (20, o.snapshots[0])],
                True,
            )[0]["predicted_state_at_witness"],
            UNKNOWN,
        )

    def test_source_edit_breaks_freeze(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "code.py"
            p.write_text("x=1\n")
            freeze(t, {})
            verify_source(t, {})
            p.write_text("x=2\n")
            with self.assertRaises(GuardError):
                verify_source(t, {})

    def test_proposed_cohort_counts_and_determinism(self):
        with tempfile.TemporaryDirectory() as t:
            p = {"seed": 1, "duration": 7200}
            a = make_cohort(p, "source", Path(t) / "a.json")
            b = make_cohort(p, "source", Path(t) / "b.json")
            self.assertEqual(a, b)
            self.assertEqual(len(a["slots"]), 55)
            self.assertEqual(sum(x["scenario"] == "s1" for x in a["slots"]), 5)
            self.assertEqual(a["trace_hours"], 110)

    def test_unknown_control_sample_blocks_instrument_gate(self):
        import json

        with tempfile.TemporaryDirectory() as t:
            p = Path(t)
            rows = [
                {
                    "kind": "canary",
                    "request_end": utc(i),
                    "state": UNKNOWN if i == 20 else ALLOW,
                }
                for i in (0, 10, 20, 30)
            ]
            (p / "main_control.jsonl").write_text(
                "".join(json.dumps(x) + "\n" for x in rows)
            )
            write_json(p / "control_summary.json", {"run_id": "r"})
            seal_run(p)
            result = validate_control(
                p, {"trace_start_utc": utc(0), "trace_end_utc": utc(30)}
            )
            self.assertTrue(result["sample_coverage"])
            self.assertFalse(result["instrument_complete"])
            self.assertEqual(result["unknown"], 1)

    def test_flapping_behavior_does_not_produce_single_window_bound(self):
        d = obs()
        d["scenario"] = "s2"
        o = from_observation_dict(d)
        ps = [
            {
                "kind": "canary",
                "actor": "experiment",
                "context": "main",
                "start": t,
                "end": t + 0.1,
                "state": s,
                "payload_verified": True,
            }
            for t, s in [(1, DENY), (10, ALLOW), (20, DENY), (30, ALLOW), (40, DENY)]
        ]
        result = behavioral_null({"trace_origin": 0}, o, ps, {"intervals": [60]})
        self.assertEqual(result["status"], "SINGLE_EPISODE_BOUNDS_UNESTABLISHED")

    def test_unknown_experimental_issuance_invalidates_complete_ledger(self):
        from ephemeraltrust.runner import Runner
        from tests.fake_aws import Clock, FakeAWS
        from tests.test_pipeline import CFG, ROOT
        from ephemeraltrust.common import read_json

        with tempfile.TemporaryDirectory() as t:
            c = Clock()
            a = FakeAWS(CFG, c)
            r = Runner(
                a,
                CFG,
                read_json(ROOT / "configs/protocol.json"),
                "s1",
                "unknown-issue",
                Path(t) / "run",
                "SYNTHETIC",
                "synthetic",
                c.now,
                c.sleep,
                c.wall,
            )
            a.fail_operation = "assume_role_with_web_identity"
            sid, state = r.issue()
            self.assertIsNone(sid)
            self.assertEqual(state, UNKNOWN)
            self.assertFalse(r.meta["credential_ledger_complete"])
            for journal in r.j.values():
                journal.close()

    def test_live_config_accepts_exact_immutable_oidc_subjects(self):
        import copy
        from unittest.mock import patch
        from tests.test_pipeline import CFG, ROOT
        from ephemeraltrust.common import read_json
        from ephemeraltrust.operations import validate_live

        c = copy.deepcopy(CFG)
        c.update(
            bucket="ep2-canary-test",
            zero_cost_reviewed=True,
            dedicated_experiment_scope_confirmed=True,
            max_live_runs_per_dispatch=1,
            max_trace_seconds=7200,
        )
        c["subjects"] = {
            k: "repo:example@123/research@456:environment:ep2-" + k
            for k in ("main", "alternate")
        }
        with patch.dict(
            "os.environ",
            {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": c["repository"]},
        ):
            validate_live(c, read_json(ROOT / "configs/protocol.json"), True)
            c["subjects"][
                "alternate"
            ] = "repo:example@123/research@789:environment:ep2-alternate"
            with self.assertRaises(GuardError):
                validate_live(c, read_json(ROOT / "configs/protocol.json"), True)
