import tempfile, unittest
from pathlib import Path
from ephemeraltrust.common import read_json, read_lines, InvalidEvidence, verify_run
from ephemeraltrust.runner import Runner
from ephemeraltrust.synthetic import demo
from ephemeraltrust.analysis import analyze
from ephemeraltrust.operations import pilot_gate, validate_live
from tests.fake_aws import Clock, FakeAWS

ROOT = Path(__file__).resolve().parents[1]
CFG = {
    "account_id": "123456789012",
    "repository": "example/research",
    "region": "us-east-1",
    "bucket": "ep2-simulation",
    "provider_arn": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
    "controller_role_arn": "arn:aws:iam::123456789012:role/ep2-controller-test",
    "subjects": {
        "main": "repo:example/research:environment:ep2-main",
        "alternate": "repo:example/research:environment:ep2-alternate",
    },
}


class Pipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.tmp.name) / "demo"
        cls.protocol = read_json(ROOT / "configs/protocol.json")
        cls.summaries = demo(cls.path, cls.protocol)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_full_six_scenario_pipeline(self):
        for s in self.summaries:
            with self.subTest(scenario=s["scenario"]):
                m = read_json(self.path / s["scenario"] / "run.json")
                self.assertEqual(m["status"], "TRACE_COMPLETE")
                self.assertGreaterEqual(m["duration"], 7200)
                self.assertTrue(m["cleanup_confirmed"])
                self.assertEqual(m["restoration"], "CONFIRMED")
                self.assertEqual(s["eligible_rows"], 240)

    def test_s5_certificate(self):
        self.assertEqual(
            self.summaries[4]["s5_certificate"]["status"], "SCOPED_LEDGER_CERTIFIED"
        )

    def test_positive_witnesses(self):
        for s in self.summaries:
            self.assertEqual(
                s["reference_instances"], 0 if s["scenario"] == "s5" else 1
            )

    def test_deterministic_analysis(self):
        new = self.path / "repeat"
        analyze(self.path / "s3", new, self.protocol)
        for f in new.iterdir():
            self.assertEqual(
                f.read_bytes(),
                (self.path / "s3-analysis" / f.name).read_bytes(),
                f.name,
            )

    def test_synthetic_not_live_pilot(self):
        with self.assertRaises(Exception):
            pilot_gate(
                [self.path / "s1"], "SYNTHETIC", self.protocol, self.path / "gate.json"
            )

    def test_live_flag_required(self):
        with self.assertRaises(Exception):
            validate_live(CFG, self.protocol, False)

    def test_failure_cleanup(self):
        c = Clock()
        a = FakeAWS(CFG, c)
        a.fail_operation = "put_role_policy"
        r = Runner(
            a,
            CFG,
            self.protocol,
            "s1",
            "fail-policy",
            self.path / "failure",
            "synthetic",
            "synthetic",
            c.now,
            c.sleep,
            c.wall,
        )
        m = r.run()
        self.assertEqual(m["status"], "FAILED_INSTRUMENT")
        self.assertTrue(m["cleanup_confirmed"])
        verify_run(self.path / "failure")

    def test_transport_exception_with_none_response_is_journaled_unknown(self):
        class NoneResponseError(Exception):
            response = None

        class BrokenAWS:
            def call(self, service, op, params, credentials=None):
                raise NoneResponseError("simulated transport failure")

        c = Clock()
        r = Runner(
            BrokenAWS(),
            CFG,
            self.protocol,
            "s4",
            "none-response",
            self.path / "none-response",
            "synthetic",
            "synthetic",
            c.now,
            c.sleep,
            c.wall,
        )
        value, record = r.request("iam", "get_role_policy", {"RoleName": "x"})
        self.assertIsNone(value)
        self.assertEqual(record["state"], "UNKNOWN")
        self.assertEqual(record["error_code"], "NoneResponseError")
        self.assertIsNone(record["request_id"])
        for j in r.j.values():
            j.close()

    def test_existing_role_not_mutated(self):
        c = Clock()
        a = FakeAWS(CFG, c)
        r = Runner(
            a,
            CFG,
            self.protocol,
            "s1",
            "collision",
            self.path / "collision",
            "synthetic",
            "synthetic",
            c.now,
            c.sleep,
            c.wall,
        )
        a.roles[r.entry] = {"trust": {}, "policies": {}}
        m = r.run()
        self.assertEqual(m["status"], "FAILED_INSTRUMENT")
        self.assertIn(r.entry, a.roles)

    def test_late_confirmation(self):
        c = Clock()
        a = FakeAWS(CFG, c)
        r = Runner(
            a,
            CFG,
            self.protocol,
            "s1",
            "late",
            self.path / "late",
            "synthetic",
            "synthetic",
            c.now,
            c.sleep,
            c.wall,
        )
        r.restore_baseline = lambda: None
        r.expect("change", "ALLOW", "issuance")
        for t in (280, 290, 300.001):
            c.t = t
            r.confirmations({"issuance": ("ALLOW", t)})
        self.assertNotIn("change", r.completed)
        self.assertTrue(r.abort_mechanism)
        for j in r.j.values():
            j.close()

    def test_deadline_inclusive(self):
        c = Clock()
        a = FakeAWS(CFG, c)
        r = Runner(
            a,
            CFG,
            self.protocol,
            "s1",
            "on-time",
            self.path / "on-time",
            "synthetic",
            "synthetic",
            c.now,
            c.sleep,
            c.wall,
        )
        r.expect("change", "ALLOW", "issuance")
        for t in (280, 290, 300):
            c.t = t
            r.confirmations({"issuance": ("ALLOW", t)})
        self.assertIn("change", r.completed)
        for j in r.j.values():
            j.close()

    def test_all_probe_issuance_ledgered(self):
        ss = read_lines(self.path / "s5/sessions.jsonl")
        ps = read_lines(self.path / "s5/probes.jsonl")
        issued = [
            p["sid"] for p in ps if p["kind"] == "issuance" and p["state"] == "ALLOW"
        ]
        self.assertEqual(set(issued), {s["sid"] for s in ss})
        self.assertEqual(len(issued), len(ss))

    def test_tamper_detection(self):
        p = self.path / "s1/probes.jsonl"
        old = p.read_bytes()
        p.write_bytes(old + b"\n")
        try:
            with self.assertRaises(InvalidEvidence):
                verify_run(self.path / "s1")
        finally:
            p.write_bytes(old)

    def test_stable_control_scored_after_sampling_warmup(self):
        import csv

        rows = list(csv.DictReader((self.path / "s1-analysis" / "metrics.csv").open()))
        self.assertTrue(rows)
        self.assertTrue(
            all(r["unknown"] == "0" and float(r["recall_lower"]) == 1 for r in rows)
        )
