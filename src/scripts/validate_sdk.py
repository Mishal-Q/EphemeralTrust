"""Validate every simulated runner request against pinned botocore shapes.
No clients, credentials, AWS endpoints, sockets or live requests are used.
"""

import sys, tempfile, json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import botocore.session
from botocore import xform_name
from botocore.validate import validate_parameters
from ephemeraltrust.common import read_json, write_json
from ephemeraltrust.runner import Runner, SCENARIOS
from tests.fake_aws import Clock, FakeAWS
from tests.test_pipeline import CFG

root = Path(__file__).resolve().parents[1]
protocol = read_json(root / "configs/protocol.json")
session = botocore.session.get_session()
models = {s: session.get_service_model(s) for s in ("iam", "sts", "s3")}
mapping = {s: {xform_name(n): n for n in m.operation_names} for s, m in models.items()}
counts = {}


class ValidatedFake(FakeAWS):
    def call(self, service, op, params, credentials=None):
        model = models[service].operation_model(mapping[service][op])
        validate_parameters(params, model.input_shape)
        counts[service + "." + op] = counts.get(service + "." + op, 0) + 1
        return super().call(service, op, params, credentials)


with tempfile.TemporaryDirectory() as tmp:
    for s in SCENARIOS:
        c = Clock()
        a = ValidatedFake(CFG, c)
        r = Runner(
            a,
            CFG,
            protocol,
            s,
            "sdk-" + s,
            Path(tmp) / s,
            "SYNTHETIC",
            "synthetic",
            c.now,
            c.sleep,
            c.wall,
        )
        m = r.run()
        assert m["status"] == "TRACE_COMPLETE" and m["cleanup_confirmed"], (s, m)
# Conditional evaluation-slot claim is outside Runner; validate it separately.
validate_parameters(
    {
        "Bucket": "ep2-canary-test",
        "Key": "ep2-run-cohort-test/slot-1.json",
        "Body": b"{}",
        "IfNoneMatch": "*",
        "ServerSideEncryption": "AES256",
    },
    models["s3"].operation_model("PutObject").input_shape,
)
result = {
    "status": "PASS",
    "botocore_version": __import__("botocore").__version__,
    "requests_validated": sum(counts.values()),
    "operations": counts,
    "aws_requests_executed": 0,
    "scope": "API request shapes only; IAM permissions, propagation, OIDC exchange and live outcomes remain unvalidated.",
}
write_json(root / "validation/SDK_REQUEST_VALIDATION.json", result)
print(json.dumps(result, indent=2))
