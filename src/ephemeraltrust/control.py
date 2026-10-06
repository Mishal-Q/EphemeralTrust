"""S6 main-context companion. Separate job/context; never shares raw tokens."""

import time, hashlib, json
from pathlib import Path
from .common import Journal, write_json, seal_run, utc
from .transport import classification
from .runner import PAYLOAD_HASH


def run_control(
    aws,
    cfg,
    run_id,
    out,
    max_seconds=8100,
    sleep=time.sleep,
    clock=time.monotonic,
    wall=time.time,
):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    j = Journal(out / "main_control.jsonl")
    start = clock()
    prefix = "ep2-run-" + hashlib.sha256(run_id.encode()).hexdigest()[:20]
    entry = "arn:aws:iam::" + cfg["account_id"] + ":role/" + prefix + "-entry"
    creds = None
    expiry = 0
    ready = None
    observed = False
    count = 0
    status = "TIMEOUT"

    def record(row):
        j.append({"utc": utc(wall()), "elapsed": clock() - start, **row})

    try:
        while clock() - start < max_seconds:
            tick = clock()
            begin = wall()
            try:
                r = aws.call(
                    "s3",
                    "get_object",
                    {"Bucket": cfg["bucket"], "Key": prefix + "/ready.json"},
                )
                ready = json.loads(r["Body"].read())
                r["Body"].close()
                observed = True
            except Exception as e:
                code = (
                    getattr(e, "response", {})
                    .get("Error", {})
                    .get("Code", type(e).__name__)
                )
                if code == "NoSuchKey" and observed:
                    status = "RUNNER_REMOVED_READY_MARKER"
                    break
                record({"kind": "await_ready", "error_code": code})
                sleep(10)
                continue
            if not creds or wall() >= expiry - 120:
                try:
                    token, claims = aws.token("main")
                    request_start = wall()
                    r = aws.call(
                        "sts",
                        "assume_role_with_web_identity",
                        {
                            "RoleArn": entry,
                            "RoleSessionName": "ep2-control-" + str(count),
                            "WebIdentityToken": token,
                            "DurationSeconds": 900,
                        },
                    )
                    creds = r["Credentials"]
                    expiry = creds["Expiration"].timestamp()
                    record(
                        {
                            "kind": "issuance",
                            "actor": "control",
                            "state": "ALLOW",
                            "session_id": r["AssumedRoleUser"]["AssumedRoleId"],
                            "request_start": utc(request_start),
                            "request_end": utc(wall()),
                            "expiry": utc(expiry),
                            "parent": None,
                            "role": entry,
                            "claims": claims,
                            "request_id": r.get("ResponseMetadata", {}).get(
                                "RequestId"
                            ),
                        }
                    )
                except Exception as e:
                    record(
                        {
                            "kind": "issuance",
                            "state": classification(
                                getattr(e, "response", {})
                                .get("Error", {})
                                .get("Code", "")
                            ),
                        }
                    )
                    sleep(10)
                    continue
            try:
                request_start = wall()
                r = aws.call(
                    "s3",
                    "get_object",
                    {"Bucket": cfg["bucket"], "Key": ready["key"]},
                    creds,
                )
                b = r["Body"].read()
                r["Body"].close()
                state = (
                    "ALLOW"
                    if hashlib.sha256(b).hexdigest() == PAYLOAD_HASH
                    else "UNKNOWN"
                )
                record(
                    {
                        "kind": "canary",
                        "state": state,
                        "request_start": utc(request_start),
                        "request_end": utc(wall()),
                        "request_id": r.get("ResponseMetadata", {}).get("RequestId"),
                    }
                )
            except Exception as e:
                record(
                    {
                        "kind": "canary",
                        "request_start": utc(request_start),
                        "request_end": utc(wall()),
                        "state": classification(
                            getattr(e, "response", {}).get("Error", {}).get("Code", "")
                        ),
                    }
                )
            count += 1
            sleep(max(0, 10 - (clock() - tick)))
    finally:
        j.close()
        write_json(
            out / "control_summary.json",
            {
                "run_id": run_id,
                "status": status,
                "sampled_ticks": count,
                "context": "main",
                "ready": ready,
                "continuous_availability_proven": False,
            },
        )
        seal_run(out)
    return status
