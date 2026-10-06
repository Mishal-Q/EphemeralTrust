"""One isolated scenario per invocation. Append-only evidence; cleanup in finally."""

import json, time, uuid, hashlib, signal, os, platform
from importlib.metadata import version, PackageNotFoundError
from pathlib import Path
from .common import GuardError, Journal, write_json, seal_run, utc, epoch, digest
from .iam import trust, identity, chain_trust, ALLOW, DENY, UNKNOWN
from .transport import classification

PAYLOAD = b"EphemeralTrust Phase 2 canary\n"
PAYLOAD_HASH = hashlib.sha256(PAYLOAD).hexdigest()
SCENARIOS = ("s1", "s2", "s3", "s4", "s5", "s6")


class StopRun(RuntimeError):
    pass


class Runner:
    def __init__(
        self,
        aws,
        cfg,
        protocol,
        scenario,
        run_id,
        out,
        source_digest,
        cohort="pilot",
        clock=time.monotonic,
        sleep=time.sleep,
        wall=time.time,
    ):
        self.aws = aws
        self.cfg = cfg
        self.protocol = protocol
        self.scenario = scenario
        self.run_id = run_id
        self.out = Path(out)
        self.clock = clock
        self.sleep = sleep
        self.wall = wall
        self.process_start = clock()
        self.wall_start = wall()
        self.origin = 0
        self.sessions = {}
        self.session_rows = []
        self.created = []
        self.targets = {}
        self.lastfresh = {}
        self.old = None
        self.child = None
        self.verifier = None
        self.cycle = 0
        self.seq = 0
        self.pending = []
        self.completed = []
        self.abort_mechanism = False
        self.last_snapshot = None
        self.last_completion = 0
        self.baseline_history = []
        self.baseline_passed = False
        self.key_attempted = False
        self.context = "alternate" if scenario == "s6" else "main"
        self.account = cfg["account_id"]
        self.bucket = cfg["bucket"]
        self.prefix = "ep2-run-" + hashlib.sha256(run_id.encode()).hexdigest()[:20]
        self.entry = self.prefix + "-entry"
        self.chain = self.prefix + "-chain"
        self.entry_arn = f"arn:aws:iam::{self.account}:role/{self.entry}"
        self.chain_arn = f"arn:aws:iam::{self.account}:role/{self.chain}"
        self.key = self.prefix + "/canary.txt"
        self.resource = f"arn:aws:s3:::{self.bucket}/{self.key}"
        self.action = "s3:PutObject" if scenario == "s2" else "s3:GetObject"
        self.strict = trust(cfg["provider_arn"], cfg["subjects"]["main"])
        self.blocked = trust(
            cfg["provider_arn"],
            "repo:" + cfg["repository"] + ":environment:ep2-never-" + self.prefix,
        )
        self.chaintrust = chain_trust(
            self.account, self.entry_arn, cfg["controller_role_arn"]
        )
        self.base_entry = (
            []
            if scenario in ("s2", "s4", "s5")
            else [identity("s3:GetObject", self.resource)]
        )
        self.entry_policies = list(self.base_entry)
        self.chain_policies = []
        self.trust_doc = self.strict
        self.out.mkdir(parents=True, exist_ok=False)
        self.j = {
            n: Journal(self.out / (n + ".jsonl"))
            for n in ("snapshots", "sessions", "probes", "events")
        }
        packages = {}
        for package in ("boto3", "botocore", "urllib3", "s3transfer"):
            try:
                packages[package] = version(package)
            except PackageNotFoundError:
                packages[package] = "NOT_INSTALLED_OFFLINE"
        self.meta = {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "packages": packages,
            "schema": "ep2-run-1",
            "run_id": run_id,
            "scenario": scenario,
            "cohort": cohort,
            "source_digest": source_digest,
            "protocol_digest": digest(protocol),
            "trace_origin": 0,
            "duration": 0,
            "status": "INITIALIZING",
            "target_context": self.context,
            "contexts": {
                k: {
                    "token.actions.githubusercontent.com:sub": v,
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                }
                for k, v in cfg["subjects"].items()
            },
            "entry": self.entry_arn,
            "chain": self.chain_arn,
            "provider": cfg["provider_arn"],
            "account": self.account,
            "action": self.action,
            "resource": self.resource,
            "episodes": protocol["episodes"][scenario],
            "resource_prefix": self.prefix,
            "region": cfg["region"],
            "bucket": self.bucket,
            "key": self.key,
            "start_utc": utc(self.wall_start),
            "github_sha": os.environ.get("GITHUB_SHA"),
            "github_run_id": os.environ.get("GITHUB_RUN_ID"),
            "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "config_digest": digest(cfg),
            "credential_ledger_complete": True,
            "request_retries": "SDK automatic retries disabled; each request logged; no authorization errors recoded",
        }

    def now(self):
        return self.clock() - self.process_start

    def event(self, event_type, **kw):
        self.j["events"].append(
            {"event": event_type, "t": self.now(), "utc": utc(self.wall()), **kw}
        )

    def request(self, service, op, params, credentials=None):
        self.seq += 1
        rid = f"{self.run_id}-{self.seq:06d}"
        start = self.now()
        w = self.wall()
        value = None
        code = None
        reqid = None
        try:
            value = self.aws.call(service, op, params, credentials)
            state = ALLOW
            reqid = value.get("ResponseMetadata", {}).get("RequestId")
        except Exception as e:
            # Some botocore transport exceptions expose ``response = None``.
            # Treat those as UNKNOWN rather than crashing the evidence recorder.
            er = getattr(e, "response", None)
            if not isinstance(er, dict):
                er = {}
            error = er.get("Error")
            metadata = er.get("ResponseMetadata")
            if not isinstance(error, dict):
                error = {}
            if not isinstance(metadata, dict):
                metadata = {}
            code = error.get("Code") or type(e).__name__
            reqid = metadata.get("RequestId")
            state = classification(code)
        end = self.now()
        record = {
            "probe_id": rid,
            "service": service,
            "operation": op,
            "start": start,
            "end": end,
            "utc_start": utc(w),
            "utc_end": utc(self.wall()),
            "state": state,
            "error_code": code,
            "request_id": reqid,
            "cycle": self.cycle,
        }
        self.j["events"].append({"event": "request", **record})
        return value, record

    def must(self, service, op, params):
        v, r = self.request(service, op, params)
        if r["state"] != ALLOW:
            raise StopRun(op + ": " + str(r["error_code"]))
        return v, r

    def policy_doc(self, policies):
        return {
            "Version": "2012-10-17",
            "Statement": [s for p in policies for s in p["Statement"]],
        }

    def set_policies(self, role, policies):
        if policies:
            self.must(
                "iam",
                "put_role_policy",
                {
                    "RoleName": role,
                    "PolicyName": "ep2-experiment",
                    "PolicyDocument": json.dumps(self.policy_doc(policies)),
                },
            )
        else:
            v, r = self.request(
                "iam",
                "delete_role_policy",
                {"RoleName": role, "PolicyName": "ep2-experiment"},
            )
            if r["state"] != ALLOW and r["error_code"] != "NoSuchEntity":
                raise StopRun("Policy removal failed")

    def set_trust(self, doc):
        self.must(
            "iam",
            "update_assume_role_policy",
            {"RoleName": self.entry, "PolicyDocument": json.dumps(doc)},
        )
        self.trust_doc = doc

    def prepare(self):
        who, _ = self.must("sts", "get_caller_identity", {})
        if (
            who["Account"] != self.account
            or ":assumed-role/" + self.cfg["controller_role_arn"].split("/")[-1] + "/"
            not in who["Arn"]
        ):
            raise GuardError("Unexpected controller/account")
        # Establish the supported S3 policy/encryption scope before creating roles.
        _, bp = self.request("s3", "get_bucket_policy", {"Bucket": self.bucket})
        if bp["error_code"] != "NoSuchBucketPolicy":
            raise GuardError("Bucket policy must be confirmed absent")
        enc, _ = self.must("s3", "get_bucket_encryption", {"Bucket": self.bucket})
        ownership, _ = self.must(
            "s3", "get_bucket_ownership_controls", {"Bucket": self.bucket}
        )
        public, _ = self.must("s3", "get_public_access_block", {"Bucket": self.bucket})
        if any(
            x["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] != "AES256"
            for x in enc["ServerSideEncryptionConfiguration"]["Rules"]
        ):
            raise GuardError("Only SSE-S3 is in scope")
        if ownership["OwnershipControls"]["Rules"] != [
            {"ObjectOwnership": "BucketOwnerEnforced"}
        ] or not all(public["PublicAccessBlockConfiguration"].values()):
            raise GuardError("Bucket ownership/public-access controls differ")
        # Fresh names only. Never mutate an existing role, even one with our prefix.
        for role, td in [(self.entry, self.strict), (self.chain, self.chaintrust)]:
            _, r = self.request("iam", "get_role", {"RoleName": role})
            if r["error_code"] != "NoSuchEntity":
                raise GuardError("Role is not confirmed absent: " + role)
            self.must(
                "iam",
                "create_role",
                {
                    "RoleName": role,
                    "AssumeRolePolicyDocument": json.dumps(td),
                    "MaxSessionDuration": 3600,
                    "Tags": [
                        {"Key": "EphemeralTrustPhase", "Value": "2"},
                        {"Key": "EphemeralTrustRun", "Value": self.run_id},
                    ],
                },
            )
            self.created.append(role)
        self.set_policies(self.entry, self.base_entry)
        self.key_attempted = True
        self.must(
            "s3",
            "put_object",
            {
                "Bucket": self.bucket,
                "Key": self.key,
                "Body": PAYLOAD,
                "ServerSideEncryption": "AES256",
            },
        )
        self.event("resources_created", entry=self.entry_arn, chain=self.chain_arn)
        # A bounded setup interval; no mechanism outcome is selected here.
        self.sleep(self.protocol["setup_settle_seconds"])
        self.snapshot()
        if (
            not self.last_snapshot["complete"]
            or self.last_snapshot["config"]["scope"] != "supported"
        ):
            raise StopRun(
                "Initial observation is incomplete or outside supported scope"
            )
        self.origin = self.now()
        self.meta["trace_origin"] = self.origin
        self.meta["trace_start_utc"] = utc(self.wall())
        self.meta["status"] = "RUNNING"
        write_json(self.out / "run.json", self.meta)
        self.must(
            "s3",
            "put_object",
            {
                "Bucket": self.bucket,
                "Key": self.prefix + "/ready.json",
                "Body": json.dumps(
                    {
                        "trace_start_utc": self.meta["trace_start_utc"],
                        "entry": self.entry_arn,
                        "key": self.key,
                        "duration": self.protocol["duration"],
                        "run_id": self.run_id,
                    }
                ).encode(),
            },
        )

    def snapshot(self):
        start = self.now()
        complete = True
        scope = "supported"
        roles = {}
        for name, label in ((self.entry, "entry"), (self.chain, "chain")):
            role, r = self.request("iam", "get_role", {"RoleName": name})
            plist, pr = self.request("iam", "list_role_policies", {"RoleName": name})
            attached, ar = self.request(
                "iam", "list_attached_role_policies", {"RoleName": name}
            )
            if not role or not plist or not attached:
                complete = False
                continue
            if (
                set(plist.get("PolicyNames", [])) - {"ep2-experiment"}
                or plist.get("IsTruncated")
                or attached.get("IsTruncated")
                or attached.get("AttachedPolicies")
                or role["Role"].get("PermissionsBoundary")
            ):
                scope = "unsupported"
            policies = []
            for n in plist.get("PolicyNames", []):
                pol, rr = self.request(
                    "iam", "get_role_policy", {"RoleName": name, "PolicyName": n}
                )
                if not pol:
                    complete = False
                else:
                    policies.append(pol["PolicyDocument"])
            roles[label] = {
                "trust": role["Role"]["AssumeRolePolicyDocument"],
                "policies": policies,
            }
        config = {
            "scope": scope,
            "entry_trust": roles.get("entry", {}).get("trust", {}),
            "chain_trust": roles.get("chain", {}).get("trust", {}),
            "entry_policies": roles.get("entry", {}).get("policies", []),
            "chain_policies": roles.get("chain", {}).get("policies", []),
        }
        row = {
            "start": start,
            "end": self.now(),
            "config": config,
            "complete": complete,
        }
        self.j["snapshots"].append(row)
        self.last_snapshot = row
        return row

    def issue(
        self,
        role=None,
        parent=None,
        actor="experiment",
        context=None,
        duration=900,
        purpose="fresh_issuance",
    ):
        role = role or self.entry_arn
        context = context or self.context
        params = {
            "RoleArn": role,
            "RoleSessionName": "ep2-" + uuid.uuid4().hex[:20],
            "DurationSeconds": duration,
        }
        creds = None
        if parent:
            creds = self.sessions[parent]
            op = "assume_role"
        elif role == self.chain_arn:
            op = "assume_role"  # controller verifier, excluded from attacker lineage
        else:
            try:
                token, profile = self.aws.token(context)
            except Exception as e:
                self.last_completion = self.now()
                self.event("oidc_acquisition_failed", error_type=type(e).__name__)
                return None, UNKNOWN
            params["WebIdentityToken"] = token
            op = "assume_role_with_web_identity"
            self.event("oidc_profile", context=context, profile=profile)
        value, r = self.request("sts", op, params, creds)
        sid = None
        if r["state"] == UNKNOWN and actor == "experiment":
            self.meta["credential_ledger_complete"] = False
        if value:
            sid = value["AssumedRoleUser"]["AssumedRoleId"]
            c = value["Credentials"]
            exp = (
                c["Expiration"].timestamp()
                if hasattr(c["Expiration"], "timestamp")
                else epoch(c["Expiration"])
            )
            row = {
                "sid": sid,
                "role": role,
                "context": context,
                "parent": parent,
                "start": r["start"],
                "issued": r["end"],
                "expires": exp - self.wall_start,
                "actor": actor,
                "session_policy": None,
                "revoked": None,
                "request_id": r["request_id"],
                "requested_duration": duration,
            }
            if sid in self.sessions:
                raise StopRun("Session identity collision")
            self.j["sessions"].append(row)
            self.session_rows.append(row)
            self.sessions[sid] = c
        self.last_completion = r["end"]
        self.j["probes"].append(
            {
                **r,
                "kind": "issuance",
                "purpose": purpose,
                "context": context,
                "actor": actor,
                "sid": sid,
                "role": role,
            }
        )
        return sid, r["state"]

    def usable(self, sid, margin=15):
        return bool(
            sid
            and any(
                c["sid"] == sid and c["expires"] > self.now() + margin
                for c in self.session_rows
            )
        )

    def canary(self, sid, episode=None, actor="experiment", context=None):
        if not self.usable(sid, 0):
            return UNKNOWN
        context = context or self.context
        params = {"Bucket": self.bucket, "Key": self.key}
        op = "get_object"
        if self.action == "s3:PutObject":
            op = "put_object"
            params["Body"] = PAYLOAD
            params["ServerSideEncryption"] = "AES256"
        value, r = self.request("s3", op, params, self.sessions[sid])
        verified = False
        if value and op == "get_object":
            try:
                body = value["Body"]
                payload = body.read()
                body.close()
                verified = hashlib.sha256(payload).hexdigest() == PAYLOAD_HASH
            except Exception:
                verified = False
        elif value and op == "put_object":
            verified = (
                value.get("ETag", "").strip('"') == hashlib.md5(PAYLOAD).hexdigest()
            )
        r["end"] = self.now()
        r["utc_end"] = utc(self.wall())
        self.last_completion = r["end"]
        self.j["probes"].append(
            {
                **r,
                "kind": "canary",
                "sid": sid,
                "actor": actor,
                "context": context,
                "action": self.action,
                "resource": self.resource,
                "episode": episode,
                "payload_verified": verified,
            }
        )
        return r["state"] if r["state"] != ALLOW or verified else UNKNOWN

    def expect(self, name, expected, purpose):
        self.pending.append(
            {
                "name": name,
                "expected": expected,
                "purpose": purpose,
                "ack": self.now(),
                "streak": 0,
                "completions": [],
            }
        )

    def confirmations(self, states):
        for item in list(self.pending):
            if item not in self.pending:
                continue
            state, completion = states.get(item["purpose"], (UNKNOWN, self.now()))
            if 0 <= completion - item["ack"] <= self.protocol["confirmation_seconds"]:
                item["streak"] = item["streak"] + 1 if state == item["expected"] else 0
                if state == item["expected"]:
                    item["completions"].append(completion)
                if item["streak"] >= 3:
                    self.event(
                        "transition",
                        name=item["name"],
                        status="CONFIRMED",
                        ack=item["ack"],
                        completions=item["completions"],
                    )
                    self.completed.append(item["name"])
                    self.pending.remove(item)
            if (
                item in self.pending
                and self.now() - item["ack"] > self.protocol["confirmation_seconds"]
            ):
                self.event(
                    "transition",
                    name=item["name"],
                    status="UNCONFIRMED_WITHIN_300_SECONDS",
                    ack=item["ack"],
                    late_state=state,
                    completions=item["completions"],
                )
                self.pending.remove(item)
                self.restore_baseline()
                self.abort_mechanism = True
                for other in self.pending:
                    self.event(
                        "transition",
                        name=other["name"],
                        status="ABORTED_WITH_RESTORATION",
                    )
                self.pending.clear()

    def restore_baseline(self):
        self.set_trust(self.strict)
        self.set_policies(self.entry, self.base_entry)
        self.set_policies(self.chain, [])
        self.entry_policies = list(self.base_entry)
        self.chain_policies = []
        self.event("baseline_restore_acknowledged")

    def mutate(self, name):
        if name == "issue_old":
            self.old, state = self.issue(duration=1800, purpose="old_session")
            if not self.old:
                raise StopRun(
                    "Old-session issuance failed; reference mechanism unavailable"
                )
        elif name == "grant_cap":
            self.entry_policies = self.base_entry + [
                identity(self.action, self.resource)
            ]
            self.set_policies(self.entry, self.entry_policies)
            self.expect(name, ALLOW, "canary")
        elif name == "revoke_cap":
            self.set_policies(self.entry, self.base_entry)
            self.entry_policies = list(self.base_entry)
            self.expect(name, DENY, "canary")
        elif name == "block_trust":
            self.set_trust(self.blocked)
            self.expect(name, DENY, "issuance")
        elif name == "restore_trust":
            self.set_trust(self.strict)
            self.expect(name, ALLOW, "issuance")
        elif name == "grant_chain":
            self.entry_policies = self.base_entry + [
                identity("sts:AssumeRole", self.chain_arn)
            ]
            self.set_policies(self.entry, self.entry_policies)
            self.expect(name, ALLOW, "chain")
        elif name == "remove_chain":
            self.entry_policies = list(self.base_entry)
            self.set_policies(self.entry, self.entry_policies)
            self.expect(name, DENY, "chain")
        elif name == "grant_chain_cap":
            if self.scenario == "s5":
                cs = [
                    x
                    for x in self.session_rows
                    if x["role"] == self.chain_arn and x["actor"] == "experiment"
                ]
                expiry = max([x["expires"] for x in cs], default=float("inf"))
                passed = (
                    bool(cs)
                    and expiry + 30 < self.origin + 3600
                    and "remove_chain" in self.completed
                )
                self.event(
                    "s5_phase2_gate",
                    passed=passed,
                    latest_experiment_expiry=expiry if cs else None,
                )
                if not passed:
                    raise StopRun(
                        "S5 expiry separation is unestablished; phase 2 prohibited"
                    )
            self.chain_policies = [identity("s3:GetObject", self.resource)]
            self.set_policies(self.chain, self.chain_policies)
            self.expect(name, ALLOW, "verifier" if self.scenario == "s5" else "canary")
        elif name == "remove_chain_cap":
            self.chain_policies = []
            self.set_policies(self.chain, [])
            self.expect(name, DENY, "verifier" if self.scenario == "s5" else "canary")
        elif name == "broad_trust":
            broad = trust(self.cfg["provider_arn"], self.cfg["subjects"]["main"])
            broad["Statement"][0]["Condition"]["StringEquals"][
                "token.actions.githubusercontent.com:sub"
            ] = list(self.cfg["subjects"].values())
            self.set_trust(broad)
            self.expect(name, ALLOW, "issuance")
        elif name == "strict_trust":
            self.set_trust(self.strict)
            self.expect(name, DENY, "issuance")
        else:
            raise StopRun("Unknown scheduled mutation: " + name)
        self.event(
            "scheduled_mutation", name=name, actual_trace_time=self.now() - self.origin
        )

    def tick(self, t):
        states = {}
        sid, state = self.issue()
        states["issuance"] = (state, self.last_completion)
        if self.scenario in ("s4", "s5"):
            chain = None
            chstate = UNKNOWN
            if sid:
                chain, chstate = self.issue(
                    self.chain_arn, sid, purpose="chain_issuance"
                )
            states["chain"] = (chstate, self.last_completion)
            if chain:
                self.child = chain
            if self.usable(self.child):
                state = self.canary(
                    self.child, "chain" if self.scenario == "s4" else None
                )
                states["canary"] = (state, self.last_completion)
            if self.scenario == "s5" and 3600 <= t < 4500:
                if not self.usable(self.verifier, 120):
                    self.verifier, _ = self.issue(
                        self.chain_arn,
                        actor="verifier",
                        context="verifier",
                        purpose="independent_verifier",
                    )
                if self.verifier:
                    state = self.canary(
                        self.verifier, actor="verifier", context="verifier"
                    )
                    states["verifier"] = (state, self.last_completion)
        elif self.scenario == "s3":
            if self.usable(self.old, 0):
                state = self.canary(self.old, "persistence")
                states["canary"] = (state, self.last_completion)
            elif sid and t < 1740:
                state = self.canary(sid)
                states["canary"] = (state, self.last_completion)
        else:
            if sid:
                state = self.canary(
                    sid,
                    {"s1": "control", "s2": "temporary", "s6": "alternate"}[
                        self.scenario
                    ],
                )
                states["canary"] = (state, self.last_completion)
        if t < 600:
            self.baseline_history.append({k: v[0] for k, v in states.items()})
            self.baseline_history = self.baseline_history[-3:]
        elif not self.baseline_passed:
            required = {"issuance": DENY if self.scenario == "s6" else ALLOW}
            if self.scenario in ("s1", "s2", "s3"):
                required["canary"] = DENY if self.scenario == "s2" else ALLOW
            if self.scenario in ("s4", "s5"):
                required["chain"] = DENY
            self.baseline_passed = len(self.baseline_history) == 3 and all(
                all(x.get(k) == v for k, v in required.items())
                for x in self.baseline_history
            )
            self.event("baseline_gate", passed=self.baseline_passed)
            if not self.baseline_passed:
                raise StopRun("Baseline behavior not established before intervention")
        self.confirmations(states)

    def restoration_check(self):
        # Separate follow-up clock. It cannot repair an in-trace deadline failure.
        begin = self.now()
        streak = 0
        while self.now() - begin <= 300:
            self.cycle += 1
            self.snapshot()
            sid, st = self.issue(purpose="restoration")
            expected = DENY if self.scenario == "s6" else ALLOW
            config = self.last_snapshot["config"]
            strict = (
                config["entry_trust"] == self.strict
                and config["entry_policies"] == self.base_entry
                and not config["chain_policies"]
            )
            # Policy documents are normalized in snapshot() into a one-document list.
            if self.base_entry:
                strict = (
                    config["entry_trust"] == self.strict
                    and config["entry_policies"] == [self.policy_doc(self.base_entry)]
                    and not config["chain_policies"]
                )
            ok = st == expected and strict and self.last_snapshot["complete"]
            if self.scenario in ("s2", "s4", "s5") and sid:
                if self.scenario == "s2":
                    ok &= self.canary(sid) == DENY
                else:
                    child, state = self.issue(
                        self.chain_arn, sid, purpose="restoration_chain"
                    )
                    ok &= state == DENY
            elif self.scenario in ("s1", "s3") and sid:
                ok &= self.canary(sid) == ALLOW
            if self.now() - begin > 300:
                break
            streak = streak + 1 if ok else 0
            if streak >= 3:
                return "CONFIRMED"
            self.sleep(10)
        return "UNKNOWN"

    def cleanup(self):
        results = {}
        for role in reversed(self.created):
            results[role] = False
            for attempt in range(6):
                try:
                    self.set_policies(role, [])
                    _, r = self.request("iam", "delete_role", {"RoleName": role})
                    if r["state"] == ALLOW or r["error_code"] == "NoSuchEntity":
                        results[role] = True
                        break
                except Exception:
                    pass
                self.sleep(2)
        for key in (
            (self.key, self.prefix + "/ready.json") if self.key_attempted else ()
        ):
            _, r = self.request(
                "s3", "delete_object", {"Bucket": self.bucket, "Key": key}
            )
            results[key] = r["state"] == ALLOW
            value, check = self.request(
                "s3", "get_object", {"Bucket": self.bucket, "Key": key}
            )
            if value and "Body" in value:
                value["Body"].close()
            results[key] = results[key] and check["error_code"] == "NoSuchKey"
        for role in self.created:
            _, r = self.request("iam", "get_role", {"RoleName": role})
            results[role] = (
                results.get(role, False) and r["error_code"] == "NoSuchEntity"
            )
        self.event("cleanup", results=results)
        return all(results.values())

    def run(self):
        status = "FAILED_INSTRUMENT"
        restoration = "NOT_STARTED"
        cleanup = False
        try:
            self.prepare()
            schedule = list(self.protocol["schedules"][self.scenario])
            done = set()
            next_tick = 0.0
            duration = self.protocol["duration"]
            while True:
                t = self.now() - self.origin
                if t >= duration:
                    break
                for at, name in schedule:
                    if t >= at and name not in done:
                        done.add(name)
                        if self.abort_mechanism:
                            self.event(
                                "scheduled_mutation_skipped",
                                name=name,
                                reason="primary_transition_unconfirmed",
                            )
                        elif t - at > self.protocol["max_schedule_lateness"]:
                            raise StopRun("Scheduled mutation late: " + name)
                        else:
                            self.mutate(name)
                self.cycle += 1
                self.snapshot()
                self.tick(self.now() - self.origin)
                next_tick += self.protocol["tick_seconds"]
                if next_tick < self.now() - self.origin:
                    missed = (
                        int(
                            (self.now() - self.origin - next_tick)
                            // self.protocol["tick_seconds"]
                        )
                        + 1
                    )
                    next_tick += missed * self.protocol["tick_seconds"]
                    self.event("skipped_ticks", count=missed)
                wait = min(next_tick, duration) - (self.now() - self.origin)
                if wait > 0:
                    self.sleep(wait)
            status = "TRACE_COMPLETE"
            self.meta["duration"] = self.now() - self.origin
        except BaseException as e:
            self.meta["failure_type"] = type(e).__name__
            self.meta["failure_reason"] = (
                str(e)
                if isinstance(e, (StopRun, GuardError))
                else "See structured events; raw exception text suppressed"
            )
            self.event("run_stopped", error_type=type(e).__name__)
            self.meta["duration"] = max(0, self.now() - self.origin)
        finally:
            if self.created:
                try:
                    self.restore_baseline()
                    restoration = self.restoration_check()
                except BaseException:
                    restoration = "UNKNOWN"
            try:
                cleanup = self.cleanup()
            except BaseException:
                cleanup = False
            self.meta.update(
                status=status,
                restoration=restoration,
                cleanup_confirmed=cleanup,
                trace_end_utc=utc(
                    self.wall_start + self.origin + self.meta["duration"]
                ),
                finished_utc=utc(self.wall()),
                transition_confirmed=self.completed,
                mechanism_aborted=self.abort_mechanism,
                clock_check=getattr(self.aws, "last_clock_check", None),
            )
            write_json(self.out / "run.json", self.meta)
            for j in self.j.values():
                j.close()
            seal_run(self.out)
        return self.meta
