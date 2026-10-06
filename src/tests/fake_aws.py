"""Explicit simulation transport. No network, credentials or AWS SDK required."""

import io, json, hashlib
from datetime import datetime, timezone


class FakeError(Exception):
    def __init__(self, code):
        self.response = {
            "Error": {"Code": code},
            "ResponseMetadata": {"RequestId": "fake-error"},
        }


class Clock:
    def __init__(self):
        self.t = 0

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s

    def wall(self):
        return 1800000000 + self.t


class FakeAWS:
    def __init__(self, cfg, clock):
        self.cfg = cfg
        self.clock = clock
        self.roles = {}
        self.objects = {}
        self.ids = 0
        self.creds = {}
        self.calls = []
        self.last_clock_check = {"skew_seconds": 0, "simulation": True}
        self.fail_operation = None

    def token(self, context):
        return "SIMULATED:" + context, {
            "sub": self.cfg["subjects"][context],
            "simulation": True,
        }

    def call(self, service, op, p, credentials=None):
        self.clock.sleep(0.001)
        self.calls.append((service, op))
        self.ids += 1
        r = {"ResponseMetadata": {"RequestId": "fake-" + str(self.ids)}}
        if op == self.fail_operation:
            raise FakeError("ThrottlingException")
        role = p.get("RoleName")
        action = p.get("RoleArn", "").split("/")[-1]
        if op == "get_bucket_policy":
            raise FakeError("NoSuchBucketPolicy")
        if op == "get_bucket_encryption":
            return {
                **r,
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256"
                            }
                        }
                    ]
                },
            }
        if op == "get_bucket_ownership_controls":
            return {
                **r,
                "OwnershipControls": {
                    "Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]
                },
            }
        if op == "get_public_access_block":
            return {
                **r,
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "BlockPublicPolicy": True,
                    "IgnorePublicAcls": True,
                    "RestrictPublicBuckets": True,
                },
            }
        if op == "get_caller_identity":
            return {
                **r,
                "Account": self.cfg["account_id"],
                "Arn": "arn:aws:sts::"
                + self.cfg["account_id"]
                + ":assumed-role/"
                + self.cfg["controller_role_arn"].split("/")[-1]
                + "/fake",
            }
        if op == "create_role":
            if role in self.roles:
                raise FakeError("EntityAlreadyExists")
            self.roles[role] = {
                "trust": json.loads(p["AssumeRolePolicyDocument"]),
                "policies": {},
            }
            return r
        if op in {
            "get_role",
            "list_role_policies",
            "list_attached_role_policies",
            "get_role_policy",
            "put_role_policy",
            "delete_role_policy",
            "update_assume_role_policy",
            "delete_role",
        }:
            if role not in self.roles:
                raise FakeError("NoSuchEntity")
            rr = self.roles[role]
            if op == "get_role":
                return {**r, "Role": {"AssumeRolePolicyDocument": rr["trust"]}}
            if op == "list_role_policies":
                return {**r, "PolicyNames": list(rr["policies"])}
            if op == "list_attached_role_policies":
                return {**r, "AttachedPolicies": []}
            if op == "get_role_policy":
                return {**r, "PolicyDocument": rr["policies"][p["PolicyName"]]}
            if op == "put_role_policy":
                rr["policies"][p["PolicyName"]] = json.loads(p["PolicyDocument"])
                return r
            if op == "delete_role_policy":
                if p["PolicyName"] not in rr["policies"]:
                    raise FakeError("NoSuchEntity")
                del rr["policies"][p["PolicyName"]]
                return r
            if op == "update_assume_role_policy":
                rr["trust"] = json.loads(p["PolicyDocument"])
                return r
            if op == "delete_role":
                del self.roles[role]
                return r
        if op in {"assume_role_with_web_identity", "assume_role"}:
            if action not in self.roles:
                raise FakeError("AccessDenied")
            if op == "assume_role_with_web_identity":
                ctx = p["WebIdentityToken"].split(":")[1]
                sub = self.cfg["subjects"][ctx]
                values = self.roles[action]["trust"]["Statement"][0]["Condition"][
                    "StringEquals"
                ]["token.actions.githubusercontent.com:sub"]
                values = [values] if isinstance(values, str) else values
                if sub not in values:
                    raise FakeError("AccessDenied")
            elif credentials:
                self.valid(credentials)
                if not self.allowed(
                    credentials["role"], "sts:AssumeRole", p["RoleArn"]
                ):
                    raise FakeError("AccessDenied")
            sid = "fake-session-" + str(self.ids)
            c = {
                "AccessKeyId": "FAKEKEY" + str(self.ids),
                "SecretAccessKey": "fake-secret",
                "SessionToken": "fake-session-token",
                "Expiration": datetime.fromtimestamp(
                    self.clock.wall() + p["DurationSeconds"], timezone.utc
                ),
                "role": action,
            }
            self.creds[sid] = c
            return {
                **r,
                "Credentials": c,
                "AssumedRoleUser": {
                    "AssumedRoleId": sid,
                    "Arn": "arn:aws:sts::"
                    + self.cfg["account_id"]
                    + ":assumed-role/"
                    + action
                    + "/fake",
                },
            }
        if op in {"get_object", "put_object", "delete_object"}:
            k = (p["Bucket"], p["Key"])
            if credentials:
                self.valid(credentials)
                act = {
                    "get_object": "s3:GetObject",
                    "put_object": "s3:PutObject",
                    "delete_object": "s3:DeleteObject",
                }[op]
                if not self.allowed(
                    credentials["role"],
                    act,
                    "arn:aws:s3:::" + p["Bucket"] + "/" + p["Key"],
                ):
                    raise FakeError("AccessDenied")
            if op == "put_object":
                self.objects[k] = p["Body"]
                return {**r, "ETag": '"' + hashlib.md5(p["Body"]).hexdigest() + '"'}
            if op == "delete_object":
                self.objects.pop(k, None)
                return r
            if k not in self.objects:
                raise FakeError("NoSuchKey")
            return {**r, "Body": io.BytesIO(self.objects[k])}
        raise NotImplementedError(op)

    def valid(self, c):
        if self.clock.wall() >= c["Expiration"].timestamp():
            raise FakeError("ExpiredToken")

    def allowed(self, role, action, resource):
        # Independent exact-match simulation: does not call analysis/iam evaluator.
        statements = [
            s
            for p in self.roles.get(role, {}).get("policies", {}).values()
            for s in p["Statement"]
        ]
        relevant = [
            s
            for s in statements
            if action
            in ([s["Action"]] if isinstance(s["Action"], str) else s["Action"])
            and s["Resource"] == resource
        ]
        return bool(
            any(s["Effect"] == "Allow" for s in relevant)
            and not any(s["Effect"] == "Deny" for s in relevant)
        )
