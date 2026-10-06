"""Conservative supported subset, not an AWS IAM simulator.
Only exact same-account root+ArnEquals chain delegation is certified here.
Unsupported syntax or external policy layers yields UNKNOWN, never DENY.
"""

from fnmatch import fnmatchcase

ALLOW = "ALLOW"
DENY = "DENY"
UNKNOWN = "UNKNOWN"
ACTIONS = {
    "sts:AssumeRoleWithWebIdentity",
    "sts:AssumeRole",
    "s3:GetObject",
    "s3:PutObject",
}


def strings(x):
    if isinstance(x, str):
        return [x]
    if isinstance(x, list) and all(isinstance(a, str) for a in x):
        return x
    raise ValueError("Expected string or string list")


def evaluate(policies, action, resource, context, principal=None):
    if action not in ACTIONS:
        return UNKNOWN
    allowed = False
    denied = False
    uncertain = False
    for policy in policies:
        try:
            if not isinstance(policy, dict) or set(policy) - {
                "Version",
                "Statement",
                "Id",
            }:
                raise ValueError()
            ss = policy["Statement"]
            ss = [ss] if isinstance(ss, dict) else ss
            if not isinstance(ss, list):
                raise ValueError()
            for s in ss:
                if set(s) - {
                    "Sid",
                    "Effect",
                    "Action",
                    "Resource",
                    "Principal",
                    "Condition",
                }:
                    raise ValueError()
                if s.get("Effect") not in {"Allow", "Deny"}:
                    raise ValueError()
                acts = strings(s["Action"])
                if any(a not in ACTIONS for a in acts):
                    raise ValueError()
                if principal is None:
                    if "Principal" in s:
                        raise ValueError()
                    resources = strings(s["Resource"])
                else:
                    if "Resource" in s:
                        raise ValueError()
                    resources = ["*"]
                    p = s.get("Principal")
                    if not isinstance(p, dict) or set(p) != {principal[0]}:
                        raise ValueError()
                    ps = strings(p[principal[0]])
                    if any("*" in x or "?" in x for x in ps):
                        raise ValueError()
                cond = s.get("Condition", {})
                if not isinstance(cond, dict):
                    raise ValueError()
                for op, block in cond.items():
                    if op not in {
                        "StringEquals",
                        "StringLike",
                        "ArnEquals",
                    } or not isinstance(block, dict):
                        raise ValueError()
                    if set(block) - {
                        "token.actions.githubusercontent.com:sub",
                        "token.actions.githubusercontent.com:aud",
                        "aws:PrincipalArn",
                    }:
                        raise ValueError()
                    for values in block.values():
                        strings(values)
                if action not in acts:
                    continue
                if principal is not None and principal[1] not in ps:
                    continue
                if not any(fnmatchcase(resource, r) for r in resources):
                    continue
                match = True
                for op, block in cond.items():
                    for key, values in block.items():
                        if key not in context:
                            uncertain = True
                            match = False
                            continue
                        match &= any(
                            (
                                fnmatchcase(context[key], v)
                                if op == "StringLike"
                                else context[key] == v
                            )
                            for v in strings(values)
                        )
                if match:
                    denied |= s["Effect"] == "Deny"
                    allowed |= s["Effect"] == "Allow"
        except (KeyError, ValueError, TypeError):
            uncertain = True
    if denied:
        return DENY
    if uncertain:
        return UNKNOWN
    return ALLOW if allowed else DENY


def combine(*states):
    if DENY in states:
        return DENY
    if UNKNOWN in states:
        return UNKNOWN
    return ALLOW


def trust(provider, subject):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": provider},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                        "token.actions.githubusercontent.com:sub": subject,
                    }
                },
            }
        ],
    }


def identity(action, resource):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": action, "Resource": resource}],
    }


def chain_trust(account, entry, controller):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::" + account + ":root"},
                "Action": "sts:AssumeRole",
                "Condition": {"ArnEquals": {"aws:PrincipalArn": [entry, controller]}},
            }
        ],
    }
