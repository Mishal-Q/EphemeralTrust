"""Live-only transport. boto3 is imported only when explicitly constructed."""

import base64, json, os, time, hashlib
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from urllib.request import Request, urlopen
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from .common import GuardError

DENIAL_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}


def classification(code):
    return "DENY" if code in DENIAL_CODES else "UNKNOWN"


def github_token(expected_sub, repository):
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    auth = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not auth:
        raise GuardError(
            "Live runner must execute in GitHub Actions with id-token: write"
        )
    p = urlsplit(url)
    if p.scheme != "https":
        raise GuardError("OIDC endpoint must use HTTPS")
    q = dict(parse_qsl(p.query))
    q["audience"] = "sts.amazonaws.com"
    req = Request(
        urlunsplit((p.scheme, p.netloc, p.path, urlencode(q), p.fragment)),
        headers={"Authorization": "bearer " + auth},
    )
    with urlopen(req, timeout=20) as r:
        token = json.load(r)["value"]
    try:
        claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "==="))
    except Exception as e:
        raise GuardError("Invalid OIDC token shape") from e
    # Signature/authenticity is verified by AWS STS; these checks constrain intent.
    if (
        claims.get("iss") != "https://token.actions.githubusercontent.com"
        or claims.get("aud") != "sts.amazonaws.com"
        or (expected_sub is not None and claims.get("sub") != expected_sub)
        or claims.get("repository") != repository
    ):
        raise GuardError("OIDC claims do not match configured context")
    if os.environ.get("GITHUB_SHA") and claims.get("sha") != os.environ["GITHUB_SHA"]:
        raise GuardError("OIDC SHA differs from the checked-out workflow SHA")
    if claims.get("exp", 0) <= time.time() + 30:
        raise GuardError("OIDC token is about to expire")
    safe = {
        k: claims.get(k)
        for k in (
            "iss",
            "aud",
            "sub",
            "repository",
            "ref",
            "sha",
            "job_workflow_ref",
            "environment",
            "iat",
            "exp",
        )
    }
    safe["token_sha256"] = hashlib.sha256(token.encode()).hexdigest()
    return token, safe


class AWS:
    def __init__(self, cfg, context):
        import boto3
        from botocore.config import Config

        self.boto3 = boto3
        self.botoconfig = Config(
            region_name=cfg["region"],
            connect_timeout=5,
            read_timeout=10,
            retries={"total_max_attempts": 1},
            s3={"addressing_style": "path"},
        )
        self.cfg = cfg
        self.context = context
        self.controller = None
        self.expiry = 0
        self.last_clock_check = None

    def client(self, service, credentials=None):
        if credentials is None:
            self.refresh()
            credentials = self.controller
        kw = {}
        if credentials:
            kw = {
                "aws_access_key_id": credentials["AccessKeyId"],
                "aws_secret_access_key": credentials["SecretAccessKey"],
                "aws_session_token": credentials["SessionToken"],
            }
        return self.boto3.client(service, config=self.botoconfig, **kw)

    def refresh(self):
        if self.controller and time.time() < self.expiry - 300:
            return
        token, _ = github_token(
            self.cfg["subjects"][self.context], self.cfg["repository"]
        )
        from botocore import UNSIGNED
        from botocore.config import Config

        sts = self.boto3.client(
            "sts",
            region_name=self.cfg["region"],
            config=Config(
                signature_version=UNSIGNED,
                connect_timeout=5,
                read_timeout=10,
                retries={"total_max_attempts": 1},
            ),
        )
        start = time.time()
        r = sts.assume_role_with_web_identity(
            RoleArn=self.cfg["controller_role_arn"],
            RoleSessionName="ep2-controller-"
            + os.environ.get("GITHUB_RUN_ID", "local"),
            WebIdentityToken=token,
            DurationSeconds=3600,
        )
        end = time.time()
        server = r.get("ResponseMetadata", {}).get("HTTPHeaders", {}).get("date")
        if not server:
            raise GuardError("STS server date unavailable; clock cannot be verified")
        skew = parsedate_to_datetime(server).timestamp() - (start + end) / 2
        if abs(skew) > 5:
            raise GuardError("Clock skew exceeds five seconds")
        self.last_clock_check = {
            "skew_seconds": skew,
            "roundtrip_seconds": end - start,
            "checked_at_epoch": end,
        }
        self.controller = r["Credentials"]
        self.expiry = r["Credentials"]["Expiration"].timestamp()

    def call(self, service, operation, params, credentials=None):
        return getattr(self.client(service, credentials), operation)(**params)

    def token(self, context):
        return github_token(self.cfg["subjects"][context], self.cfg["repository"])
