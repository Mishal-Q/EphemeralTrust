import hashlib, json, math, os, re
from pathlib import Path
from datetime import datetime, timezone


class InvalidEvidence(ValueError):
    pass


class GuardError(RuntimeError):
    pass


def canonical(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(x):
    return hashlib.sha256(canonical(x).encode()).hexdigest()


def read_json(p):
    return json.loads(Path(p).read_text())


def write_json(p, x):
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(x, indent=2, sort_keys=True, allow_nan=False) + "\n")
    os.replace(tmp, p)


def read_lines(p):
    p = Path(p)
    if not p.exists():
        raise InvalidEvidence("Missing evidence stream: " + str(p))
    rows = []
    for i, line in enumerate(p.read_text().splitlines(), 1):
        if line.strip():
            try:
                rows.append(json.loads(line))
            except Exception as e:
                raise InvalidEvidence(f"{p.name}: corrupt/truncated line {i}") from e
    return rows


def utc(epoch):
    return (
        datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")
    )


def epoch(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def finite(x):
    if not isinstance(x, (int, float)) or isinstance(x, bool) or not math.isfinite(x):
        raise InvalidEvidence("Nonfinite time")
    return float(x)


SECRET_KEYS = {
    "accesskeyid",
    "secretaccesskey",
    "sessiontoken",
    "webidentitytoken",
    "authorization",
    "password",
    "aws_secret_access_key",
    "aws_session_token",
}


def no_secrets(x):
    if isinstance(x, dict):
        for k, v in x.items():
            if k.lower() in SECRET_KEYS:
                raise InvalidEvidence("Secret field rejected: " + k)
            no_secrets(v)
    elif isinstance(x, (list, tuple)):
        for v in x:
            no_secrets(v)
    elif isinstance(x, str):
        if re.search(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", x) or re.search(
            r"eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", x
        ):
            raise InvalidEvidence("Raw credential/token rejected")


class Journal:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.f = self.path.open("x", encoding="utf-8")

    def append(self, row):
        no_secrets(row)
        self.f.write(canonical(row) + "\n")
        self.f.flush()
        os.fsync(self.f.fileno())

    def close(self):
        self.f.close()


def seal_run(path):
    p = Path(path)
    files = {
        f.name: hashlib.sha256(f.read_bytes()).hexdigest()
        for f in sorted(p.iterdir())
        if f.is_file() and f.name != "SHA256.json"
    }
    write_json(p / "SHA256.json", files)


def verify_run(path):
    p = Path(path)
    checks = read_json(p / "SHA256.json")
    for n, h in checks.items():
        if Path(n).name != n or hashlib.sha256((p / n).read_bytes()).hexdigest() != h:
            raise InvalidEvidence("Run integrity failed: " + n)
    for n in (
        "run.json",
        "snapshots.jsonl",
        "sessions.jsonl",
        "probes.jsonl",
        "events.jsonl",
    ):
        if n not in checks:
            raise InvalidEvidence("Unsealed required stream: " + n)
    return checks
