"""Honeytoken minting.

Produces decoys that look real enough to lure an attacker, with each token
carrying an opaque ID we can recognize when it shows up in our logs.
None of these are valid credentials — they share *shape* but not content.
"""
from __future__ import annotations
import secrets
import string
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Literal

TokenKind = Literal["aws_key", "github_pat", "stripe_key", "url", "doc"]


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _token_id(prefix: str = "ht") -> str:
    """16-char opaque ID. Embedded in every token so we can identify it on trigger."""
    return f"{prefix}_{secrets.token_urlsafe(12).rstrip('=')}"


@dataclass
class Honeytoken:
    """A single honeytoken record."""
    token_id: str
    kind: TokenKind
    value: str
    placement_hint: str   # where the operator was told to place it
    created_at: str
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# ---------- minters ----------

def mint_aws_key(placement_hint: str = "~/.aws/credentials") -> Honeytoken:
    """Looks like an AWS access-key pair. The key ID prefix 'AKIA' is real;
    everything after it is random — so it's syntactically valid but bound
    to no account."""
    tid = _token_id("aws")
    # AKIA + 16 alphanum chars = 20-char ID (matches real AWS shape)
    body = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    access_key = "AKIA" + body
    # secret access key is 40 chars base64-ish
    secret = secrets.token_urlsafe(30)[:40]
    value = f"aws_access_key_id = {access_key}\naws_secret_access_key = {secret}"
    return Honeytoken(
        token_id=tid, kind="aws_key", value=value,
        placement_hint=placement_hint, created_at=_utcnow_iso(),
        metadata={"access_key": access_key, "fingerprint": _fingerprint(access_key)},
    )


def mint_github_pat(placement_hint: str = "scripts/deploy.sh comment") -> Honeytoken:
    """Looks like a GitHub fine-grained PAT (`github_pat_*`)."""
    tid = _token_id("ghp")
    suffix = secrets.token_urlsafe(60).replace("-", "A").replace("_", "B")[:82]
    value = "github_pat_11AAAA" + suffix
    return Honeytoken(
        token_id=tid, kind="github_pat", value=value,
        placement_hint=placement_hint, created_at=_utcnow_iso(),
        metadata={"fingerprint": _fingerprint(value)},
    )


def mint_stripe_key(placement_hint: str = ".env, STRIPE_LIVE_KEY") -> Honeytoken:
    """Looks like a Stripe live secret key (`sk_live_*`)."""
    tid = _token_id("stp")
    body = secrets.token_urlsafe(20).replace("-", "X").replace("_", "Y")[:24]
    value = "sk_live_" + body
    return Honeytoken(
        token_id=tid, kind="stripe_key", value=value,
        placement_hint=placement_hint, created_at=_utcnow_iso(),
        metadata={"fingerprint": _fingerprint(value)},
    )


def mint_canary_url(base_url: str, placement_hint: str = "internal wiki page") -> Honeytoken:
    """A URL that hits our listener when anyone fetches it.
    The token_id is embedded as a path segment, so we know which token tripped."""
    tid = _token_id("url")
    base = base_url.rstrip("/")
    value = f"{base}/c/{tid}"
    return Honeytoken(
        token_id=tid, kind="url", value=value,
        placement_hint=placement_hint, created_at=_utcnow_iso(),
    )


def mint_decoy_doc(
    filename: str = "Q4_Salaries_FINAL.docx",
    placement_hint: str = "shared drive, top level",
) -> Honeytoken:
    """A 'decoy document' record. The actual document is built separately
    by the docgen utility — this just registers the watermark token."""
    tid = _token_id("doc")
    return Honeytoken(
        token_id=tid, kind="doc", value=filename,
        placement_hint=placement_hint, created_at=_utcnow_iso(),
        metadata={"watermark": tid},
    )


def _fingerprint(s: str) -> str:
    """Short SHA-256 prefix — used for quick exact-match lookups in logs."""
    return hashlib.sha256(s.encode()).hexdigest()[:12]


# ---------- detection ----------

def detect_in_text(text: str, registry: list[Honeytoken]) -> list[Honeytoken]:
    """Scan a blob of text (e.g. a log line, a pasted commit diff) for any
    of our minted tokens. Returns the matching Honeytoken records."""
    hits: list[Honeytoken] = []
    for t in registry:
        # detect by exact value (covers aws/github/stripe/url verbatim)
        if t.value and t.value in text:
            hits.append(t)
            continue
        # detect by access_key (shorter substring, useful for aws)
        ak = t.metadata.get("access_key")
        if ak and ak in text:
            hits.append(t)
            continue
        # detect by token_id (covers URL hits we built ourselves)
        if t.token_id in text:
            hits.append(t)
    return hits
