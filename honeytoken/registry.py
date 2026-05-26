"""On-disk JSON registry of minted honeytokens + trigger events."""
from __future__ import annotations
import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .tokens import Honeytoken


@dataclass
class TriggerEvent:
    """Something fetched / used / leaked one of our tokens."""
    token_id: str
    timestamp: str
    source_ip: Optional[str]
    user_agent: Optional[str]
    note: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class Snapshot:
    tokens: list[Honeytoken] = field(default_factory=list)
    events: list[TriggerEvent] = field(default_factory=list)


class Registry:
    """Append-mostly registry. Atomic writes (write+rename) so concurrent
    readers always see a consistent snapshot."""

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self._snap: Snapshot = Snapshot()
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        raw = json.loads(self.path.read_text() or "{}")
        toks = [Honeytoken(**t) for t in raw.get("tokens", [])]
        events = [TriggerEvent(**e) for e in raw.get("events", [])]
        self._snap = Snapshot(tokens=toks, events=events)

    def _save(self) -> None:
        # atomic write: tmp file + rename
        payload = {
            "tokens": [t.to_dict() for t in self._snap.tokens],
            "events": [asdict(e) for e in self._snap.events],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            prefix=".registry-", suffix=".json", dir=str(self.path.parent)
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(payload, f, indent=2)
            os.replace(tmp_path, self.path)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    # --- queries ---
    @property
    def tokens(self) -> list[Honeytoken]:
        return list(self._snap.tokens)

    @property
    def events(self) -> list[TriggerEvent]:
        return list(self._snap.events)

    def get(self, token_id: str) -> Optional[Honeytoken]:
        for t in self._snap.tokens:
            if t.token_id == token_id:
                return t
        return None

    # --- mutations ---
    def add_token(self, token: Honeytoken) -> None:
        if self.get(token.token_id) is not None:
            raise ValueError(f"duplicate token_id {token.token_id!r}")
        self._snap.tokens.append(token)
        self._save()

    def record_trigger(
        self, token_id: str, source_ip: Optional[str] = None,
        user_agent: Optional[str] = None, note: str = "", extra: Optional[dict] = None,
    ) -> TriggerEvent:
        if self.get(token_id) is None:
            raise KeyError(f"unknown token_id {token_id!r}")
        evt = TriggerEvent(
            token_id=token_id,
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            source_ip=source_ip,
            user_agent=user_agent,
            note=note,
            extra=extra or {},
        )
        self._snap.events.append(evt)
        self._save()
        return evt

    def events_for(self, token_id: str) -> list[TriggerEvent]:
        return [e for e in self._snap.events if e.token_id == token_id]
