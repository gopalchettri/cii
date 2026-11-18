"""The refresher's stores as in-memory doubles that follow the claim as the real ones do: a heartbeat that
fails once the claim is taken over, and a record store that knows the ids it
holds. Built on the shared doubles (tests/external_intelligence/evidence_fakes.py)."""

from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Any

import pytest

from app.core.constants import IntelSource
from app.domain.intel import refresh
from app.schemas.intel_records import IntelRecord
from tests.external_intelligence.evidence_fakes import MemoryFeeds, MemoryRecords, StubFetcher


class StoredGraph:
    """A graph store that holds the release of every stored checkpoint; a refresh with no graph writes none."""

    def is_release_stored(self, source: str, release: str) -> bool:
        return True


def use_refresh_parts(monkeypatch: pytest.MonkeyPatch, fetchers: dict[IntelSource, StubFetcher], **parts: Any) -> Any:
    """The refresh module over the given `records`, `feeds` and `keeper` (and `attack`, the graph store: by
    default one that holds every release, so a stored checkpoint is trusted), each source read by its fetcher."""
    attack = parts.get("attack") or StoredGraph()
    monkeypatch.setattr(refresh, "get_attack_repository", lambda: attack)
    monkeypatch.setattr(refresh, "get_intel_record_repository", lambda: parts["records"])
    monkeypatch.setattr(refresh, "get_intel_feed_repository", lambda: parts["feeds"])
    monkeypatch.setattr(refresh, "get_evidence_index_keeper", lambda: parts["keeper"])
    monkeypatch.setattr(refresh, "MitreAttackSource", lambda source: fetchers[source])
    monkeypatch.setattr(refresh, "apply_proxy_once", lambda: None)
    return refresh


class ClaimFeeds(MemoryFeeds):
    def __init__(self, sources: list[IntelSource] | None = None) -> None:
        super().__init__(sources)
        self.renewals = 0

    def renew_intel_feed_refresh(self, source: IntelSource, claim: str, now: datetime) -> bool:
        if self.claimed.get(source) != claim:
            return False
        self.renewals += 1
        return True


class CurrentRecords(MemoryRecords):
    """`current`: the ids the store holds as current for any source asked about. `after_save` runs after
    each batch is saved (a take-over can be injected there); `after_retire` after the retirement."""

    def __init__(self, current: Sequence[str] = ()) -> None:
        super().__init__()
        self.current = set(current)
        self.after_save: Callable[[int], None] | None = None
        self.after_retire: Callable[[], None] | None = None

    def list(self, fields=None, **where) -> list[dict]:
        return [{"external_id": external_id} for external_id in self.current]

    def save_intel_records(self, records: Sequence[IntelRecord], fetched_at: datetime) -> int:
        new_versions = super().save_intel_records(records, fetched_at)
        if self.after_save:
            self.after_save(len(self.saved))
        return new_versions

    def retire_intel_records_missing_from(
        self, source: IntelSource, seen_ids: set[str], retired_at: datetime | None = None
    ) -> int:
        super().retire_intel_records_missing_from(source, seen_ids)
        if self.after_retire:
            self.after_retire()
        return len(self.current - seen_ids)
