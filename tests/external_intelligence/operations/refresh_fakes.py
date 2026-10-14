"""The refresher's stores as in-memory doubles that follow the claim as the real ones do: a heartbeat that
fails once the claim is taken over or the source is revoked, and a record store that knows the ids it
holds. Built on the shared doubles (tests/external_intelligence/evidence_fakes.py)."""

from collections.abc import Callable, Sequence
from datetime import datetime

from app.core.constants import IntelSource
from app.models.external_intelligence.intel_record import IntelRecord, SaveCounts
from app.models.external_intelligence.source_health import SourceHealth
from tests.external_intelligence.evidence_fakes import MemoryFeeds, MemoryRecords


class ClaimFeeds(MemoryFeeds):
    def __init__(self, approved: list[IntelSource] | None = None) -> None:
        super().__init__(approved)
        self.renewals = 0

    def renew_claim(self, source: IntelSource, claim: str, now: datetime) -> bool:
        if self.claimed.get(source) != claim or source not in self.approved:
            return False
        self.renewals += 1
        return True

    def release_claim(self, source: IntelSource, claim: str) -> bool:
        if self.claimed.get(source) != claim:
            return False
        del self.claimed[source]
        return True

    def revoke_source(self, source: IntelSource, *, create: bool = True) -> None:
        self.set_source_approved(source, False)
        self.health[source] = SourceHealth(source)

    def approve_source(self, source: IntelSource) -> None:
        self.set_source_approved(source, True)
        self.health[source] = SourceHealth(source)


class CurrentRecords(MemoryRecords):
    """`current`: the ids the store holds as current for any source asked about. `after_save` runs after
    each batch is saved (a revoke can be injected there); `after_retire` after the retirement."""

    def __init__(self, current: Sequence[str] = ()) -> None:
        super().__init__()
        self.current = set(current)
        self.after_save: Callable[[int], None] | None = None
        self.after_retire: Callable[[], None] | None = None

    def list_current_external_ids(self, source: IntelSource) -> set[str]:
        return set(self.current)

    def save_batch(
        self, records: Sequence[IntelRecord], rejected: Sequence, fetched_at: datetime
    ) -> SaveCounts:
        counts = super().save_batch(records, rejected, fetched_at)
        if self.after_save:
            self.after_save(len(self.saved))
        return counts

    def retire_records_missing_from(
        self, source: IntelSource, seen_ids: set[str], retired_at: datetime
    ) -> int:
        super().retire_records_missing_from(source, seen_ids)  # type: ignore[call-arg]
        if self.after_retire:
            self.after_retire()
        return len(self.current - seen_ids)
