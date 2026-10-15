"""Planning's own small copy of what its UAE/Gulf tie-break reads (G238, owner 2026-10-14: no waiting, and
never the old data): the MITRE ATT&CK techniques' texts and the real groups behind them, read straight from
the stored records (807 techniques, about 0.1 s measured), kept in memory and read again only when the active
snapshot pointer names another snapshot (one small read per plan).

It used to borrow the writer's evidence index, which a worker rebuilds in the background after a refresh: the
first plan after a reload ranked with the old groups (run 0ffdeabd: 0 of 37 threats near; the new data: 29),
and a worker's first plan waited up to 2 minutes for a first index.

While a refresh is building its snapshot, the records may already be newer than the pointer names: a plan
then ranks with the newer groups and records the snapshot published so far (the writer's evidence carries its
own snapshot id). No ATT&CK technique stored (the sources revoked) is an answer too: no tie-break, kept like a
copy, so it is not read again for every plan."""

from typing import Any

from app.core.constants import IntelKind, IntelSource
from app.core.database import get_mongodb
from app.core.singletons import singleton
from app.data_access.external_intelligence.feed_status_store import FeedStatusStore
from app.data_access.external_intelligence.intel_record_store import IntelRecordStore
from app.data_access.external_intelligence.snapshot_pointer_store import SnapshotPointerStore
from app.models.external_intelligence.evidence_corpus import EvidenceCorpus
from app.search.external_intelligence.corpus_builder import CorpusBuilder
from app.search.external_intelligence.index_refused import EvidenceIndexRefused

_ATTACK = (IntelSource.ATTACK_ENTERPRISE, IntelSource.ATTACK_ICS)


class RelevanceCorpus:
    def __init__(
        self, records: IntelRecordStore, pointers: SnapshotPointerStore, feeds: FeedStatusStore
    ) -> None:
        self._records, self._pointers, self._feeds = records, pointers, feeds
        # ponytail: one reference swapped whole; two plans reading at once after a refresh both read the
        # records once (about 0.1 s) and keep the same copy.
        self._held: tuple[str, EvidenceCorpus | None] | None = None

    def current(self) -> tuple[EvidenceCorpus | None, dict[str, Any]]:
        """The approved ATT&CK techniques as of the active snapshot (None: none stored), and that snapshot's
        description ({} before the first), which the plan records. Raises only what a store raises."""
        active = self._pointers.read_active_snapshot() or {}
        key = str(active.get("snapshot_id") or "")
        held = self._held
        if held is not None and key and held[0] == key:
            return held[1], active
        sources = [source for source in self._feeds.list_approved_sources() if source in _ATTACK]
        try:
            corpus: EvidenceCorpus | None = CorpusBuilder().build_corpus(
                self._records.stream_current_records(sources, IntelKind.TECHNIQUE)
            )
        except EvidenceIndexRefused:  # no technique stored: no tie-break, and that is kept as the answer
            corpus = None
        self._held = (key, corpus)
        return corpus, active


@singleton
def get_relevance_corpus() -> RelevanceCorpus:
    db = get_mongodb()
    return RelevanceCorpus(IntelRecordStore(db), SnapshotPointerStore(db), FeedStatusStore(db))
