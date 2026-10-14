"""tsg_external_feed_status, read side: each source's approval, checkpoint and health.

One document per source, `_id` the source id: the `SourceHealth` fields plus `approved` and
`more_pending`. The same collection holds the run-time switch document (switch_flag_store.py), so every read
of the sources asks for the source ids only. The writes are in feed_status_store.py (FeedStatusStore extends
this class)."""

from typing import Any

from pymongo.database import Database

from app.core.constants import Collection, FeedStatus, IntelSource
from app.models.external_intelligence.source_health import SourceHealth

Doc = dict[str, Any]
ALL_SOURCES = [source.value for source in IntelSource]


def _as_health(doc: Doc) -> SourceHealth:
    fields = SourceHealth(IntelSource(doc["_id"])).as_doc()
    values = {name: doc.get(name, default) for name, default in fields.items()}
    values.update(source=IntelSource(doc["_id"]), status=FeedStatus(values["status"]))
    return SourceHealth(**values)


class FeedStatusReader:
    def __init__(self, db: Database) -> None:
        self._feeds = db[Collection.EXTERNAL_FEED_STATUS]

    def read_source_health(self, source: IntelSource) -> SourceHealth | None:
        doc = self._feeds.find_one({"_id": source})
        return None if doc is None else _as_health(doc)

    def read_all_source_health(self) -> list[SourceHealth]:
        docs = self._feeds.find({"_id": {"$in": ALL_SOURCES}})
        return sorted((_as_health(doc) for doc in docs), key=lambda health: ALL_SOURCES.index(health.source))

    def is_source_approved(self, source: IntelSource) -> bool:
        doc = self._feeds.find_one({"_id": source}, {"approved": 1})
        return bool(doc and doc.get("approved"))

    def list_approved_sources(self) -> list[IntelSource]:
        approved = {doc["_id"] for doc in self._feeds.find({"_id": {"$in": ALL_SOURCES}, "approved": True})}
        return [source for source in IntelSource if source in approved]

    def is_more_pending(self, source: IntelSource) -> bool:
        doc = self._feeds.find_one({"_id": source}, {"more_pending": 1})
        return bool(doc and doc.get("more_pending"))
