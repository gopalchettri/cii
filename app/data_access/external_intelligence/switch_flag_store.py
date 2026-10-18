"""The run-time on/off switch of external intelligence: one document in tsg_external_feed_status."""

from datetime import datetime

from pymongo.database import Database

from app.core.constants import Collection, IntelDocId


class SwitchFlagStore:
    def __init__(self, db: Database) -> None:
        self._flags = db[Collection.EXTERNAL_FEED_STATUS]

    def read_runtime_flag(self) -> tuple[bool, datetime | None, str | None] | None:
        """(enabled, changed_at, changed_by), or None when an admin never set it."""
        doc = self._flags.find_one({"_id": IntelDocId.SWITCH})
        if doc is None:
            return None
        return bool(doc.get("enabled", True)), doc.get("changed_at"), doc.get("changed_by")

    def write_runtime_flag(self, enabled: bool, changed_by: str, now: datetime) -> None:
        """The switch set, with who changed it and when."""
        change = {"enabled": enabled, "changed_by": changed_by, "changed_at": now}
        self._flags.update_one({"_id": IntelDocId.SWITCH}, {"$set": change}, upsert=True)
