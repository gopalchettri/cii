"""The run-time switch document of tsg_external_feed_status, saved whole through the base."""

from datetime import UTC, datetime

from app import container
from app.core.constants import Collection, IntelDocId
from app.core.database import get_mongodb

NOW = datetime(2026, 10, 12, 12, tzinfo=UTC)


def test_the_flag_is_unset_until_an_admin_writes_it_then_follows_the_last_write() -> None:
    get_mongodb()[Collection.EXTERNAL_FEED_STATUS].delete_many({})
    flags = container.get_intel_feed_repository()
    assert flags.get(_id=IntelDocId.SWITCH) is None
    flags.save({"_id": IntelDocId.SWITCH, "enabled": False, "changed_by": "admin-1", "changed_at": NOW})
    assert flags.get(["enabled", "changed_at", "changed_by"], _id=IntelDocId.SWITCH) == {
        "_id": IntelDocId.SWITCH,
        "enabled": False,
        "changed_at": NOW,
        "changed_by": "admin-1",
    }
    flags.save({"_id": IntelDocId.SWITCH, "enabled": True, "changed_by": "admin-2", "changed_at": NOW})
    assert flags.get(_id=IntelDocId.SWITCH)["changed_by"] == "admin-2"
    assert get_mongodb()[Collection.EXTERNAL_FEED_STATUS].count_documents({}) == 1
