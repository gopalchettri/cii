"""The run-time switch document."""

from datetime import UTC, datetime

from app.core.constants import Collection
from app.core.database import get_mongodb
from app.data_access.external_intelligence.switch_flag_store import SwitchFlagStore

NOW = datetime(2026, 10, 12, 12, tzinfo=UTC)


def test_the_flag_is_unset_until_an_admin_writes_it_then_follows_the_last_write() -> None:
    get_mongodb()[Collection.EXTERNAL_FEED_STATUS].delete_many({})
    flags = SwitchFlagStore(get_mongodb())
    assert flags.read_runtime_flag() is None
    flags.write_runtime_flag(False, "admin-1", NOW)
    assert flags.read_runtime_flag() == (False, NOW, "admin-1")
    flags.write_runtime_flag(True, "admin-2", NOW)
    assert flags.read_runtime_flag() == (True, NOW, "admin-2")
    assert get_mongodb()[Collection.EXTERNAL_FEED_STATUS].count_documents({}) == 1
