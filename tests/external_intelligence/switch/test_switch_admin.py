"""The admin over the REAL switch: one audit row and one log line per change, nothing read or created while
the master switch is off."""

from datetime import datetime
from typing import Any

import pytest
from structlog.testing import capture_logs

from app.core.config import get_settings
from app.core.constants import AuditAction, Collection, LogEvent
from app.core.database import get_mongodb
from app.core.exceptions import Conflict
from app.domain.intel.switch import IntelligenceSwitch
from tests.external_intelligence.fakes import intelligence_service


class Untouched:
    """A store that must be neither read nor written: any use fails the test."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"the store was used: {name}")


class Flags:
    def __init__(self) -> None:
        self.stored: tuple[bool, datetime, str] | None = None

    def get(self, fields: Any = None, **where: Any) -> dict[str, Any] | None:
        if self.stored is None:
            return None
        return {"enabled": self.stored[0], "changed_at": self.stored[1], "changed_by": self.stored[2]}

    def save(self, record: dict[str, Any], only_if: Any = None) -> bool:
        self.stored = (record["enabled"], record["changed_at"], record["changed_by"])
        return True


def _audit(action: AuditAction) -> list[dict[str, Any]]:
    return list(get_mongodb()[Collection.AUDIT].find({"action": action}))


def _admin(monkeypatch: pytest.MonkeyPatch, *, env: bool, switch=None):
    """The service over Untouched stores and the real audit; the refreshes it queues are recorded, not started."""
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", env)
    untouched = ("feeds", "snapshots", "admin_jobs", "index_keeper")
    parts = {name: Untouched() for name in untouched}
    switch = switch or IntelligenceSwitch(Flags(), lambda: env)  # type: ignore[arg-type]
    admin = intelligence_service(monkeypatch, switch=switch, **parts)
    started: list[str] = []

    def start(requested_by: str) -> dict[str, Any]:
        started.append(requested_by)
        return {"job_id": "job-1", "status": "queued"}

    monkeypatch.setattr(admin, "create_intelligence_refresh", start)
    return admin, started


def test_one_put_writes_exactly_one_audit_row_and_one_log_line(monkeypatch: pytest.MonkeyPatch) -> None:
    admin, refreshes = _admin(monkeypatch, env=True)
    before = len(_audit(AuditAction.EXTERNAL_INTELLIGENCE_SWITCHED))
    with capture_logs() as logs:
        admin.update_intelligence_switch_state(False, "op-1")
    rows = _audit(AuditAction.EXTERNAL_INTELLIGENCE_SWITCHED)
    assert len(rows) == before + 1
    assert rows[-1]["actor"]["user_id"] == "op-1"
    assert rows[-1]["before"] == {"env_enabled": True, "runtime_enabled": True}
    assert rows[-1]["after"] == {"env_enabled": True, "runtime_enabled": False}
    assert [log["event"] for log in logs].count(LogEvent.EXTERNAL_INTELLIGENCE_SWITCH_CHANGED) == 1
    admin.update_intelligence_switch_state(True, "op-1")  # turning it on queues one refresh, still one row
    assert len(_audit(AuditAction.EXTERNAL_INTELLIGENCE_SWITCHED)) == before + 2
    assert refreshes == ["op-1"]


def test_with_the_master_switch_off_the_switch_answers_without_touching_the_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin, _ = _admin(monkeypatch, env=False, switch=IntelligenceSwitch(Untouched(), env_enabled=lambda: False))
    state = admin.get_intelligence_switch_state()
    assert (state["env_enabled"], state["effective"]) == (False, False)
    with pytest.raises(Conflict):
        admin.update_intelligence_switch_state(True, "op")
