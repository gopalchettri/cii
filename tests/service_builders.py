"""The scenario use cases on the app's own repositories and side effects, some swapped for a test's own."""

from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from app.domain.scenario import runs

#: A part's name -> the getter in runs that serves it.
_GETTERS = {
    "sessions": "get_threat_scenario_session_repository",
    "scenarios": "get_threat_scenario_repository",
    "threats": "get_threat_repository",
    "switch": "get_intelligence_switch",
    "intel_snapshots": "get_intel_snapshot_repository",
    "audit": "get_audit_repository",
}
#: Parts set on runs as they are given.
_AS_GIVEN = {"get_asset_context", "send_job", "publish_session_status"}


def use_scenario_parts(monkeypatch: pytest.MonkeyPatch, **parts: Any) -> ModuleType:
    """Swap the given parts into runs (undone after the test); runs, whose functions use them."""
    for name, part in parts.items():
        if name in _GETTERS:
            monkeypatch.setattr(runs, _GETTERS[name], lambda part=part: part)
        elif name == "threat_library":
            monkeypatch.setattr(runs, "get_library_cache", lambda part=part: SimpleNamespace(get_threat_library=part))
        elif name in _AS_GIVEN:
            monkeypatch.setattr(runs, name, part)
        else:
            raise TypeError(f"unknown scenario part {name!r}")
    return runs
