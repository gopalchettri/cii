"""The shared contract of external intelligence: constants, record hash, stored shapes, immutability."""

import dataclasses
from datetime import UTC, datetime, timedelta

import pytest

from app.core.config import Settings
from app.core.constants import (
    EvidenceDecision,
    EvidenceSearchFailure,
    FeedStatus,
    IntelKind,
    IntelMessage,
    IntelSource,
    IntelState,
)
from app.core.exceptions import IntelFetchFailed
from app.schemas.intel_records import (
    Considered,
    Evidence,
    EvidenceRequest,
    EvidenceResult,
    EvidenceSearchRecord,
    FetchResult,
    IntelRecord,
    SourceHealth,
    SwitchState,
)

NOW = datetime(2026, 10, 12, tzinfo=UTC)


def _record(**changes: object) -> IntelRecord:
    base = IntelRecord(
        source=IntelSource.ATTACK_ENTERPRISE,
        external_id="T1059",
        kind=IntelKind.TECHNIQUE,
        asset_type="IT",
        title="Command and Scripting Interpreter",
        text="Adversaries may abuse command interpreters.",
        url="https://example.test/1",
        source_version="2026.10.12",
        data={"tactics": ["execution"]},
    )
    return dataclasses.replace(base, **changes)


def test_hash_follows_content_only() -> None:
    assert _record().content_hash == _record(source_version="other", url="https://x.test").content_hash
    assert _record().content_hash != _record(text="changed").content_hash


def test_a_record_stores_as_a_valid_current_version() -> None:
    doc = _record().as_doc(NOW)
    assert doc["state"] == IntelState.VALID
    assert doc["content_hash"] == _record().content_hash


def test_the_contract_types_are_immutable() -> None:
    request = EvidenceRequest("text", frozenset({"IT"}))
    result = EvidenceResult((), EvidenceSearchRecord("q", ("IT",), None, 1.0))
    for frozen in (request, result, _record(), SwitchState(True), FetchResult((), (), "c", "v")):
        with pytest.raises(dataclasses.FrozenInstanceError):
            frozen.__setattr__("x", 1)  # noqa: PLC2801 - a frozen dataclass refuses any attribute


def test_a_search_record_stores_as_plain_json() -> None:
    considered = Considered("T1059", 12.5, EvidenceDecision.USED)
    record = EvidenceSearchRecord(
        "q", ("IT", "OT"), "snap-1", 1.0, (considered,), failure=EvidenceSearchFailure.UNAVAILABLE
    )
    doc = record.as_doc()
    assert doc["asset_types"] == ["IT", "OT"]
    assert doc["considered"] == [{"ref": "T1059", "score": 12.5, "decision": "used", "reason": ""}]
    evidence = Evidence("T1059", IntelKind.TECHNIQUE, IntelSource.ATTACK_ENTERPRISE, "t", "u", 9.0, ("a", "b"))
    assert evidence.as_doc()["facts"] == ["a", "b"]


def test_the_runtime_switch_can_only_turn_intelligence_off() -> None:
    assert SwitchState(env_enabled=True).effective
    assert not SwitchState(env_enabled=True, runtime_enabled=False).effective
    assert not SwitchState(env_enabled=False, runtime_enabled=True).effective


def test_a_source_that_never_succeeded_is_pending() -> None:
    never_run = SourceHealth(IntelSource.ATTACK_ICS)
    only_failed = SourceHealth(IntelSource.ATTACK_ICS, FeedStatus.FAILED, last_attempt_at=NOW)
    assert never_run.is_pending and only_failed.is_pending
    old = SourceHealth(IntelSource.ATTACK_ENTERPRISE, FeedStatus.OK, last_success_at=NOW - timedelta(hours=49))
    assert not old.is_pending


def test_the_fetch_failure_carries_its_filled_message() -> None:
    error = IntelFetchFailed(IntelMessage.REFUSED, url="https://x.test", status=403)
    assert str(error) == "https://x.test answered with status 403."


def test_the_settings_defaults() -> None:
    fields = Settings.model_fields
    assert fields["external_intelligence_enabled"].default is False
    assert fields["evidence_similarity_threshold"].default == 1.0
