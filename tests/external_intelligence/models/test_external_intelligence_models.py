"""The shared contract of external intelligence: constants, record hash, stored shapes, immutability."""

import dataclasses
from datetime import UTC, datetime, timedelta

import pytest

from app.core.config import Settings
from app.core.constants import (
    REFRESH_AFTER_HOURS,
    EvidenceDecision,
    EvidenceSearchFailure,
    FeedStatus,
    IntelKind,
    IntelLimits,
    IntelMessage,
    IntelSource,
    IntelState,
)
from app.core.exceptions import IntelFetchFailed
from app.models.external_intelligence.evidence import Considered, Evidence, EvidenceSearchRecord
from app.models.external_intelligence.evidence_request import (
    EvidenceRequest,
    EvidenceResult,
    RecordedProduct,
    RecordedProducts,
)
from app.models.external_intelligence.fetch_result import FetchResult
from app.models.external_intelligence.intel_record import IntelRecord, RejectedRecord, SaveCounts
from app.models.external_intelligence.source_health import HealthReport, SourceHealth
from app.models.external_intelligence.switch_state import SwitchState

NOW = datetime(2026, 10, 12, tzinfo=UTC)


def _record(**changes: object) -> IntelRecord:
    base = IntelRecord(
        source=IntelSource.CISA_KEV,
        external_id="CVE-2024-0001",
        kind=IntelKind.VULNERABILITY,
        asset_type="IT",
        title="A flaw",
        text="A flaw in a product.",
        url="https://example.test/1",
        source_version="2026.10.12",
        data={"cve": "CVE-2024-0001"},
    )
    return dataclasses.replace(base, **changes)


def test_every_source_has_a_refresh_interval() -> None:
    assert set(REFRESH_AFTER_HOURS) == set(IntelSource)
    assert REFRESH_AFTER_HOURS[IntelSource.ATTACK_ENTERPRISE] == 168


def test_hash_follows_content_only() -> None:
    assert _record().content_hash == _record(source_version="other", url="https://x.test").content_hash
    assert _record().content_hash != _record(text="changed").content_hash


def test_a_record_stores_as_a_valid_current_version() -> None:
    doc = _record().as_doc(NOW)
    assert doc["state"] == IntelState.VALID
    assert doc["content_hash"] == _record().content_hash
    assert doc["parser_version"] == IntelLimits.PARSER_VERSION
    rejected = RejectedRecord(IntelSource.FIRST_EPSS, "x", "why", "h").as_doc(NOW)
    assert rejected["state"] == IntelState.QUARANTINED and rejected["current"] is False


def test_save_counts_add() -> None:
    assert SaveCounts(1, 2, 3) + SaveCounts(4, 5, 6) == SaveCounts(5, 7, 9)


def test_the_contract_types_are_immutable() -> None:
    request = EvidenceRequest("text", frozenset({"IT"}), RecordedProducts())
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
    evidence = Evidence(
        "T1059", IntelKind.TECHNIQUE, IntelSource.ATTACK_ENTERPRISE, "t", "u", 9.0, ("a", "b")
    )
    assert evidence.as_doc()["facts"] == ["a", "b"]


def test_recorded_products_hold_plain_strings() -> None:
    products = RecordedProducts(
        (RecordedProduct(vendors=("Acme",), products=("Acme Gateway",), versions=("1.2",)),)
    )
    assert products.rows[0].versions == ("1.2",)


def test_the_runtime_switch_can_only_turn_intelligence_off() -> None:
    assert SwitchState(env_enabled=True).effective
    assert not SwitchState(env_enabled=True, runtime_enabled=False).effective
    assert not SwitchState(env_enabled=False, runtime_enabled=True).effective


def test_a_source_that_never_succeeded_is_pending() -> None:
    never_run = SourceHealth(IntelSource.NIST_NVD)
    only_failed = SourceHealth(IntelSource.NIST_NVD, FeedStatus.FAILED, last_attempt_at=NOW)
    assert never_run.is_pending and only_failed.is_pending
    old = SourceHealth(IntelSource.CISA_KEV, FeedStatus.OK, last_success_at=NOW - timedelta(hours=49))
    assert not old.is_pending
    doc = HealthReport(SwitchState(True), None, (old,)).as_doc()
    assert (
        doc["sources"][0]["source"] == "cisa_kev" and doc["pending_sources"] == [] and doc["no_data"] is False
    )


def test_the_report_lists_pending_sources_and_says_when_there_is_no_data() -> None:
    report = HealthReport(SwitchState(True), None, (), (IntelSource.NIST_NVD,), True)
    doc = report.as_doc()
    assert doc["pending_sources"] == ["nist_nvd"] and doc["no_data"] is True


def test_the_fetch_failure_carries_its_filled_message() -> None:
    error = IntelFetchFailed(IntelMessage.REFUSED, url="https://x.test", status=403)
    assert str(error) == "https://x.test answered with status 403."


def test_the_settings_defaults() -> None:
    fields = Settings.model_fields
    assert fields["external_intelligence_enabled"].default is False
    assert fields["evidence_similarity_threshold"].default == 1.0
    assert fields["nvd_api_key"].default.get_secret_value() == ""
