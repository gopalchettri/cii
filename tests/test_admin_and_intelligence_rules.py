"""The pure rules behind job control, library promotion, API keys and the intelligence refresh."""

from datetime import UTC, datetime, timedelta

import pytest

from app.core.constants import (
    REFRESH_AFTER_HOURS,
    ApiKey,
    ConflictReason,
    Decision,
    IntelSource,
    JobKind,
    PromotionOutcome,
    ResolveOutcome,
    Status,
    TaskName,
)
from app.core.exceptions import Conflict
from app.domain.admin.api_keys import could_be_minted_key, hash_api_key
from app.domain.external_intelligence.evidence_settings import evidence_settings
from app.domain.external_intelligence.refresh_rules import (
    is_cut_short_feed,
    is_empty_complete_feed,
    is_refresh_due,
    trusted_checkpoint,
)
from app.domain.jobs import check_run_cancel_stopped_something, run_job_kind_and_status
from app.domain.library.curation import accepted_ai_threat_key, decision_operation_key, promotion_outcome

NOW = datetime(2026, 10, 18, tzinfo=UTC)


def test_a_working_run_shows_its_job_and_a_finished_one_shows_control_matching() -> None:
    assert run_job_kind_and_status(Status.QUEUED, TaskName.FIND_THREATS) == (JobKind.THREATS, Status.QUEUED)
    assert run_job_kind_and_status(Status.RUNNING, TaskName.WRITE_SCENARIOS) == (
        JobKind.SCENARIOS,
        Status.RUNNING,
    )
    assert run_job_kind_and_status(Status.DONE, None) == (JobKind.CONTROLS, Status.RUNNING)
    check_run_cancel_stopped_something("s1", False, 2)
    with pytest.raises(Conflict) as refused:
        check_run_cancel_stopped_something("s1", False, 0)
    assert refused.value.reason == ConflictReason.NOTHING_TO_CANCEL


def test_only_an_accepted_scenarios_ai_threat_is_promoted() -> None:
    ai = {"decision": Decision.ACCEPTED, "content": {"threat": {"ai_generated": True, "key": "k1"}}}
    assert accepted_ai_threat_key(ai, "sc1") == "k1"
    assert accepted_ai_threat_key({**ai, "content": {"threat": {"key": "k1"}}}, "sc1") is None
    with pytest.raises(Conflict):
        accepted_ai_threat_key({**ai, "decision": Decision.REJECTED}, "sc1")
    assert promotion_outcome(ResolveOutcome.CREATED_PENDING) == PromotionOutcome.INSERTED
    assert promotion_outcome("already_active") == PromotionOutcome.EXISTING
    assert (
        decision_operation_key([1], [2], "u")
        == decision_operation_key([1], [2], "u")
        != decision_operation_key([2], [1], "u")
    )


def test_only_a_key_shaped_like_a_minted_one_is_looked_up() -> None:
    assert not could_be_minted_key("junk")
    assert not could_be_minted_key(ApiKey.PREFIX + "x")
    assert len(hash_api_key("k")) == 64


def test_a_source_is_due_until_its_period_passes_and_a_cut_short_feed_is_refused() -> None:
    period = timedelta(hours=REFRESH_AFTER_HOURS[IntelSource.CISA_KEV])
    assert is_refresh_due(IntelSource.CISA_KEV, None, False, NOW)
    assert is_refresh_due(IntelSource.CISA_KEV, NOW, True, NOW)
    assert not is_refresh_due(IntelSource.CISA_KEV, NOW - period + timedelta(seconds=1), False, NOW)
    assert is_refresh_due(IntelSource.CISA_KEV, NOW - period, False, NOW)
    assert trusted_checkpoint("c", None) is None and trusted_checkpoint("c", "v") == "c"
    assert is_empty_complete_feed(0, partial=False) and not is_empty_complete_feed(0, partial=True)
    assert is_cut_short_feed(100, 1) and not is_cut_short_feed(100, 100) and not is_cut_short_feed(0, 0)


def test_the_evidence_settings_name_the_model_never_its_path() -> None:
    settings = evidence_settings("C:\\models\\bge-reranker-v2-m3\\", 0.5)
    assert settings["rerank_model"] == "bge-reranker-v2-m3" and settings["threshold_calibrated"]
    assert evidence_settings("/m/other", 0.5)["threshold_calibrated_on"] is None
