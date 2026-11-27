"""What POST /v1/create_session, the ATT&CK graph, the control links and the import schedule all build on:
their constants and settings, request and response shapes, and prompts."""

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from app.core import constants as c
from app.core.ai_tuning_settings import TUNING, AiTuningSettings
from app.core.prompts import PROMPTS
from app.schemas.intel import ControlLinksSummary, IntelScheduleBody, IntelScheduleOut
from app.schemas.intel_records import FetchResult
from app.schemas.jobs import AdminJobOut, ControlLinksJobOut
from app.schemas.scenarios import StartRunRequest
from tests.checkout import REPO

RUN = {"asset_id": 7, "supporting_system_id": [3, 1], "service_id": 2}
WEEKLY = {"enabled": True, "frequency": "weekly", "day_of_week": 6, "time": "02:00", "timezone": "UTC"}
FROZEN = json.loads((REPO / "tests" / "contract" / "ui_api_frozen.json").read_text(encoding="utf-8"))["schemas"]


def test_the_run_body_both_start_routes_take_keeps_its_fingerprint() -> None:
    """POST /v1/create_session takes POST /v1/sessions' own body: no new field, the same fingerprint as before."""
    stored = {"asset_id": 7, "sector_id": None, "service_id": 2, "subsector_id": None, "supporting_system_ids": [1, 3]}
    as_before = hashlib.sha256(json.dumps(stored, sort_keys=True).encode()).hexdigest()
    assert StartRunRequest.model_validate(RUN).fingerprint() == as_before
    assert StartRunRequest.model_validate(RUN | {"supporting_system_id": [1, 3]}).fingerprint() == as_before
    with pytest.raises(ValidationError, match="data_handled"):  # an asset fact the procedure gives, never a field
        StartRunRequest.model_validate(RUN | {"data_handled": "Grid telemetry"})


def test_a_schedule_is_daily_or_weekly_at_a_time_in_a_real_time_zone() -> None:
    weekly = IntelScheduleBody.model_validate(WEEKLY | {"timezone": "Asia/Dubai"})
    assert (weekly.frequency, weekly.day_of_week, weekly.time, weekly.timezone) == ("weekly", 6, "02:00", "Asia/Dubai")
    daily = IntelScheduleBody.model_validate(WEEKLY | {"frequency": "daily", "time": "23:59"})
    assert (daily.frequency, daily.day_of_week, daily.time) == (c.ScheduleFrequency.DAILY, None, "23:59")
    assert IntelScheduleBody.model_validate(WEEKLY | {"frequency": "daily", "day_of_week": None}).day_of_week is None


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"day_of_week": None}, "is required when frequency is weekly"),
        ({"day_of_week": 7}, "less than or equal to 6"),
        ({"day_of_week": -1}, "greater than or equal to 0"),
        ({"time": "24:00"}, "pattern"),
        ({"time": "2:00"}, "pattern"),
        ({"time": "02:60"}, "pattern"),
        ({"time": "02:00:00"}, "pattern"),
        ({"timezone": "Mars/Olympus"}, "Unknown time zone 'Mars/Olympus'"),
        ({"timezone": ""}, "Unknown time zone"),
        ({"timezone": "../etc/passwd"}, "Unknown time zone"),
        ({"frequency": "hourly"}, "daily"),
        ({"enabled": "yes"}, "boolean"),
        ({"next_run_at": "2026-11-22T02:00:00Z"}, "Extra inputs"),
    ],
)
def test_a_schedule_that_cannot_run_is_refused_with_its_reason(change: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        IntelScheduleBody.model_validate(WEEKLY | change)


def test_a_weekly_schedule_missing_its_day_is_refused_even_when_the_field_is_left_out() -> None:
    without_day = {name: value for name, value in WEEKLY.items() if name != "day_of_week"}
    with pytest.raises(ValidationError, match="day_of_week"):
        IntelScheduleBody.model_validate(without_day)
    for missing in ("enabled", "frequency", "time", "timezone"):
        with pytest.raises(ValidationError, match=missing):
            IntelScheduleBody.model_validate({name: value for name, value in WEEKLY.items() if name != missing})


def test_the_default_schedule_is_weekly_on_sunday_at_two_utc_and_reads_as_a_saved_one() -> None:
    """A database with no schedule document keeps importing: enabled, weekly, Sunday 02:00 UTC."""
    defaults = {
        "enabled": c.IntelSchedule.DEFAULT_ENABLED,
        "frequency": c.IntelSchedule.DEFAULT_FREQUENCY,
        "day_of_week": c.IntelSchedule.DEFAULT_DAY_OF_WEEK,
        "time": c.IntelSchedule.DEFAULT_TIME,
        "timezone": c.IntelSchedule.DEFAULT_TIMEZONE,
    }
    assert defaults == WEEKLY and IntelScheduleBody.model_validate(defaults).model_dump() == WEEKLY
    shown = IntelScheduleOut.model_validate(defaults | {"_id": c.IntelDocId.SCHEDULE, "updated_by": "admin"})
    assert shown.model_dump() == WEEKLY | {"next_run_at": None, "last_run_at": None, "updated_at": None}
    assert c.IntelDocId.SCHEDULE == "schedule" and c.IntelLimits.CHECK_EVERY_SECONDS == 60


def test_a_control_links_job_has_its_own_shape_and_the_admin_job_shape_the_ui_reads_is_untouched() -> None:
    """AdminJobOut and AdminJobKind are frozen (tests/contract/ui_api_frozen.json): the new kind is no member.
    Mutation: add CONTROL_LINKS to AdminJobKind and GET /v1/embeddings/{job_id}'s schema changes."""
    assert {kind.value for kind in c.AdminJobKind} == set(FROZEN["AdminJobKind"]["enum"])
    assert c.CONTROL_LINKS_JOB_KIND == "control_links" not in set(c.AdminJobKind)
    properties = AdminJobOut.model_json_schema(ref_template="#/components/schemas/{model}")["properties"]
    for name in ("kind", "result"):  # FastAPI leaves a null default out of the document it serves
        assert {key: value for key, value in properties[name].items() if key != "default"} == (
            FROZEN["AdminJobOut"]["properties"][name]
        )
    now = datetime(2026, 11, 17, 2, 0, tzinfo=UTC)
    stored = {
        "job_id": "j1",
        "kind": c.CONTROL_LINKS_JOB_KIND,
        "status": c.Status.DONE,
        "requested_by": "admin",
        "created_at": now,
        "result": {"judged": 40, "unchanged": 55, "failed": 1},
        "request_id": "r1",  # a stored field the route does not show
    }
    shown = ControlLinksJobOut.model_validate(stored).model_dump()
    assert shown["result"] == {"judged": 40, "unchanged": 55, "failed": 1} and "request_id" not in shown
    assert ControlLinksJobOut.model_validate(stored | {"result": None}).result is None
    assert set(shown["result"]) == {outcome.value for outcome in c.ControlLinkOutcome}
    summary = ControlLinksSummary(mitigations=96, linked=80, without_links=16, prepared_at=now)
    shown_summary = {"mitigations": 96, "linked": 80, "without_links": 16, "not_prepared": 0, "prepared_at": now}
    assert summary.model_dump() == shown_summary
    assert ControlLinksSummary(mitigations=0, linked=0, without_links=0).prepared_at is None


def test_the_link_task_runs_on_the_import_queue_and_its_job_kind_maps_to_it() -> None:
    assert c.TaskName.LINK_MITIGATIONS == "tsg_link_mitigations"
    assert c.TASK_ROUTES[c.TaskName.LINK_MITIGATIONS] == c.TASK_ROUTES[c.TaskName.REFRESH_EXTERNAL_INTELLIGENCE]
    assert c.TASK_ROUTES[c.TaskName.LINK_MITIGATIONS] == {"queue": c.Queue.MAINTENANCE}  # no new queue or pod
    assert c.ADMIN_JOB_TASKS[c.CONTROL_LINKS_JOB_KIND] == c.TaskName.LINK_MITIGATIONS
    for name in (c.TaskName.LINK_MITIGATIONS, c.CONTROL_LINKS_JOB_KIND):
        assert c.module_of(name) == c.module_of(c.AdminJobKind.INTEL_REFRESH) == c.Module.EXTERNAL_INTELLIGENCE
    assert all(c.module_of(task) != "other" for task in c.TaskName)


def test_the_new_collections_api_pipeline_and_audit_names() -> None:
    assert (c.Collection.ATTACK, c.Collection.CONTROL_LINKS) == ("tsg_attack", "tsg_control_links")
    assert c.RunPipeline.ATTACK == "attack"
    assert c.AiApi.CREATE_SESSION == "create_session"
    label, about = c.api_info(c.Module.THREAT_SCENARIOS, c.AiApi.CREATE_SESSION)
    assert label == "Create session" and "MITRE ATT&CK" in about
    assert c.AuditAction.EXTERNAL_INTELLIGENCE_SCHEDULE_CHANGED == "external_intelligence.schedule_changed"
    assert c.ATTACK_MATRIX_NAMES == {"mitre_attack_enterprise": "Enterprise", "mitre_attack_ics": "ICS"}
    assert c.AttackMessage.NOT_FOUND.format(name="T9999", matrix="ICS") == "T9999 is not in MITRE ATT&CK ICS."
    assert c.AttackReading.FORMAT == "9"


def test_only_attack_techniques_are_an_intelligence_kind() -> None:
    """The KEV, EPSS, ICS advisory and NVD feeds are gone, and so are their names."""
    assert [kind.value for kind in c.IntelKind] == ["technique"]
    assert [source.value for source in c.IntelSource] == ["mitre_attack_enterprise", "mitre_attack_ics"]
    gone = ("KEV_LISTED", "RANSOMWARE", "ADVISORY", "NO_PRODUCT_LINK", "NOT_APPLICABLE")
    for enum in (c.EvidenceFact, c.EvidenceDecision, c.EvidenceReason):
        assert not set(gone) & set(enum.__members__), enum


def test_the_two_control_tasks_are_repeatable_counted_under_controls_and_have_their_own_answer_room(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for task, setting in ((c.AiTask.LINK_CONTROLS, "link_controls"), (c.AiTask.PICK_CONTROLS, "pick_controls")):
        assert c.CHAT_TEMPERATURES[task] == 0.0
        assert c.CHAT_MAX_OUTPUT_TOKENS[task] == getattr(TUNING, f"answer_tokens_{setting}")
        assert c.ai_bucket(task, None) == c.AiBucket.CONTROLS
        assert c.activity_info(c.AiBucket.CONTROLS, task)[0] != task  # named in the reports
        monkeypatch.setenv(f"CII_ANSWER_TOKENS_{setting.upper()}", "1024")
        assert getattr(AiTuningSettings(), f"answer_tokens_{setting}") == 1024
        monkeypatch.setenv(f"CII_ANSWER_TOKENS_{setting.upper()}", "100")
        with pytest.raises(ValidationError, match=f"answer_tokens_{setting}"):
            AiTuningSettings()
        monkeypatch.delenv(f"CII_ANSWER_TOKENS_{setting.upper()}")
    assert (c.AiTask.LINK_CONTROLS, c.AiTask.PICK_CONTROLS) == ("link_controls", "pick_controls")
    # the linking's own searches are counted under controls too
    assert c.ai_bucket(c.AiTask.EMBED, c.TaskName.LINK_MITIGATIONS) == c.AiBucket.CONTROLS
    assert c.ai_bucket(c.AiTask.RERANK, c.TaskName.LINK_MITIGATIONS) == c.AiBucket.CONTROLS


def test_the_linking_and_picking_numbers_are_the_measured_ones() -> None:
    links = c.ControlLinks
    assert (links.CANDIDATES, links.JUDGED, links.DESCRIPTION_CHARS, links.JUDGE_TEXT_CHARS) == (30, 15, 1200, 300)
    assert (links.SHORTLIST, links.PER_SENTENCE, links.MEANING_HITS, links.CARD_TEXT_CHARS) == (12, 2, 3, 120)
    assert set(links.NOT_MITIGATIONS) == {"M0816", "M1055", "M1056"}
    assert (
        links.LOCK_KEY.startswith(c.Worker.BROKER_KEY_PREFIX) and links.LOCK_RENEW_SECONDS < links.LOCK_SECONDS == 900
    )
    assert [effect.value for effect in c.ControlEffect] == ["prevent", "detect", "contain", "recover"]
    assert c.ControlPickDrop.TOO_MANY.format(most=links.PER_SENTENCE) == "more than 2 controls on one sentence"


def test_the_three_prompts_are_in_the_prompt_file_and_name_controls_by_label_only() -> None:
    """No database id reaches the AI: a control is C1, C2 ... in both control prompts, never a control_id."""
    attack = PROMPTS["scenario"]["attack"]["text"]
    assert c.Writing.RISK_WORDS_SLOT in attack and c.Writing.SCENARIO_WORDS_SLOT in attack
    for field in ("threat_group", "techniques", "mitigations", "other_risks", "LIST_OTHER_RISKS", "TITLES_USED"):
        assert field in attack, field
    links, picks = PROMPTS["controls"]["links"]["text"], PROMPTS["controls"]["picks"]["text"]
    for prompt in (links, picks):
        assert "control_id" not in prompt and f'"label": "{c.ControlLinks.LABEL_PREFIX}' in prompt
        assert all(effect.value in prompt for effect in c.ControlEffect)
    assert '{"matches": [{"label": "C1", "effect": "prevent", "reason":' in links
    assert f"At most {c.ControlLinks.PER_SENTENCE} controls on one sentence" in picks
    assert (
        '{"scenarios": [{"slot": "SC1", "picks": [{"sentence": "S1", "label": "C2", "effect": "prevent"}]}]}' in picks
    )
    sentences = (c.ControlLinks.SCENARIO_SENTENCE_PREFIX, c.ControlLinks.RISK_SENTENCE_PREFIX)
    assert sentences == ("S", "R") and "S1, S2" in picks and "R1, R2" in picks
    assert PROMPTS["version"] == 1  # no existing prompt changed
    assert not (REPO / "app" / "tsg_prompt.txt").exists()  # one copy of the owner's prompt: [scenario.attack]


def test_a_fetch_carries_no_graph_unless_its_reader_gives_one() -> None:
    assert FetchResult((), (), "15.1||9", "15.1").graph == ()
    doc = {"_id": "mitre_attack_ics:x", "record": c.AttackRecord.OBJECT}
    assert FetchResult((), (), "15.1||9", "15.1", graph=(doc,)).graph == (doc,)
