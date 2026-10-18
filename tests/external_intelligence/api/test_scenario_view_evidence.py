"""The scenario view shows the evidence its text cites, in marker order, without scores, and the audit; every
other scenario shows nothing of it."""

from datetime import UTC, datetime
from typing import Any

from app.core.constants import Decision, RunKind, ScenarioStatus
from app.services.scenario.results import build_scenario_view
from tests.external_intelligence.conftest import STORY_MARKED
from tests.external_intelligence.fakes import TECHNIQUE


def _record(**content: Any) -> dict[str, Any]:
    return {
        "_id": "s1",
        "session_id": "r1",
        "version": 1,
        "status": ScenarioStatus.DONE,
        "source": RunKind.GENERATED,
        "decision": Decision.PENDING,
        "findings": [],
        "created_at": datetime.now(UTC),
        "content": content,
    }


def test_only_the_evidence_the_text_cites_is_shown_in_marker_order_without_scores() -> None:
    first = {"n": 1, **TECHNIQUE.as_doc()}
    second = {"n": 2, **TECHNIQUE.as_doc(), "ref": "T0001", "title": "Other"}
    third = {"n": 3, **TECHNIQUE.as_doc(), "ref": "T0002", "title": "Never cited"}
    statement = STORY_MARKED.replace("before [1]", "before [2] and again [1]")
    view = build_scenario_view(
        _record(
            statement=statement,
            evidence=[first, second, third],
            evidence_mode="source-documented",
            intel_search={"query": "q", "considered": []},
        )
    )
    assert [item.n for item in view.evidence] == [2, 1]  # the order the text cites them; 3 is not shown
    assert view.evidence[1].ref == "T0839" and view.evidence[1].url.startswith("https://")
    assert "score" not in view.evidence[0].model_dump()
    assert view.evidence_mode == "source-documented" and view.evidence_search == {
        "query": "q",
        "considered": [],
    }


def test_a_scenario_with_no_evidence_shows_null_and_empty() -> None:
    view = build_scenario_view(_record(statement="It could stop."))
    assert (view.evidence_mode, view.evidence, view.evidence_search) == (None, [], None)
