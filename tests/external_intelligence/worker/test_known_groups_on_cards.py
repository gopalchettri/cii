"""G230 in the write job (owner 2026-10-14: "Name the real group"): with external intelligence on, the
evidence search is asked for the threat's acting actor, its real groups are kept on the plan with the evidence
(a retry or a regenerate reuses them) and shown on the card, each under the number its technique is cited by;
with it off, a card has none. Runs on the test MongoDB with the fake chat model and the fake finder."""

from typing import Any

import pytest

from app.core.constants import GroupRelevance, KnownGroupMatch, ThreatGroupKind
from app.models.external_intelligence.known_groups import KnownGroup
from app.models.scenario_views import ScenarioView
from tests.external_intelligence.conftest import Intel
from tests.test_writing_job import (  # noqa: F401 - fixtures used by name
    _deliver_until_done,
    _queued_run,
    _scenarios_of,
    _sessions,
    chat,
    sent,
)

pytestmark = pytest.mark.usefixtures("sent")

SANDWORM = KnownGroup(
    name="Sandworm Team",
    group_id="G0034",
    url="https://attack.mitre.org/groups/G0034/",
    kind=ThreatGroupKind.NATION_STATE,
    who="Sandworm Team is a destructive threat group attributed to Russia's GRU.",
    through="Industroyer",
    how="Industroyer toggles breakers to the open state.",
    technique="T0839",  # the fake finder's evidence, cited [1] by the fake story
    technique_title="Module Firmware",
    match=KnownGroupMatch.USED_THIS_TECHNIQUE,
    relevance=(GroupRelevance.TARGETED_REGION, GroupRelevance.TARGETED_SECTOR),  # G232
)
SIMILAR = KnownGroup(
    **(
        SANDWORM.as_doc()
        | {"name": "Kimsuky", "technique": "T1071", "match": "used_related_technique", "relevance": ()}
    )
)


def _card(record_id: str) -> dict[str, Any]:
    [card] = _scenarios_of(record_id)
    return card


@pytest.mark.usefixtures("story_chat")
def test_with_intelligence_on_the_card_names_the_real_groups_under_the_cited_number(intel: Intel) -> None:
    intel.finder.groups = (SANDWORM, SIMILAR)
    record_id = _queued_run(["Threat 1"])
    _deliver_until_done(record_id)
    [requests] = [requests for requests, _ in intel.finder.calls]
    assert requests[0].actor == "Cybercriminal"  # the threat's acting actor: groups of its kind
    [threat] = _sessions().find_one({"_id": record_id})["plan"]["threats"]
    assert [group["name"] for group in threat["known_groups"]] == ["Sandworm Team", "Kimsuky"]  # kept
    card = _card(record_id)
    shown = [(group["name"], group["cited"]) for group in card["content"]["known_groups"]]
    assert shown == [("Sandworm Team", 1), ("Kimsuky", None)]  # T1071 is not cited by the story
    view = ScenarioView.from_record(card).known_groups
    assert (view[0].attack_id, view[0].through, view[0].cited, view[1].cited) == (
        "G0034",
        "Industroyer",
        1,
        None,
    )
    # G232 (live 2026-10-14: the API dropped it): why each group is near this asset reaches the API
    assert [group.relevance for group in view] == [["targeted_region", "targeted_sector"], []]


def test_with_intelligence_off_a_card_has_no_groups(chat: Any) -> None:  # noqa: F811 - the imported fixture
    record_id = _queued_run(["Threat 1"])
    _deliver_until_done(record_id)
    card = _card(record_id)
    assert "known_groups" not in card["content"] and ScenarioView.from_record(card).known_groups == []
