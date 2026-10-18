"""A control of the library's AI domain is mapped only to a card whose threat is about AI: the reranker
over-scores AI-for-OT controls on any OT card."""

import copy

import pytest

from app.core.constants import Controls
from app.domain.scenario.controls import ControlMapper, controls_record, is_about_ai
from app.models.library.library import LibraryControl
from tests.test_control_mapping import _OT_CONTEXT, _SCENARIO, _ScoresByText, _snapshot

_AI_CONTROL = LibraryControl(
    4, "C-AI", "OT", Controls.AI_DOMAIN, "Sensitive OT Data Protection in AI", "OT data"
)
_ACCESS = LibraryControl(
    5, "C-ACC", "OT", "Identification & Authentication", "Account Management", "Accounts"
)


@pytest.mark.parametrize(
    ("threat", "about_ai"),
    [
        ({"type": "AI Abuse", "name": "Prompt injection against AI assistant"}, True),
        ({"type": "AI Abuse", "name": "AI-assisted OT decision or data manipulation"}, True),
        ({"type": "Data Theft/Tampering", "name": "Shadow SaaS or personal GenAI data leakage"}, True),
        ({"type": "Model Abuse", "name": "LLM sensitive disclosure"}, True),
        ({"type": "Model Abuse", "name": "Poisoned machine learning features"}, True),
        ({"type": "Credential Abuse", "name": "OT remote credential theft and session takeover"}, False),
        ({"type": "Protocol/Command Abuse", "name": "OT protocol command abuse"}, False),
        ({"type": "Social Engineering", "name": "Email account takeover of maintenance staff"}, False),
        ({"type": "Injection", "name": "HTML injection on the operator portal"}, False),  # "ML" in a word
        (
            {"type": "Physical", "name": "Rail signal cabinet tampering"},
            False,
        ),  # "ai" inside words, lower case
        ({}, False),
    ],
)
def test_a_threat_is_about_ai_only_when_its_type_or_name_says_so(
    threat: dict[str, str], about_ai: bool
) -> None:
    assert is_about_ai(threat) is about_ai


def test_the_search_leaves_out_ai_controls_only_when_asked() -> None:
    snapshot = _snapshot(_AI_CONTROL, _ACCESS)
    for allowed in (None, {"OT", r"IT\OT"}):
        (every,) = snapshot.find_controls(["OT data access"], 5, allowed)
        (no_ai,) = snapshot.find_controls(["OT data access"], 5, allowed, ai_controls=False)
        assert {c.code for c, _ in every} == {"C-AI", "C-ACC"} and {c.code for c, _ in no_ai} == {"C-ACC"}


def test_a_non_ai_card_never_gets_an_ai_control_even_when_it_scores_best_and_an_ai_card_can() -> None:
    rerank = _ScoresByText({"Sensitive OT Data Protection in AI": 90.0, "Account Management": 70.0})
    snapshot = _snapshot(_AI_CONTROL, _ACCESS)
    mapping = ControlMapper(rerank).map_controls(_SCENARIO, _OT_CONTEXT, snapshot)  # type: ignore[arg-type]
    assert [item.code for item in mapping.items] == ["C-ACC"]
    assert all("Sensitive OT Data Protection in AI" not in doc for _, docs in rerank.asked for doc in docs)
    assert controls_record(mapping, snapshot)["made_with"]["ai_controls"] is False
    ai_card = copy.deepcopy(_SCENARIO)
    ai_card["content"]["threat"] = {
        "type": "AI Abuse",
        "name": "AI-assisted OT decision or data manipulation",
    }
    mapping = ControlMapper(rerank).map_controls(ai_card, _OT_CONTEXT, snapshot)  # type: ignore[arg-type]
    assert [item.code for item in mapping.items] == ["C-AI", "C-ACC"]
    assert controls_record(mapping, snapshot)["made_with"]["ai_controls"] is True
