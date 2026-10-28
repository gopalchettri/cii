"""scripts/scorecard.py, the owner's checks of every served card (2026-10-18): a card is judged by the
app's own rules, so one the app writes as correct passes, and a fault names what is really wrong."""

import importlib.util
import sys
from pathlib import Path

import pytest

from app.core import config
from app.core.config import Settings
from app.core.constants import PromptVersion

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))  # it imports debug_tools from its own folder
try:
    _SPEC = importlib.util.spec_from_file_location("scorecard", REPO / "scripts" / "scorecard.py")
    scorecard = importlib.util.module_from_spec(_SPEC)  # type: ignore[arg-type]
    _SPEC.loader.exec_module(scorecard)  # type: ignore[union-attr]
finally:
    sys.path.remove(str(REPO / "scripts"))

NOT_ESTABLISHED = "no reviewer verdict recorded: correctness not established"


def test_the_acting_attacker_is_one_the_plan_listed_for_its_threat() -> None:
    acting = {"id": 4, "role": "acting", "name": "Nation-state"}
    threats = {"lib:7": {"key": "lib:7", "actors": [{"id": 4, "name": "Nation-state", "role": "acting"}]}}
    card = {"content": {"threat": {"key": "lib:7"}, "actors": [acting]}}
    assert scorecard.actor(card, threats) == ""
    contributing = {"content": card["content"] | {"actors": [acting | {"role": "contributing"}]}}
    assert scorecard.actor(contributing, threats) == "no acting threat actor"
    unlisted = {"content": card["content"] | {"actors": [acting | {"id": 9, "name": "Insider"}]}}
    assert scorecard.actor(unlisted, threats) == "Insider is not an attacker the plan listed for its threat"
    other_threat = {"content": card["content"] | {"threat": {"key": "lib:8"}}}
    assert scorecard.actor(other_threat, threats) != ""


def test_the_threat_and_risk_are_the_reviewers_verdicts() -> None:
    """A card stored before the verdicts, or a check not made, has none: correctness is not established."""
    assert scorecard.threat({"plan_check": {"status": "consistent"}}) == NOT_ESTABLISHED
    assert scorecard.risk({"plan_check": None}) == NOT_ESTABLISHED
    judged = {"plan_check": {"same_threat": False, "same_impact": True}}
    assert (scorecard.threat(judged), scorecard.risk(judged)) == ("the statement tells another threat", "")


def test_evidence_is_cited_with_intelligence_on_and_absent_with_it_off() -> None:
    story = {"prompt_version": PromptVersion.SCENARIO_WRITER_EVIDENCE, "risk_statement": "Pumps stop."}
    entry = {"n": 1, "url": "https://example.test/a", "ref": "A"}
    assert scorecard.evidence({"content": story | {"statement": "Abuse [1].", "evidence": [entry]}}) == ""
    assert scorecard.evidence({"content": story | {"statement": "Abuse.", "evidence": [entry]}}) == (
        "cites no evidence"
    )
    assert scorecard.evidence({"content": story | {"statement": "Abuse [2].", "evidence": [entry]}}) == (
        "markers [2] name no stored source"
    )
    plain = {
        "prompt_version": PromptVersion.SCENARIO_WRITER,
        "statement": "Abuse.",
        "risk_statement": "Stop.",
    }
    assert scorecard.evidence({"content": plain}) == ""
    assert (
        scorecard.evidence({"content": plain | {"statement": "Abuse [1]."}})
        == "cites [1] with intelligence off"
    )
    assert scorecard.evidence({"content": plain | {"evidence": [entry]}}) == "cites [] with intelligence off"


def test_a_nearest_story_and_one_written_without_evidence_pass() -> None:
    """Owner 2026-10-19: the nearest evidence is cited like any other; none found, the card is written
    without (inferred) and passes with a note. An on-story with a mode but no citation still fails."""
    story = {"prompt_version": PromptVersion.SCENARIO_WRITER_EVIDENCE, "risk_statement": "Pumps stop."}
    entry = {"n": 1, "url": "https://example.test/a", "ref": "A", "nearest": True}
    cited = {"statement": "Abuse [1].", "evidence": [entry], "evidence_mode": "nearest"}
    nearest = {"content": story | cited}
    assert scorecard.evidence(nearest) == "" and scorecard.evidence_note(nearest) == ""
    for mode in ("nearest", "source-documented"):
        uncited = {"content": story | {"statement": "Abuse.", "evidence": [entry], "evidence_mode": mode}}
        assert scorecard.evidence(uncited) == "cites no evidence"
    plain = {
        "prompt_version": PromptVersion.SCENARIO_WRITER,
        "statement": "Abuse.",
        "risk_statement": "Stop.",
    }
    without = {"content": plain | {"evidence_mode": "inferred", "evidence": []}}
    assert scorecard.evidence(without) == "" and scorecard.evidence_note(without) == scorecard.WRITTEN_WITHOUT
    assert scorecard.WRITTEN_WITHOUT == "no evidence found: written without"
    marked = {"content": without["content"] | {"statement": "Abuse [1]."}}
    assert scorecard.evidence(marked) == "cites [1] though written without evidence"


def test_each_text_is_within_its_configured_word_maximum(monkeypatch: pytest.MonkeyPatch) -> None:
    """The narrative (the statement less its cited passage), the passage and the risk, each against its own
    maximum; the [1] marker is no word of the passage."""
    settings = Settings(  # type: ignore[call-arg]
        THREAT_SCENARIO_WORD_LIMIT="1-5", RISK_STATEMENT_WORD_LIMIT="1-3", EVIDENCE_STATEMENT_WORD_LIMIT="1-4"
    )
    monkeypatch.setattr(config, "get_settings", lambda: settings)
    passage = "In real-world attacks, APT41 did"
    card = {"content": {"statement": f"One two three four five {passage} [1].", "risk_statement": "a b c"}}
    card["content"]["evidence"] = [{"n": 1, "supports": passage}]
    assert scorecard.words(card) == "evidence passage 5 words, over 4"
    short = {"content": card["content"] | {"evidence": [{"n": 1, "supports": "A B C D"}]}}
    short["content"]["statement"] = "One two three four five A B C D [1]."
    assert scorecard.words(short) == ""
    long = {
        "content": short["content"] | {"statement": "1 2 3 4 5 6 A B C D [1].", "risk_statement": "a b c d"}
    }
    assert scorecard.words(long) == "statement 6 words, over 5; risk 4 words, over 3"


def test_a_copy_of_an_accepted_replaced_version_is_a_duplicate_but_not_of_a_rejected_one() -> None:
    """Every served card is scored, an accepted Q v1 too (it stays in the register after its path was
    regenerated). A replaced rejected version has left the register (MAPPED_VERSIONS), so a copy of it is no
    duplicate."""
    said = {"statement": "An attacker abuses the historian's remote service to stop the pumps."}
    q1 = {"_id": "q1", "path_id": "Q", "content": said, "superseded_by": "q2", "decision": "accepted"}
    r1 = {"_id": "r1", "path_id": "R", "content": said, "superseded_by": None, "decision": "pending"}
    q2 = {"_id": "q2", "path_id": "Q", "content": {"statement": "Another event."}, "superseded_by": None}
    cards = [card | {"status": "done"} for card in (q1, r1, q2)]
    served = scorecard.served_cards(cards)
    assert [c["_id"] for c in served] == ["q1", "r1", "q2"]
    assert list(scorecard.duplicates(served)) == ["r1"]
    rejected = scorecard.served_cards([cards[0] | {"decision": "rejected"}, *cards[1:]])
    assert len(rejected) == 3 and scorecard.duplicates(rejected) == {}


def test_the_same_threat_kind_and_systems_on_two_paths_is_a_duplicate() -> None:
    told = {"threat": {"key": "lib:7"}, "category": "Tampering", "systems": [{"id": 1}], "statement": "One."}
    first = {"_id": "a", "path_id": "A", "content": told, "superseded_by": None}
    second = {"_id": "b", "path_id": "B", "content": told | {"statement": "Two."}, "superseded_by": None}
    assert list(scorecard.duplicates([first, second])) == ["b"]
