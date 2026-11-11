"""Golden copies of control mapping: each card's control query, the reranker calls and the stored controls
record, the alternatives a plan reads (reused and searched again), and the refusals, for a fixed library and
the fixed cards tests/goldens/scenario/input_cards.json."""

import copy
import json
from types import SimpleNamespace
from typing import Any

import pytest

from app.core.constants import Controls
from app.core.exceptions import ControlsNotMapped
from app.domain.scenario.write import ControlMapper, build_controls_record
from app.models.library.library import LibraryControl, ThreatLibrary
from app.search.service import LibrarySearch
from app.worker.scenario.controls_job import RunControls
from tests.scenario_goldens import GOLDENS, RecordingEmbeddings, check_golden
from tests.test_scenario_goldens_plan import THREE_SYSTEMS

CARDS = json.loads((GOLDENS / "input_cards.json").read_text(encoding="utf-8"))["cards"]
CONTROLS = (
    LibraryControl(1, "C-IT", "IT", "BCDR", "Offline backup", "Keep an offline backup copy"),
    LibraryControl(2, "C-OT", "OT", "BCDR", "Backup of controller logic", "Back up PLC and SCADA logic"),
    LibraryControl(3, "C-ANY", None, "BCDR", "Backup policy", "A written backup policy"),
    LibraryControl(4, "C-MFA", "OT", "Access", "Multi-factor login", "Ask a second factor at every login"),
    LibraryControl(5, "C-MFA2", "IT", "Access", "Multi-factor login", "Ask a second factor at every login"),
    LibraryControl(6, "C-AI", None, Controls.AI_DOMAIN, "Model input checks", "Check what reaches a model"),
    LibraryControl(7, "C-SEG", r"IT\OT", "Network", "Network segmentation", "Split the control network"),
    LibraryControl(8, "C-LOG", "OT", "Monitoring", "Central logging", "Collect every system's logs"),
)
SCORES = {
    "Offline backup": 70.0,
    "Backup of controller logic": 82.0,
    "Backup policy": 61.0,
    "Multi-factor login": 75.0,
    "Model input checks": 90.0,
    "Network segmentation": 58.0,
    "Central logging": 40.0,
}


class _Reranker:
    """Scores each control by its name, lower for a query about the Historian; records every call."""

    def __init__(self, scores: dict[str, float]) -> None:
        self.scores, self.calls = scores, []

    def score_relevance(self, query: str, documents: list[str]) -> list[float]:
        self.calls.append({"query": query, "documents": list(documents)})
        less = 25.0 if "Historian" in query else 0.0
        return [max(self.scores.get(document.split(":")[0], 0.0) - less, 0.0) for document in documents]


def _snapshot(controls: tuple[LibraryControl, ...]) -> tuple[Any, RecordingEmbeddings]:
    stamp = (("Control_Library", b"\x07"), ("Threat_Catalogue", b"\x01"))
    library = SimpleNamespace(threat_library=ThreatLibrary((), ()), control_library=controls, stamp=stamp)
    embeddings = RecordingEmbeddings()
    search = LibrarySearch(SimpleNamespace(get_loaded_libraries=lambda: library), embeddings)  # type: ignore[arg-type]
    return search.snapshot(), embeddings


def _map(card: dict[str, Any], rerank: _Reranker, controls: tuple[LibraryControl, ...] = CONTROLS) -> Any:
    snapshot, embeddings = _snapshot(controls)
    mapping = ControlMapper(rerank).map_controls(card, THREE_SYSTEMS, snapshot)  # type: ignore[arg-type]
    return {"record": build_controls_record(mapping, snapshot), "embeddings": embeddings.texts}


def test_golden_controls_for_every_card() -> None:
    rerank = _Reranker(SCORES)
    mapped = [{"path_id": card["path_id"]} | _map(card, rerank) for card in CARDS]
    check_golden("controls_cards", {"mapped": mapped, "reranks": rerank.calls})


def _about_ai(card: dict[str, Any]) -> dict[str, Any]:
    card = copy.deepcopy(card)
    card["content"]["threat"] |= {
        "name": "Poisoning of the AI model that forecasts load",
        "type": "AI misuse",
    }
    return card


def test_golden_controls_nearest_other_type_ai_and_empty() -> None:
    card, low = CARDS[0], _Reranker(dict.fromkeys(SCORES, 30.0))
    it_only = tuple(control for control in CONTROLS if control.asset_type == "IT")
    outcomes: dict[str, Any] = {
        "nearest_only": _map(card, low),
        "other_type": _map(card, _Reranker(SCORES), it_only),
    }
    ai_rerank = _Reranker(SCORES)
    outcomes["about_ai"] = _map(_about_ai(card), ai_rerank) | {"reranks": ai_rerank.calls}
    with pytest.raises(ControlsNotMapped) as empty:
        _map(card, _Reranker(SCORES), ())
    outcomes["empty"] = {"code": empty.value.code, "message": empty.value.message}
    outcomes["reranks"] = low.calls
    check_golden("controls_cases", outcomes)


def test_golden_control_alternatives_reused_and_searched_again() -> None:
    card, rerank = CARDS[1], _Reranker(SCORES)
    snapshot, _ = _snapshot(CONTROLS)
    mapper = ControlMapper(rerank)  # type: ignore[arg-type]
    record = build_controls_record(mapper.map_controls(card, THREE_SYSTEMS, snapshot), snapshot)
    before = len(rerank.calls)
    reused = mapper.find_alternative_controls(card, THREE_SYSTEMS, snapshot, {2}, 3, record)
    reused_calls = len(rerank.calls) - before
    stale = copy.deepcopy(record)
    stale["made_with"]["candidates"] = 1
    searched = mapper.find_alternative_controls(card, THREE_SYSTEMS, snapshot, {2, 4}, 2, stale)
    plain = [[(control.control_id, score) for control, score in found] for found in (reused, searched)]
    outcome = {
        "reused": plain[0],
        "reused_calls": reused_calls,
        "searched": plain[1],
        "reranks": rerank.calls,
    }
    check_golden("controls_alternatives", outcome)


def test_golden_control_queries_embedded_in_one_call() -> None:
    snapshot, embeddings = _snapshot(CONTROLS)
    run = RunControls("run", "task", THREE_SYSTEMS.to_record(), None, None, snapshot, None)  # type: ignore[arg-type]
    # each claimed scenario has its own id; the fixture's original and evidence cards share theirs
    run._embed_queries([card | {"_id": f"{card['_id']}-{place}"} for place, card in enumerate(CARDS)])
    check_golden("controls_embedded", {"embeddings": embeddings.texts})
