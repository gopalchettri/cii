"""The plan trace (owner 2026-10-19: "Capture how many candidates enter and leave each processing stage,
including explicit rejection reasons"): the counts add up, each candidate left out is named with its stage,
reason and detail, the list is bounded and ordered, and GET /v1/sessions/{id}/plan-trace serves it with what
became of the planned paths. Fake AI models; the route runs on the test MongoDB."""

import dataclasses
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app import container
from app.core.config import get_settings
from app.core.constants import (
    AiTask,
    AttackerCheck,
    CandidateRejection,
    Collection,
    Header,
    PlanLoss,
    PlanStage,
    UnselectedReason,
)
from app.core.database import get_mongodb
from app.domain.scenario import plan_trace
from app.domain.scenario.plan import build_plan
from app.domain.scenario.plan_trace import build_plan_trace, plan_trace_view
from app.domain.scenario.write import held_repeat_of
from app.models.library.library import LibraryThreat
from app.models.scenario.plan import KindPlace, ThreatFindings
from app.models.scenario.views import PlanCounts
from app.worker import jobs
from app.worker.scenario.plan_job import PLAN_JOB_FIELDS
from tests.fakes import FakeRerankModel, items_in
from tests.planner_samples import (
    ADMIN_ABUSE,
    CONTEXT,
    EXFILTRATION,
    FLOOD,
    LOG_WIPE,
    PHISHING,
    RANSOMWARE,
    THREATS,
    S,
    finder,
    gap_fill_for_elevation,
    planned,
    planner_chat,
)
from tests.test_attack_paths import (  # noqa: F401 - `sent` is a fixture used by name
    LANDSCAPE,
    _plan_job,
    _queued_run,
    _stored_run,
    _threats_task,
    sent,
)

#: A library threat whose type links no attacker: never shown to the gate.
UNLINKED = LibraryThreat(7, "Rogue vendor update", 6, "Supply chain", (S.TAMPERING,), ())
_LOST = (
    "not_judged",
    "not_relevant",
    "needs_unrecorded",
    "asset_type_mismatch",
    "needs_unrecorded_elsewhere",
)


def _gate(
    answers: dict[str, dict[str, Any]], kind_needs: dict[tuple[str, str], list[str]] | None = None
) -> Any:
    """A gate answering each candidate by its threat's name (`answers`: relevant ones, with their systems and
    any attacker pick); `kind_needs`: what a threat needs under one kind ({(threat, kind): needs})."""

    def answer(user_prompt: str) -> dict[str, Any]:
        kind = user_prompt.split("STRIDE category: ", 1)[1].split(" (", 1)[0]
        verdicts = []
        for item in items_in(user_prompt, "CANDIDATES"):
            given = answers.get(item["threat"])
            needs = (kind_needs or {}).get((item["threat"], kind), [])
            verdict = {"slot": item["slot"], "relevant": given is not None, "systems": [], "confidence": 80}
            verdict |= {"reason": "It applies." if given else "Nothing here allows it.", "needs": needs}
            verdicts.append(verdict | ({"impact": "HIGH"} | given if given else {}))
        return {"verdicts": verdicts}

    return answer


def _trace(chat: Any, threats: tuple[LibraryThreat, ...] = THREATS, **found: Any) -> dict[str, Any]:
    findings = finder(chat, threats=threats).find_threats(CONTEXT, **found)
    plan = build_plan(findings, 0)
    return build_plan_trace(findings, plan, [], min(len(plan["paths"]), 6))


def _drops(trace: dict[str, Any], stage: PlanStage) -> list[tuple[str, str | None, str, str]]:
    return [
        (d["threat_name"], d["kind"], d["reason"], d["detail"]) for d in trace["drops"] if d["stage"] == stage
    ]


def test_the_counts_add_up_and_each_threat_left_out_says_where_and_why() -> None:
    """Every system of the sample run is OT: an IT threat never reaches the gate, nor one linking no
    attacker; the gate keeps two threats, refuses two as not relevant and one for what it needs."""
    library = (dataclasses.replace(RANSOMWARE, asset_type="IT"), *THREATS[1:], UNLINKED)
    chat = planner_chat({})
    chat.responders[AiTask.RELEVANCE_GATE] = _gate(
        {PHISHING.name: {"systems": ["SYS2"]}, FLOOD.name: {"systems": ["SYS1"]}},
        {(LOG_WIPE.name, S.REPUDIATION): ["jump server"]},
    )
    trace = _trace(chat, library)
    counts = trace["counts"]
    assert (counts["library_threats"], counts["type_fits_no_place"], counts["no_linked_actor"]) == (7, 1, 1)
    assert (counts["gate_asked"], counts["not_relevant"], counts["needs_unrecorded"]) == (5, 2, 1)
    assert counts["gate_accepted"] == 2 == counts["gate_asked"] - sum(counts[name] for name in _LOST)
    assert (counts["threats"], counts["paths"], counts["selected"], counts["first_set"]) == (2, 2, 2, 2)
    assert _drops(trace, PlanStage.PRE_FILTER) == [
        (UNLINKED.name, None, PlanLoss.NO_LINKED_ACTOR, ""),
        (RANSOMWARE.name, None, PlanLoss.TYPE_FITS_NO_PLACE, "asset type IT"),
    ]
    gate = _drops(trace, PlanStage.GATE)
    assert (LOG_WIPE.name, S.REPUDIATION, CandidateRejection.NEEDS_UNRECORDED, "jump server") in gate
    assert {name for name, _, reason, _ in gate if reason == CandidateRejection.NOT_RELEVANT} == {
        EXFILTRATION.name,
        ADMIN_ABUSE.name,
    }
    assert trace["drops_total"] == len(trace["drops"]) == 5 and trace["landscape_cut"] is False


def test_a_need_under_one_kind_is_traced_where_it_refuses_the_threat_under_another() -> None:
    """Ransomware is accepted as Tampering but needs a backup appliance as Denial of Service: refused under
    both, and the trace says which kind the need came from."""
    chat = planner_chat({})
    chat.responders[AiTask.RELEVANCE_GATE] = _gate(
        {RANSOMWARE.name: {"systems": ["SYS1"]}},
        {(RANSOMWARE.name, S.DENIAL_OF_SERVICE): ["backup appliance"]},
    )
    trace = _trace(chat)
    assert (
        RANSOMWARE.name,
        S.DENIAL_OF_SERVICE,
        CandidateRejection.NEEDS_UNRECORDED,
        "backup appliance",
    ) in (_drops(trace, PlanStage.GATE))
    assert _drops(trace, PlanStage.CHECKS) == [
        (
            RANSOMWARE.name,
            S.TAMPERING,
            PlanLoss.NEEDS_UNRECORDED_ELSEWHERE,
            "Denial of Service: backup appliance",
        )
    ]
    assert trace["counts"]["needs_unrecorded_elsewhere"] == 1 and trace["counts"]["paths"] == 0


def test_a_skipped_batch_and_a_threat_no_attacker_fits_are_traced() -> None:
    """On the job's last attempt a broken Spoofing reply is skipped (its threat not judged); the gate finds
    no listed attacker plausible for the flood, so it has no scenario."""
    chat = planner_chat({})
    gate = _gate({FLOOD.name: {"systems": ["SYS1"], "attacker": None, "attacker_reason": "None could."}})
    chat.responders[AiTask.RELEVANCE_GATE] = lambda user: (
        {"verdicts": "?"} if "STRIDE category: Spoofing" in user else gate(user)
    )
    trace = _trace(chat, last_attempt=True)
    assert (PHISHING.name, S.SPOOFING, PlanLoss.NOT_JUDGED, "") in _drops(trace, PlanStage.GATE)
    assert _drops(trace, PlanStage.ATTACKER) == [(FLOOD.name, None, AttackerCheck.NONE_FITS, "None could.")]
    assert (trace["counts"]["not_judged"], trace["counts"]["no_attacker"], trace["counts"]["threats"]) == (
        1,
        1,
        0,
    )


def test_the_drops_are_bounded_and_the_most_telling_come_first(monkeypatch: pytest.MonkeyPatch) -> None:
    """A held path before a gate verdict before the pre-filter; the counts stay whole."""
    monkeypatch.setattr(plan_trace.PlanTraceLimits, "MAX_DROPS", 2)
    chat = planner_chat({})
    chat.responders[AiTask.RELEVANCE_GATE] = _gate({FLOOD.name: {"systems": ["SYS1"]}})
    findings = finder(chat, threats=(*THREATS, UNLINKED)).find_threats(CONTEXT)
    plan = build_plan(findings, 0)
    held = [
        plan_trace.plan_drop("lib:5", FLOOD.name, S.DENIAL_OF_SERVICE, PlanStage.HELD, PlanLoss.ALREADY_HELD)
    ]
    trace = build_plan_trace(findings, plan, held, 0)
    assert [drop["stage"] for drop in trace["drops"]] == [PlanStage.HELD, PlanStage.GATE]
    assert trace["drops_total"] == 1 + 6 + 1  # held, the gate's six not relevant, the unlinked threat
    assert trace["counts"]["already_held"] == 1 and trace["counts"]["paths"] == 2


def test_the_view_adds_what_became_of_the_planned_paths() -> None:
    """Served, still to write, and each path given up with its reason, the scenario it repeats, its spare."""
    stored = {"counts": dict.fromkeys(PlanCounts.model_fields, 0), "landscape_cut": False}
    stored |= {"drops": [], "drops_total": 0}
    path = {"steps": ["lib:1"], "category": "Tampering", "selected": True, "served": None, "abandoned": False}
    paths = [
        path | {"path_id": "p1", "rank": 1, "served": "s1"},
        path | {"path_id": "p2", "rank": 2},
        path
        | {
            "path_id": "p3",
            "rank": 3,
            "abandoned": True,
            "abandoned_reason": "near_duplicate",
            "repeats": "h1",
        }
        | {
            "selected": False,
            "unselected_reason": UnselectedReason.REPLACED_AFTER_FAILURE,
            "replaced_by": "p2",
        },
    ]
    view = plan_trace_view("run-1", stored, paths)
    writing = view.writing
    assert (writing.served, writing.still_to_write, writing.given_up, writing.replaced) == (1, 1, 1, 1)
    (given_up,) = writing.given_up_paths
    assert (given_up.path_id, given_up.reason, given_up.repeats, given_up.replaced_by) == (
        "p3",
        "near_duplicate",
        "h1",
        "p2",
    )


@pytest.fixture(scope="module")
def api_key() -> str:
    _, key = container.get_admin_service().create_api_client(f"trace-{uuid.uuid4().hex[:8]}", None, "test")
    return key


def _who(api_key: str, entity_id: int = 86) -> dict[str, str]:
    return {
        Header.API_KEY: api_key,
        Header.USER_ID: "u1",
        Header.ENTITY_ID: str(entity_id),
        Header.TENANT_ID: "T",
    }


def test_the_route_serves_a_planned_runs_trace_and_404_before_403_for_another_entity(
    client: TestClient,
    api_key: str,
    monkeypatch: pytest.MonkeyPatch,
    sent: list[tuple[Any, ...]],  # noqa: F811 - the imported fixture
) -> None:
    monkeypatch.setattr(get_settings(), "total_scenario_count", 0)
    chat = planner_chat({LOG_WIPE.name: ["SYS1"], ADMIN_ABUSE.name: ["SYS2"]})
    planned, waiting = _queued_run(), _queued_run()
    jobs.run_leased_job(
        _threats_task(), Collection.SESSIONS, planned, 1, _plan_job(finder(chat)), fields=PLAN_JOB_FIELDS
    )
    answer = client.get(f"/v1/sessions/{planned}/plan-trace", headers=_who(api_key))
    assert answer.status_code == 200, answer.text
    body = answer.json()
    assert body["counts"] == _stored_run(planned)["plan_trace"]["counts"] and body["counts"]["paths"] == 2
    assert body["writing"] == {
        "served": 0,
        "still_to_write": 2,
        "given_up": 0,
        "replaced": 0,
        "given_up_paths": [],
    }
    assert client.get(f"/v1/sessions/{waiting}/plan-trace", headers=_who(api_key)).status_code == 404
    assert client.get(f"/v1/sessions/{planned}/plan-trace", headers=_who(api_key, 99)).status_code == 403
    get_mongodb()[Collection.SESSIONS].delete_many({"_id": {"$in": [planned, waiting]}})


def test_a_gap_fill_proposal_not_kept_is_traced_with_its_reason() -> None:
    """Elevation of Privilege has nothing accepted: the AI proposes a threat that repeats a library one the
    gate already judged, so it is not kept, and the trace says so (aliases turned to system names)."""
    proposal = {
        "applies": True,
        "threat_type": "Privilege misuse",
        "threat": "Insider misuses SYS1 admin rights",
    }
    proposal |= {"attacker": "Malicious insider", "systems": [], "reason": "Admins exist."}
    chat = planner_chat({FLOOD.name: ["SYS1"]})
    chat.responders[AiTask.GAP_FILL] = gap_fill_for_elevation(proposal)
    rerank = FakeRerankModel({("Insider misuses SYS1 admin rights", ADMIN_ABUSE.name): 90.0})
    findings = finder(chat, rerank).find_threats(CONTEXT)
    plan = build_plan(findings, 0)
    trace = build_plan_trace(findings, plan, [], 0)
    assert _drops(trace, PlanStage.GAP_FILL) == [
        ("Insider misuses SCADA server admin rights", S.ELEVATION_OF_PRIVILEGE, PlanLoss.LIBRARY_REPEAT, "")
    ]
    assert trace["counts"]["gap_fill_lost"] == 1 and trace["counts"]["ai_threats"] == 0


def test_a_kind_already_held_never_takes_a_turn_from_the_threats_other_kinds() -> None:
    """Held paths leave before the ranking: X's held Spoofing never pushes its only new kind behind Y's second
    kind, so with room for two the plan tells X and Y once each."""
    x = planned("lib:1", "X", (321,), categories=(S.SPOOFING, S.TAMPERING), impact=3)
    x = dataclasses.replace(
        x, kind_places=((S.SPOOFING, KindPlace((321,), 3, 70.0)), (S.TAMPERING, KindPlace((321,), 1, 70.0)))
    )
    y = planned(
        "lib:2", "Y", (321,), categories=(S.INFORMATION_DISCLOSURE, S.ELEVATION_OF_PRIVILEGE), impact=2
    )
    held = [{"_id": "h1", "content": {"threat": {"key": "lib:1"}, "category": S.SPOOFING, "systems": []}}]
    findings = ThreatFindings([x, y], [], LANDSCAPE)
    plan = build_plan(findings, 2, lambda path, threat: held_repeat_of(path, threat, held) is not None)
    assert [(p["steps"], p["category"]) for p in plan["paths"] if p["selected"]] == [
        (["lib:2"], S.INFORMATION_DISCLOSURE),
        (["lib:1"], S.TAMPERING),
    ]
