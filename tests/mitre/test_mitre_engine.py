"""The MITRE run's engine (ADR-010) with synthetic MITRE data and FakeChatModel: actor selection, planning, one
scenario's writing and checks, and the parallel writers' scheduling (ported from the POC's tests)."""

import json
from typing import Any

import pytest

from app.ai import UnreadableAiAnswer
from app.core.constants import AiTask, ErrorCode, PromptVersion, StrideCategory
from app.core.exceptions import JobFailed
from app.core.prompts import MITRE_PROMPTS
from app.domain.scenario.mitre_scenario import mitre_engine as engine
from app.domain.shared.ask_ai import call_tokens
from app.search.mitre.mitre_index import MitreIndex, build_mitre_index, get_mitre_id, opening_sentences
from tests.fakes import FakeChatModel
from tests.mitre.mitre_samples import (
    ALPHA,
    ASSET,
    BETA,
    CAMPAIGN,
    CONTROL_LOGIC,
    DELTA,
    DENIAL_OF_CONTROL,
    GAMMA,
    IT_ASSET,
    LOSS_OF_AVAILABILITY,
    MIXED_ASSET,
    PHISHING,
    QUOTES,
    THREAT_TYPES,
    VALID_ACCOUNTS,
    ZETA,
    MitreChat,
    actor_row,
    asset_context,
    documents,
    fake_paths,
    group,
    index_with_delta,
    index_with_ics_assets,
    planned_path_techniques,
    planner_answer,
    relationship,
    sample_index,
    selection_of,
    settings,
    writer_answer,
)

TAMPERING_PATH = (["T1566", "T0831"], "Tampering")


@pytest.fixture(scope="module")
def index() -> MitreIndex:
    return sample_index()


def answering(answer: dict[str, Any]) -> Any:
    """A responder giving the same answer to every prompt."""

    def respond(user_prompt: str) -> dict[str, Any]:
        return json.loads(json.dumps(answer))

    return respond


def chat_with(
    actor_rows: list[dict[str, Any]] | None = None,
    plan: dict[str, Any] | None = None,
    scenario: dict[str, Any] | None = None,
) -> FakeChatModel:
    chat = MitreChat()
    chat.responders[AiTask.MITRE_ACTOR_SELECTION] = answering({"relevant_actors": actor_rows or []})
    chat.responders[AiTask.MITRE_PLAN] = answering(plan or planner_answer(TAMPERING_PATH))
    chat.responders[AiTask.MITRE_WRITE] = answering({"scenarios": [scenario or writer_answer()]})
    return chat


def inputs_of(chat: FakeChatModel, task: AiTask) -> list[dict[str, Any]]:
    asked = []
    for user_prompt in chat.asked(task):
        asked.append(json.loads(user_prompt))
    return asked


def select_actors(
    index: MitreIndex, rows_for_slice: Any, **setting_changes: Any
) -> tuple[dict[str, Any], FakeChatModel]:
    """The actor selection with rows_for_slice(slice input) answering (or raising for) each slice."""
    chat = MitreChat()

    def respond(user_prompt: str) -> dict[str, Any]:
        return {"relevant_actors": rows_for_slice(json.loads(user_prompt))}

    chat.responders[AiTask.MITRE_ACTOR_SELECTION] = respond
    selection = engine.select_relevant_actors_from_all_mitre_actors(
        chat, asset_context(), index, settings(**setting_changes)
    )
    return selection, chat


def slice_lists(data: dict[str, Any], mitre_id: str) -> bool:
    """True when this actor-selection slice input carries the profile line of mitre_id."""
    return any(line.startswith(mitre_id + " |") for line in data["actor_profiles"].split("\n"))


def one_profile_per_slice_limit(index: MitreIndex) -> int:
    """A call limit that fits the actor prompt and the asset with one profile line, never two."""
    prompt = engine.actor_slice_prompt(MITRE_PROMPTS["actors"]["text"], asset_context(), [])
    largest_line = 0
    for profile in index["actor_profiles"]:
        largest_line = max(largest_line, profile["tokens"])
    return call_tokens(prompt, MitreChat(), AiTask.MITRE_ACTOR_SELECTION) + largest_line + 5


def plan(chat: FakeChatModel, index: MitreIndex, asset: dict[str, Any] | None = None, **changes: Any) -> dict[str, Any]:
    selection = selection_of((ZETA, 5))
    return engine.plan_attack_paths(chat, asset_context(asset), index, settings(**changes), selection)


def first_planned_path(
    index: MitreIndex, asset: dict[str, Any] | None = None, technique_ids: tuple[str, ...] = ("T1566", "T0831")
) -> dict[str, Any]:
    planned = plan(chat_with(plan=planner_answer((list(technique_ids), "Tampering"))), index, asset)
    return dict(planned["paths"][0])


def write_scenario(
    chat: FakeChatModel,
    planned_path: dict[str, Any],
    index: MitreIndex,
    ranked: tuple[str, ...] = (ZETA, ALPHA, GAMMA),
    asset: dict[str, Any] | None = None,
    used: list[dict[str, str]] | None = None,
    selection: dict[str, Any] | None = None,
    system_mitre_assets: dict[str, list[str]] | None = None,
    **changes: Any,
) -> dict[str, Any] | None:
    writing = {
        "asset_context": asset_context(asset),
        "index": index,
        "settings": settings(**changes),
        "actor_selection": selection or selection_of((ZETA, 5)),
        "system_mitre_assets": system_mitre_assets or {},
        "threat_types": THREAT_TYPES,
    }
    prompt = engine.writer_prompt(writing["settings"])
    brief = engine.build_path_brief(chat, prompt, (0, planned_path, list(ranked)), list(used or []), writing)
    if brief is None:
        return None
    return engine.write_briefs(chat, prompt, [brief], writing)[brief["slot"]]


# ----------------------------------------------------------------------------- actor selection


def test_actor_selection_slices_are_rechecked_and_no_actor_is_lost(index: MitreIndex) -> None:
    underestimated_profiles = []
    for profile in index["actor_profiles"]:
        underestimated_profiles.append({**profile, "tokens": 1})
    underestimated = {**index, "actor_profiles": underestimated_profiles}
    limit = one_profile_per_slice_limit(index)

    def no_rows(data: dict[str, Any]) -> list[Any]:
        return []

    selection, chat = select_actors(underestimated, no_rows, mitre_actor_slice_tokens_limit=limit)
    asked = inputs_of(chat, AiTask.MITRE_ACTOR_SELECTION)
    assert len(asked) == 5 and selection["status"] == "empty"  # packed as one slice, split by the re-check
    for user_prompt in chat.asked(AiTask.MITRE_ACTOR_SELECTION):
        actor_prompt = (MITRE_PROMPTS["actors"]["text"], user_prompt)
        assert call_tokens(actor_prompt, chat, AiTask.MITRE_ACTOR_SELECTION) <= limit
    for profile in index["actor_profiles"]:
        appearances = 0
        for data in asked:
            if profile["line"] in data["actor_profiles"].split("\n"):
                appearances += 1
        assert appearances == 1


def test_actor_selection_keeps_only_rows_backed_by_the_mitre_description(index: MitreIndex) -> None:
    def rows(data: dict[str, Any]) -> list[Any]:
        return [
            actor_row("G0101", 3),
            actor_row("G0101", 5),  # the higher relevance is kept
            actor_row("G0102", 4, quote="steals cryptocurrency from banks worldwide"),  # not in its description
            actor_row("G0103", 1),
            actor_row("G0104", 6),
            actor_row("G0104", True),  # relevance out of range
            actor_row("G0104", 4, reason=" "),
            actor_row("G0104", 4, quote="an industrial group"),  # no reason; a short quote
            actor_row("G0104", 4, reason="Uses T9999 against grids."),  # an invented MITRE ID
            {**actor_row("G0101", 4), "mitre_id": "G9999"},
            "not a row",
        ]

    selection, chat = select_actors(index, rows)
    assert len(chat.asked(AiTask.MITRE_ACTOR_SELECTION)) == 1 and selection["status"] == "complete"
    assert selection["ranked_actor_ids"] == [ZETA]
    assert (
        selection["actors"][ZETA]["relevance"] == 5 and selection["actors"][ZETA]["evidence_quote"] == QUOTES["G0101"]
    )
    assert selection["rejected_rows"] == {
        "quote not in the actor's MITRE description": 1,
        "relevance not 2-5": 3,
        "no reason": 1,
        "quote shorter than 5 words": 1,
        "invented MITRE ID in the reason": 1,
        "unknown actor id": 1,
        "not an object": 1,
    }


def test_actor_selection_drops_an_id_listed_by_another_slice(index: MitreIndex) -> None:
    def rows(data: dict[str, Any]) -> list[Any]:
        if slice_lists(data, "G0101"):
            return [actor_row("G0101", 3)]
        return [actor_row("G0101", 5)]  # Zeta is not in this slice

    selection, chat = select_actors(index, rows, mitre_actor_slice_tokens_limit=one_profile_per_slice_limit(index))
    assert len(chat.asked(AiTask.MITRE_ACTOR_SELECTION)) == 5 and selection["actors"][ZETA]["relevance"] == 3


def test_actor_selection_ranks_by_relevance_then_technique_count_then_name(index: MitreIndex) -> None:
    def rows(data: dict[str, Any]) -> list[Any]:
        return [actor_row("G0101", 3), actor_row("G0102", 4), actor_row("G0103", 3), actor_row("G0104", 3)]

    selection, _ = select_actors(index, rows)
    assert selection["ranked_actor_ids"] == [ALPHA, GAMMA, ZETA, BETA]  # Gamma and Zeta: 2 techniques; Beta none


def test_a_relevant_campaign_lifts_the_group_it_is_attributed_to(index: MitreIndex) -> None:
    def campaign_only(data: dict[str, Any]) -> list[Any]:
        return [actor_row("C0101", 4, reason="Targeted water utilities.")]

    selection, _ = select_actors(index, campaign_only)
    assert selection["actors"][ZETA]["relevance"] == 4
    assert "through the Own op campaign" in selection["actors"][ZETA]["reason"]
    assert set(selection["ranked_actor_ids"]) == {ZETA, CAMPAIGN}

    def campaign_above_group(data: dict[str, Any]) -> list[Any]:
        return [actor_row("C0101", 4), actor_row("G0101", 2)]

    selection, _ = select_actors(index, campaign_above_group)
    assert (
        selection["actors"][ZETA]["relevance"] == 4 and selection["actors"][ZETA]["evidence_quote"] == QUOTES["G0101"]
    )


def test_a_failed_slice_loses_only_its_own_actors(index: MitreIndex) -> None:
    def alpha_slice_fails(data: dict[str, Any]) -> list[Any]:
        if slice_lists(data, "G0102"):
            raise UnreadableAiAnswer("filtered")
        return [actor_row("G0101", 5)] if slice_lists(data, "G0101") else []

    selection, _ = select_actors(
        index, alpha_slice_fails, mitre_actor_slice_tokens_limit=one_profile_per_slice_limit(index)
    )
    assert selection["status"] == "partial (4 of 5 slices)" and selection["ranked_actor_ids"] == [ZETA]


def test_an_index_without_actor_profiles_selects_nothing_without_a_model_call(index: MitreIndex) -> None:
    def never(data: dict[str, Any]) -> list[Any]:
        raise AssertionError("no slice to ask")

    selection, chat = select_actors({**index, "actor_profiles": []}, never)
    assert chat.calls == [] and selection["status"] == "empty" and selection["ranked_actor_ids"] == []


@pytest.mark.parametrize(
    "model_quote",
    [
        "the local government's wastewater control system",  # straight apostrophe for MITRE's curly one
        "The local government’s wastewater CONTROL system.",  # case, a curly quote and a full stop
        "using Triton - a safety-system malware",  # link text without its URL, a plain dash
        '"compromised the local government\'s ... control system using Triton"',  # quoted, shortened with "..."
    ],
)
def test_a_quote_differing_from_mitre_only_in_formatting_is_kept(model_quote: str) -> None:
    def rows(data: dict[str, Any]) -> list[Any]:
        row = {
            "mitre_id": "G0105",
            "relevance": 5,
            "evidence_quote": model_quote,
            "reason": "Attacked a wastewater system.",
        }
        return [{**row, "matched_fields": ["sector", "supporting_systems", "not_a_field"]}]

    selection, _ = select_actors(index_with_delta(), rows)
    assert selection["ranked_actor_ids"][0] == DELTA and selection["rejected_rows"] == {}
    assert selection["actors"][DELTA]["matched_fields"] == ["sector", "supporting_systems"]  # only real input fields


def test_a_quote_that_is_not_mitre_text_is_rejected_and_counted() -> None:
    def rows(data: dict[str, Any]) -> list[Any]:
        return [
            {
                "mitre_id": "G0105",
                "relevance": 5,
                "evidence_quote": "attacked many water utilities in Europe",
                "reason": "Water.",
            },
            {
                "mitre_id": "G0105",
                "relevance": 4,
                "evidence_quote": "control system using Triton ... in Europe and Asia",
                "reason": "Water.",
            },
            {"mitre_id": "g0101", "relevance": 9, "evidence_quote": QUOTES["G0101"], "reason": "Water."},
        ]

    selection, _ = select_actors(index_with_delta(), rows)
    assert selection["ranked_actor_ids"] == []
    assert selection["rejected_rows"] == {"quote not in the actor's MITRE description": 2, "relevance not 2-5": 1}


def test_the_accepted_relevance_comes_from_env() -> None:
    def rows(data: dict[str, Any]) -> list[Any]:
        return [{"mitre_id": "G0101", "relevance": 1, "evidence_quote": QUOTES["G0101"], "reason": "Water."}]

    selection, _ = select_actors(index_with_delta(), rows)
    assert selection["ranked_actor_ids"] == [] and selection["rejected_rows"] == {"relevance not 2-5": 1}
    selection, _ = select_actors(index_with_delta(), rows, mitre_relevance_range="1-5")
    assert len(selection["ranked_actor_ids"]) == 1 and selection["rejected_rows"] == {}


# ----------------------------------------------------------------------------- planning


def test_planning_works_when_every_actor_selection_slice_fails(index: MitreIndex) -> None:
    def fails(data: dict[str, Any]) -> list[Any]:
        raise UnreadableAiAnswer("filtered")

    selection, chat = select_actors(index, fails)
    chat.responders[AiTask.MITRE_PLAN] = answering(planner_answer(TAMPERING_PATH))
    planned = engine.plan_attack_paths(chat, asset_context(), index, settings(), selection)
    assert planned["paths"] and selection["status"] == "failed"
    assert inputs_of(chat, AiTask.MITRE_PLAN)[0]["relevant_actors"] == []


def test_planner_keeps_valid_paths_and_counts_each_rejection(index: MitreIndex) -> None:
    answer = planner_answer(
        (["T1566", "T1078"], "Tampering"),  # OT asset, no ICS technique
        (["T0831", "T9999"], "Tampering"),  # only one real technique
        (["T1566", "T0831"], "Bogus"),  # not a STRIDE category
        (["T1078", "T0826"], "Denial of Service"),  # no MITRE group uses either
        (["T1566", "T0831"], "tampering"),  # valid (STRIDE is case-insensitive)
        (["T0831", "T1566"], "Tampering"),  # a duplicate of the valid one
    )
    planned = plan(chat_with(plan=answer), index)
    assert [path["technique_stix_ids"] for path in planned["paths"]] == [[PHISHING, CONTROL_LOGIC]]
    assert planned["paths"][0]["category"] == "Tampering" and planned["paths"][0]["has_it_and_ot"]
    assert planned["invalid_paths"] == {
        "no ICS technique although the path attacks OT": 1,
        "fewer than 2 techniques": 1,
        "no STRIDE category": 1,
        "no MITRE group documented for these techniques": 1,
        "duplicate of a higher-ranked path": 1,
    }


def test_only_a_path_that_attacks_an_ot_system_needs_an_ics_technique(index: MitreIndex) -> None:
    it_asset_with_ot_system = {**MIXED_ASSET, "asset_type": "IT"}  # session 24f6dd71: 14 of 20 IT paths were lost
    answer = planner_answer((["T1566", "T1078"], "Tampering"), (["T1566", "T1078"], "Spoofing"))
    answer["plans"][0]["supporting_systems"] = ["Portal"]  # IT only: Enterprise techniques are enough
    answer["plans"][1]["supporting_systems"] = ["SCADA"]  # attacks the OT system without an ICS technique
    planned = plan(chat_with(plan=answer), index, it_asset_with_ot_system)
    assert [path["supporting_systems"] for path in planned["paths"]] == [["Portal"]]
    assert planned["invalid_paths"] == {"no ICS technique although the path attacks OT": 1}


def test_a_path_the_ai_judges_the_same_target_and_result_is_dropped(index: MitreIndex) -> None:
    """Different techniques, one scenario in meaning (the user's rule: same target and result, any way in): the
    judge names N1 for N3; a bad reference is asked again. Mutation: keep every path the techniques allow."""
    answer = planner_answer(TAMPERING_PATH, (["T1078", "T0813"], "Spoofing"), (["T1566", "T0826"], "Tampering"))
    chat = chat_with(plan=answer)
    chat.queue(
        AiTask.MITRE_DUPLICATE_CHECK,
        {"new": [{"id": "N3", "duplicate_of": "N9"}]},  # names no listed path: asked again
        {"new": [{"id": "N1", "duplicate_of": None}, {"id": "N3", "duplicate_of": "N1"}]},
    )
    planned = plan(chat, index)
    assert [path["title"] for path in planned["paths"]] == ["P0", "P1"]
    assert planned["invalid_paths"] == {"the same target and result as a higher-ranked path": 1}
    asked = inputs_of(chat, AiTask.MITRE_DUPLICATE_CHECK)
    assert (
        len(asked) == 2
        and asked[0]["planned"] == []
        and asked[0]["new"][2] == ("N3 | Tampering | P2 | Disrupt pumping | SCADA")
    )
    assert (
        "Work through each STRIDE category" in MITRE_PROMPTS["plan"]["text"]
        and "repeats" not in MITRE_PROMPTS["plan"]["text"]
    )


def test_a_further_path_repeating_a_planned_one_in_meaning_is_dropped_and_a_lost_verdict_keeps_all(
    index: MitreIndex,
) -> None:
    planned = plan(chat_with(), index)["paths"]
    chat = chat_with(plan=planner_answer((["T1078", "T0813"], "Spoofing")))
    chat.responders[AiTask.MITRE_DUPLICATE_CHECK] = answering({"new": [{"id": "N1", "duplicate_of": "P1"}]})
    selection = selection_of((ZETA, 5))
    found, invalid_paths, answer_read = engine.plan_further_paths(
        chat, asset_context(), index, settings(), selection, planned
    )
    assert (found, answer_read) == ([], True) and invalid_paths == {
        "the same target and result as a higher-ranked path": 1
    }
    assert inputs_of(chat, AiTask.MITRE_DUPLICATE_CHECK)[0]["planned"] == [
        "P1 | Tampering | P0 | Disrupt pumping | SCADA"
    ]
    lost = chat_with(plan=planner_answer((["T1078", "T0813"], "Spoofing")))
    lost.responders[AiTask.MITRE_DUPLICATE_CHECK] = answering({"no": "verdicts"})
    assert len(engine.plan_further_paths(lost, asset_context(), index, settings(), selection, planned)[0]) == 1


def test_a_system_written_as_an_object_is_read_as_its_name(index: MitreIndex) -> None:
    """The writer gave {"name": "SCADA"} for a system (live AOCC run): read, never re-asked."""
    written = writer_answer()
    written["supporting_systems"] = [{"name": "SCADA"}]
    chat = chat_with(scenario=written)
    scenario = write_scenario(chat, first_planned_path(index), index)
    assert scenario is not None and scenario["supporting_systems"] == ["SCADA"] and chat.writer_calls == 1


def test_the_same_attack_under_another_stride_category_is_a_duplicate(index: MitreIndex) -> None:
    """AOCC run 7db2e785: one attack (the same techniques) filed as Tampering and as Information Disclosure.
    Mutation: compare paths of one category only and both are kept."""
    answer = planner_answer(
        TAMPERING_PATH, (["T1566", "T0831"], "Information Disclosure"), (["T1078", "T0831"], "Spoofing")
    )
    planned = plan(chat_with(plan=answer), index)
    assert [path["category"] for path in planned["paths"]] == ["Tampering", "Spoofing"]
    assert planned["invalid_paths"] == {"duplicate of a higher-ranked path": 1}


def test_planner_rejects_paths_outside_the_env_technique_range(index: MitreIndex) -> None:
    answer = planner_answer((["T1566", "T0831", "T1078"], "Tampering"), TAMPERING_PATH)
    planned = plan(chat_with(plan=answer), index, attack_path_techniques="2-2")
    assert len(planned["paths"]) == 1 and planned["invalid_paths"] == {"more than 2 techniques": 1}
    assert "pick 2 to 2 techniques (never more than 2)" in engine.planner_prompt(settings(attack_path_techniques="2-2"))
    assert "pick 3 to 5 techniques (never more than 6)" in engine.planner_prompt(settings(attack_path_techniques="3-6"))


def test_the_planner_gets_the_top_ranked_actors_and_drops_the_lowest_to_fit_its_limit(index: MitreIndex) -> None:
    rows = [actor_row("G0101", 5), actor_row("G0104", 4), actor_row("G0102", 3)]
    selection = engine.select_relevant_actors_from_all_mitre_actors(chat_with(rows), asset_context(), index, settings())
    assert selection["ranked_actor_ids"] == [ZETA, GAMMA, ALPHA]
    chat = chat_with()
    engine.plan_attack_paths(chat, asset_context(), index, settings(planner_relevant_actors=2), selection)
    top_lines = inputs_of(chat, AiTask.MITRE_PLAN)[-1]["relevant_actors"]
    assert len(top_lines) == 2 and top_lines[0].startswith(
        'G0101 Zeta (intrusion-set) | relevance 5 | MITRE: "targets wastewater'
    )
    assert top_lines[0].endswith("techniques: T0831,T1566") and top_lines[1].startswith("G0104 Gamma")

    engine.plan_attack_paths(chat, asset_context(), index, settings(), selection)
    planner_input = inputs_of(chat, AiTask.MITRE_PLAN)[-1]
    all_lines = planner_input["relevant_actors"]
    one_line_prompt = (
        engine.planner_prompt(settings()),
        engine.to_user_prompt({**planner_input, "relevant_actors": all_lines[:1]}),
    )
    limit = call_tokens(one_line_prompt, chat, AiTask.MITRE_PLAN)
    engine.plan_attack_paths(chat, asset_context(), index, settings(mitre_plan_call_tokens_limit=limit), selection)
    assert len(all_lines) == 3 and inputs_of(chat, AiTask.MITRE_PLAN)[-1]["relevant_actors"] == all_lines[:1]


def test_a_path_needs_a_group_documented_for_any_of_its_techniques(index: MitreIndex) -> None:
    planned = plan(chat_with(plan=planner_answer((["T1566", "T0826"], "Denial of Service"))), index)
    assert (
        planned["paths"][0]["technique_stix_ids"] == [PHISHING, LOSS_OF_AVAILABILITY] and planned["invalid_paths"] == {}
    )


def test_an_it_only_asset_keeps_enterprise_techniques_only(index: MitreIndex) -> None:
    chat = chat_with(plan=planner_answer((["T1566", "T0831", "T1078"], "Spoofing")))
    planned = plan(chat, index, IT_ASSET)
    assert planned["paths"][0]["technique_stix_ids"] == [PHISHING, VALID_ACCOUNTS]
    assert not planned["it_ot_crossing_required"] and "ics_assets" not in inputs_of(chat, AiTask.MITRE_PLAN)[0]


def test_large_requests_plan_one_call_per_stride_category(index: MitreIndex) -> None:
    chat = chat_with()
    assert plan(chat, index, total_scenario_count=50)["planner_calls"] == 6
    scopes = []
    for data in inputs_of(chat, AiTask.MITRE_PLAN):
        scopes.append(data["stride_scope"])
    assert sorted(scopes) == sorted(str(category) for category in StrideCategory)
    chat = chat_with()
    assert plan(chat, index, total_scenario_count=5)["planner_calls"] == 1
    assert inputs_of(chat, AiTask.MITRE_PLAN)[0]["stride_scope"] == "all STRIDE categories"


def test_all_paths_asks_one_call_with_no_number_however_many_it_finds(index: MitreIndex) -> None:
    chat = chat_with()
    assert plan(chat, index, mitre_planner_single_call_limit=1)["planner_calls"] == 1  # never a per-category round
    (asked,) = inputs_of(chat, AiTask.MITRE_PLAN)
    assert (asked["stride_scope"], asked["paths_requested"]) == ("all STRIDE categories", "all")  # never a floor
    assert "planned_already" not in asked


def test_a_further_round_sends_the_planned_paths_and_keeps_only_new_unique_ones(index: MitreIndex) -> None:
    planned = plan(chat_with(), index)["paths"]  # one Tampering path: T1566, T0831
    further = planner_answer(TAMPERING_PATH, (["T1078", "T0831"], "Spoofing"))  # a copy, then a new one
    chat = chat_with(plan=further)
    new_paths, invalid_paths, answer_read = engine.plan_further_paths(
        chat, asset_context(), index, settings(), selection_of((ZETA, 5)), planned
    )
    (asked,) = inputs_of(chat, AiTask.MITRE_PLAN)
    assert asked["paths_requested"] == "all further"
    assert asked["planned_already"] == ["P1 | Tampering | P0 | SCADA | T1566, T0831"]
    assert [(path["category"], path["title"]) for path in new_paths] == [("Spoofing", "P1")] and answer_read
    assert invalid_paths == {"duplicate of a higher-ranked path": 1} and len(planned) == 1  # planned is not changed
    none_left = chat_with(plan=planner_answer())
    selection = selection_of((ZETA, 5))
    assert engine.plan_further_paths(none_left, asset_context(), index, settings(), selection, planned) == (
        [],
        {},
        True,
    )
    lost = MitreChat()  # an answer that is never readable: lost, not "none left"
    lost.responders[AiTask.MITRE_PLAN] = answering({"no": "plans"})
    assert engine.plan_further_paths(lost, asset_context(), index, settings(), selection, planned) == ([], {}, False)


def test_a_failed_planner_scope_or_odd_plan_does_not_fail_the_run(index: MitreIndex) -> None:
    chat = MitreChat()

    def answer_for(user_prompt: str) -> dict[str, Any]:
        if json.loads(user_prompt)["stride_scope"] == "Spoofing":
            raise UnreadableAiAnswer("filtered")
        answer = planner_answer(TAMPERING_PATH)
        answer["plans"][0]["supporting_systems"] = [{"name": "SCADA"}, "SCADA", 7]  # objects and numbers ignored
        return answer

    chat.responders[AiTask.MITRE_PLAN] = answer_for
    planned = plan(chat, index, total_scenario_count=50)
    assert planned["paths"] and planned["paths"][0]["supporting_systems"] == ["SCADA"]


def test_no_valid_path_fails_the_run_after_one_fresh_round(index: MitreIndex) -> None:
    chat = MitreChat()

    def unreadable(user_prompt: str) -> dict[str, Any]:
        raise UnreadableAiAnswer("filtered")

    chat.responders[AiTask.MITRE_PLAN] = unreadable
    with pytest.raises(JobFailed) as failure:
        plan(chat, index)
    assert (
        failure.value.code == ErrorCode.GENERATION_FAILED and len(chat.asked(AiTask.MITRE_PLAN)) == 2
    )  # the round, then once afresh


def test_crossing_rule_follows_the_asset_and_the_planner(index: MitreIndex) -> None:
    chat = chat_with(
        plan=planner_answer(TAMPERING_PATH, it_ot_crossing_relevant=True, it_ot_crossing_reason="VPN from the office")
    )
    planned = plan(chat, index)
    assert (
        inputs_of(chat, AiTask.MITRE_PLAN)[-1]["it_ot_crossing"] == "decide from the context"
    )  # all OT: the planner judges
    assert planned["it_ot_crossing_required"] and planned["it_ot_crossing_reason"] == "VPN from the office"
    planned = plan(chat, index, MIXED_ASSET)
    assert inputs_of(chat, AiTask.MITRE_PLAN)[-1]["it_ot_crossing"] == "required" and planned["it_ot_crossing_required"]


def test_the_planners_crossing_reason_is_cut_to_the_env_size() -> None:
    long_reason = {"it_ot_crossing_relevant": True, "it_ot_crossing_reason": "remote engineering access " * 40}
    required, reason = engine.decide_it_ot_crossing({"OT"}, [long_reason], settings())
    assert required and reason is not None and 0 < len(reason) <= settings().mitre_crossing_reason_characters
    assert reason.startswith("remote engineering access") and not reason.endswith(" ")


def test_supporting_systems_are_mapped_to_mitre_asset_types_and_shown_per_scenario() -> None:
    index = index_with_ics_assets()
    mapping = [
        {"supporting_system": " scada ", "mitre_asset_ids": ["a0003", "A9999"]},
        {"supporting_system": "Unknown system", "mitre_asset_ids": ["A0003"]},
    ]
    chat = chat_with(plan={**planner_answer(TAMPERING_PATH), "system_assets": mapping})
    planned = plan(chat, index)
    assert "A0003 | Programmable Logic Controller (PLC)" in inputs_of(chat, AiTask.MITRE_PLAN)[0]["ics_assets"]
    assert planned["system_mitre_assets"] == {"SCADA": ["A0003"]}  # only real systems and IDs
    scenario = write_scenario(chat, planned["paths"][0], index, system_mitre_assets=planned["system_mitre_assets"])
    techniques = {}
    for written_technique in inputs_of(chat, AiTask.MITRE_WRITE)[0]["techniques"]:
        techniques[written_technique["mitre_id"]] = written_technique
    assert techniques["T0831"]["targets_ics_assets"] == ["A0003 Programmable Logic Controller (PLC)"]
    assert scenario is not None and scenario["systems_targeted"] == [
        {
            "technique": "T0831",
            "supporting_system": "SCADA",
            "mitre_assets": ["A0003 Programmable Logic Controller (PLC)"],
        }
    ]


# ----------------------------------------------------------------------------- writing and checking one scenario


def test_writer_gets_mitre_candidates_and_code_sets_the_evidence(index: MitreIndex) -> None:
    chat = chat_with()
    scenario = write_scenario(chat, first_planned_path(index), index)
    writer_input = inputs_of(chat, AiTask.MITRE_WRITE)[0]
    candidates = writer_input["candidate_actors"]
    assert [candidate["name"] for candidate in candidates] == ["Zeta", "Alpha", "Gamma"]  # in the scheduler's order
    assert candidates[0]["targeting"] == "a quote from MITRE" and "relevance_reason" not in candidates[0]
    assert candidates[1]["targeting"] is None  # the AI's unchecked reason never reaches the writer
    assert candidates[1]["documented_for"] == [{"technique": "T1566", "domain": "enterprise", "via_software": "Tool"}]
    assert writer_input["groups_used_in_other_scenarios"] == []
    assert [technique["domain"] for technique in writer_input["techniques"]] == ["enterprise", "ics"]
    assert scenario is not None and scenario["relevant_groups"][0]["evidence_type"] == "direct"
    phishing, logic = "https://attack.mitre.org/techniques/T1566", "https://attack.mitre.org/techniques/T0831"
    assert scenario["relevant_groups"][0]["documented_techniques"] == [
        {"mitre_id": "T1566", "name": "Phishing", "domain": "enterprise", "via_software": None, "url": phishing},
        {"mitre_id": "T0831", "name": "Modify Control Logic", "domain": "ics", "via_software": None, "url": logic},
    ]
    # each technique and group links to its own attack.mitre.org page, as MITRE's reference gives it
    assert [technique["url"] for technique in scenario["attack_techniques"]] == [phishing, logic]
    assert scenario["relevant_groups"][0]["url"] == "https://attack.mitre.org/groups/G0101"
    assert "M1017" in json.dumps(scenario["mitigations"]) and scenario["prompt_version"] == PromptVersion.MITRE_WRITER
    assert (
        scenario["category"] == "Tampering"
        and scenario["relevant_groups"][0]["mitre_targeting_quote"] == "a quote from MITRE"
    )
    # the writer's own words about the group are replaced by MITRE's: its checked quote and documented techniques
    assert scenario["relevant_groups"][0]["relevance"] == (
        'MITRE describes it: "a quote from MITRE". MITRE documents it using Phishing, Modify Control Logic.'
    )


def test_a_group_with_no_targeting_quote_is_listed_for_its_documented_techniques_only() -> None:
    documented = [{"name": "Phishing", "via_software": "Tool"}, {"name": "Modify Control Logic", "via_software": None}]
    assert engine.relevance_from_mitre(documented, None) == (
        "Listed because MITRE documents it using Phishing (via Tool), Modify Control Logic."
    )


def test_a_technique_the_writer_dropped_keeps_no_mitigations_or_procedures(index: MitreIndex) -> None:
    answer = writer_answer(techniques=("T1566", "T0831"))
    scenario, problems = engine.check_written_scenario(
        answer, first_planned_path(index), asset_context(), index, settings(), [ZETA]
    )
    assert problems == [] and scenario is not None
    scenario["attack_techniques"] = scenario["attack_techniques"][:1]  # the writer kept Phishing only
    procedures = [{"technique": "T1566", "text": "kept"}, {"technique": "T0831", "text": "dropped"}]
    shown = engine.add_mitre_evidence_to_scenario(scenario, procedures, index, selection_of((ZETA, 5)), {})
    assert [entry["technique"] for entry in shown["mitigations"]] == ["T1566"]
    assert [procedure["text"] for procedure in shown["procedures"]] == ["kept"]


def test_a_group_documented_only_for_the_enterprise_step_is_valid_for_an_ot_asset(index: MitreIndex) -> None:
    planned_path = first_planned_path(index)
    answer = writer_answer(groups=(("Alpha", "G0102"),))
    scenario, problems = engine.check_written_scenario(
        answer, planned_path, asset_context(), index, settings(), [ALPHA]
    )
    assert problems == [] and scenario is not None and scenario["relevant_groups"][0]["evidence_type"] == "indirect"
    assert scenario["relevant_groups"][0]["documented_techniques"] == [
        {"mitre_id": "T1566", "name": "Phishing", "domain": "enterprise", "via_software": "Tool"}
    ]


def test_writer_trims_procedures_then_candidates_to_fit_the_call_limit(
    index: MitreIndex, monkeypatch: pytest.MonkeyPatch
) -> None:
    planned_path = first_planned_path(index)
    sizes = []

    def counted_tokens(prompt: tuple[str, str], chat: Any, task: AiTask) -> int:  # 100 per procedure, 10 per candidate
        data = json.loads(prompt[1])
        sizes.append((len(data["procedures"]), len(data["candidate_actors"])))
        return 100 * len(data["procedures"]) + 10 * len(data["candidate_actors"])

    monkeypatch.setattr(engine, "call_tokens", counted_tokens)
    ranked = (ALPHA, GAMMA, BETA, ZETA)
    zeta_answer, alpha_answer = (
        {"scenarios": [writer_answer()]},
        {"scenarios": [writer_answer(groups=(("Alpha", "G0102"),))]},
    )
    # Phishing has 4 procedures, Modify Control Logic 1: a limit of 4 gives 5 procedures, 2 gives 3, 1 gives 2.
    chat = MitreChat()
    chat.queue(AiTask.MITRE_WRITE, zeta_answer)
    scenario = write_scenario(
        chat, planned_path, index, ranked, procedures_per_technique=4, mitre_write_call_tokens_limit=240
    )
    assert (
        sizes == [(5, 4), (3, 4), (2, 4)] and scenario is not None and scenario["relevant_groups"][0]["name"] == "Zeta"
    )

    sizes.clear()
    chat = MitreChat()
    chat.queue(AiTask.MITRE_WRITE, zeta_answer, alpha_answer)
    used = [{"mitre_id": "G0104", "name": "Gamma"}]
    scenario = write_scenario(
        chat, planned_path, index, ranked, used=used, procedures_per_technique=4, mitre_write_call_tokens_limit=230
    )
    assert sizes == [(5, 4), (3, 4), (2, 4), (2, 3)]  # candidates only once procedures reach 1
    assert (
        len(chat.asked(AiTask.MITRE_WRITE)) == 2
        and scenario is not None
        and scenario["relevant_groups"][0]["name"] == "Alpha"
    )
    for writer_input in inputs_of(chat, AiTask.MITRE_WRITE):
        assert [candidate["name"] for candidate in writer_input["candidate_actors"]] == ["Alpha", "Gamma", "Beta"]
        assert writer_input["groups_used_in_other_scenarios"] == used

    chat = MitreChat()
    assert (
        write_scenario(chat, planned_path, index, ranked, procedures_per_technique=4, mitre_write_call_tokens_limit=229)
        is None
    )
    assert chat.calls == []


@pytest.mark.parametrize(
    "bad_answer",
    [
        writer_answer(groups=(("Beta", "G0103"),)),  # not a candidate, and no other group left
        writer_answer(  # names Beta, which is left out: asked again
            narrative="Zeta and Beta could phish an operator.", groups=(("Zeta", "G0101"), ("Beta", "G0103"))
        ),
        writer_answer() | {"relevant_groups": []},  # schema: no group
        writer_answer() | {"attack_techniques": []},  # schema: no technique
        writer_answer(techniques=("T0831",)),  # the crossing's IT side dropped
        writer_answer(narrative="Zeta could use T9999 to alter logic."),  # an invented MITRE ID
    ],
)
def test_writer_is_asked_again_when_an_answer_fails_the_mitre_checks(
    index: MitreIndex, bad_answer: dict[str, Any]
) -> None:
    planned_path = first_planned_path(index)
    _, problems = engine.check_written_scenario(
        bad_answer, planned_path, asset_context(), index, settings(), [ZETA, ALPHA, GAMMA]
    )
    assert problems
    chat = MitreChat()
    chat.queue(AiTask.MITRE_WRITE, {"scenarios": [bad_answer]}, {"scenarios": [writer_answer()]})
    scenario = write_scenario(chat, planned_path, index)
    assert (
        len(chat.asked(AiTask.MITRE_WRITE)) == 2
        and scenario is not None
        and scenario["relevant_groups"][0]["name"] == "Zeta"
    )


def test_an_answer_never_right_drops_the_path(index: MitreIndex) -> None:
    chat = chat_with(scenario=writer_answer(groups=(("Beta", "G0103"),)))
    assert write_scenario(chat, first_planned_path(index), index) is None


def test_the_problems_name_the_failing_field_and_the_trimmed_candidates(index: MitreIndex) -> None:
    planned_path = first_planned_path(index)
    broken = writer_answer()
    broken["attack_techniques"][0]["domain"] = ["enterprise"]  # a list instead of the required string
    _, problems = engine.check_written_scenario(broken, planned_path, asset_context(), index, settings(), [ZETA])
    assert problems[0].startswith("Schema validation failed: attack_techniques.0.domain")
    _, problems = engine.check_written_scenario(
        writer_answer(), planned_path, asset_context(), index, settings(), [ALPHA]
    )
    assert "candidate_actors" in problems[0]
    too_many = writer_answer(groups=(("Zeta", "G0101"), ("Alpha", "G0102")))
    checked, problems = engine.check_written_scenario(
        too_many, planned_path, asset_context(), index, settings(mitre_groups_per_scenario=1), [ZETA, ALPHA]
    )
    assert problems == [] and [group["name"] for group in checked["relevant_groups"]] == ["Zeta"]  # first N kept


def test_a_technique_reaches_the_writer_as_its_opening_sentences(index: MitreIndex) -> None:
    """Only the whole sentences that open MITRE's description, within WRITER_TECHNIQUE_DESCRIPTION_CHARACTERS,
    reach the writer: MITRE's own words, never cut mid-sentence. Mutation: send the full description and the
    writer gets every sentence."""
    description = "Adversaries may phish operators. They send lures by email. They also call the help desk."
    objects = {**index["objects"], CONTROL_LOGIC: {**index["objects"][CONTROL_LOGIC], "description": description}}
    shown = engine.writer_techniques(
        [CONTROL_LOGIC], {**index, "objects": objects}, settings(writer_technique_description_characters=70)
    )
    assert shown[0]["description"] == "Adversaries may phish operators. They send lures by email."
    assert opening_sentences("One very long first sentence without any stop", 20) == "One very long first"


def test_code_leaves_out_an_unplanned_technique_or_a_bad_group_instead_of_asking_again(index: MitreIndex) -> None:
    """The writer adds a technique the plan lacks (T1078), a group listed twice and one that is no candidate
    (Beta): code keeps the planned techniques and Zeta, in one writer call. Mutation: report the unplanned
    technique as a problem again and the writer is asked twice."""
    answer = writer_answer(techniques=("T1566", "T0831", "T1078"), groups=(("Zeta", "G0101"), ("Zeta", "G0101")))
    answer["relevant_groups"].append({"name": "Beta", "mitre_id": "G0103", "relevance": ""})
    chat = chat_with(scenario=answer)
    scenario = write_scenario(chat, first_planned_path(index), index)
    assert len(chat.asked(AiTask.MITRE_WRITE)) == 1 and scenario is not None
    assert [technique["mitre_id"] for technique in scenario["attack_techniques"]] == ["T1566", "T0831"]
    assert [group["name"] for group in scenario["relevant_groups"]] == ["Zeta"]


def test_a_left_out_technique_or_group_named_in_the_text_is_asked_again(index: MitreIndex) -> None:
    """The text must never tell of what the card no longer lists: naming the left-out T1078 (or its MITRE name)
    in the scenario keeps the re-ask."""
    for narrative in ("An attacker uses T1078 to log in.", "An attacker uses valid accounts to log in."):
        answer = writer_answer(narrative=narrative, techniques=("T1566", "T0831", "T1078"))
        _, problems = engine.check_written_scenario(
            answer, first_planned_path(index), asset_context(), index, settings(), [ZETA, ALPHA, GAMMA]
        )
        assert problems and "leave it out" in problems[0], narrative


def test_several_relevant_groups_are_each_verified_against_mitre(index: MitreIndex) -> None:
    planned_path = first_planned_path(index, IT_ASSET, ("T1566", "T1078"))
    answer = writer_answer(groups=(("Zeta", "G0101"), ("Alpha", "G0102")), techniques=("T1566",))
    answer["supporting_systems"] = ["Portal"]
    chat = chat_with(scenario=answer)
    scenario = write_scenario(chat, planned_path, index, asset=IT_ASSET)
    names = set()
    for candidate in inputs_of(chat, AiTask.MITRE_WRITE)[0]["candidate_actors"]:
        names.add(candidate["name"])
    assert names == {"Zeta", "Alpha", "Gamma"} and scenario is not None
    groups = {}
    for relevant_group in scenario["relevant_groups"]:
        groups[relevant_group["name"]] = relevant_group
    assert groups["Zeta"]["evidence_type"] == "direct"
    assert (
        groups["Alpha"]["evidence_type"] == "indirect"
        and groups["Alpha"]["documented_techniques"][0]["via_software"] == "Tool"
    )


def test_writer_aims_for_the_lower_end_of_the_env_range() -> None:
    limited = settings(mitre_threat_scenario_word_limit="80-100", mitre_risk_statement_word_limit="30-40")
    prompt = engine.writer_prompt(limited)
    assert "about 5 short sentences of about 80 words in total (between 80 and 100, never more than 100)" in prompt
    assert "about 30 words (between 30 and 40, never more than 40)" in prompt and "<scenario_words>" not in prompt
    assert "one noun phrase of 4 to 10 words" in prompt and "in sentence case, 3 to 8 words" in prompt
    assert "_title_words>" not in prompt


def test_a_short_scenario_is_still_asked_for_the_env_fewest_sentences() -> None:
    prompt = engine.writer_prompt(settings(mitre_threat_scenario_word_limit="20-40"))
    assert "about 3 short sentences of about 20 words in total" in prompt  # 20 / 15 alone would ask for 1


def test_word_limits_come_from_env_and_only_the_maximum_is_enforced(index: MitreIndex) -> None:
    planned_path = first_planned_path(index)
    limited = settings(mitre_threat_scenario_word_limit="120-140", mitre_risk_statement_word_limit="60-80")

    def problems(scenario_words: int, risk_words: int) -> list[str]:
        answer = {
            **writer_answer(),
            "threat_scenario": "word " * scenario_words,
            "risk_statement": "word " * risk_words,
        }
        return engine.check_written_scenario(answer, planned_path, asset_context(), index, limited, [ZETA])[1]

    assert problems(150, 80) == []  # within MITRE_WORD_LIMIT_SLACK (10%)
    assert problems(90, 40) == []  # short is allowed (prompt guidance only)
    assert problems(200, 70)[0].startswith("threat_scenario exceeds the word limit")
    assert problems(130, 100)[0].startswith("risk_statement exceeds the word limit")
    long_title = {**writer_answer(), "threat_scenario_description": "word " * 20}
    title_problems = engine.check_written_scenario(long_title, planned_path, asset_context(), index, limited, [ZETA])[1]
    assert title_problems[0].startswith("threat_scenario_description exceeds the word limit")
    strict = settings(mitre_threat_scenario_word_limit="120-140", mitre_word_limit_slack=0.0)
    over_by_one = {**writer_answer(), "threat_scenario": "word " * 141}
    strict_problems = engine.check_written_scenario(over_by_one, planned_path, asset_context(), index, strict, [ZETA])[
        1
    ]
    assert strict_problems[0].startswith("threat_scenario exceeds the word limit")


def test_writer_names_are_resolved_by_mitre_id_and_systems_ignore_case(index: MitreIndex) -> None:
    answer = writer_answer()
    answer["attack_techniques"][0]["name"] = "Phishing (initial access)"  # cosmetic: no re-ask needed
    answer["relevant_groups"][0]["name"] = "ZETA group"
    answer["supporting_systems"] = ["  scada ", "pump controller"]  # the asset itself: left out, not a re-ask
    chat = chat_with(scenario=answer)
    scenario = write_scenario(chat, first_planned_path(index), index)
    assert len(chat.asked(AiTask.MITRE_WRITE)) == 1 and scenario is not None
    assert scenario["attack_techniques"][0]["name"] == "Phishing" and scenario["relevant_groups"][0]["name"] == "Zeta"
    assert scenario["supporting_systems"] == ["SCADA"]


def test_the_writer_copies_a_library_threat_type_or_is_asked_again(index: MitreIndex) -> None:
    """A listed type (any case) is kept with its library id; one not listed is re-asked once, then the path drops."""
    answer = writer_answer() | {"threat_type": "unauthorised ACCESS"}
    chat = chat_with(scenario=answer)
    scenario = write_scenario(chat, first_planned_path(index), index)
    assert scenario is not None and (scenario["threat_type"], scenario["threat_type_id"]) == ("Unauthorised access", 2)
    assert inputs_of(chat, AiTask.MITRE_WRITE)[0]["threat_types"] == ["Malware/Ransomware", "Unauthorised access"]
    chat = chat_with(scenario=writer_answer() | {"threat_type": "Invented type"})
    assert write_scenario(chat, first_planned_path(index), index) is None
    assert len(chat.asked(AiTask.MITRE_WRITE)) == 2  # the one re-ask, then dropped


# ----------------------------------------------------------------------------- writing in parallel


def run_writers(
    index: MitreIndex,
    paths: list[dict[str, Any]],
    goal: int,
    selection: dict[str, Any] | None = None,
    group_usage: dict[str, int] | None = None,
    crossing_required: bool = False,
    chat: FakeChatModel | None = None,
    run_target: int | None = None,
    **changes: Any,
) -> tuple[dict[str, Any], list[str]]:
    """write_scenario_set, with the titles of the paths saved in the order they were saved."""
    saved = []

    def save_card(planned_path: dict[str, Any], scenario: dict[str, Any]) -> None:
        saved.append(planned_path["title"])

    result = engine.write_scenario_set(
        chat or MitreChat(),
        paths,
        goal,
        group_usage or {},
        save_card,
        asset_context=asset_context(),
        index=index,
        settings=settings(**changes),
        actor_selection=selection or selection_of((ZETA, 5)),
        system_mitre_assets={},
        run_target=goal if run_target is None else run_target,
        crossing_required=crossing_required,
        threat_types=THREAT_TYPES,
    )
    return result, saved


def written_titles(result: dict[str, Any], paths: list[dict[str, Any]]) -> list[str]:
    titles = []
    for position, _ in result["written"]:
        titles.append(paths[position]["title"])
    return titles


def patch_writer(monkeypatch: pytest.MonkeyPatch, fake_writer: Any) -> None:
    """The set's writer replaced, one path at a time, by fake_writer(chat, planned path, ranked candidate ids,
    groups used in other scenarios, **writing) giving the path's scenario or None."""

    def write_briefs(
        chat: Any, prompt: str, briefs: list[dict[str, Any]], writing: dict[str, Any]
    ) -> dict[str, dict[str, Any] | None]:
        written = {}
        for brief in briefs:
            used = brief["shared"]["groups_used_in_other_scenarios"]
            written[brief["slot"]] = fake_writer(chat, brief["path"], brief["candidate_ids"], used, **writing)
        return written

    monkeypatch.setattr(engine, "write_briefs", write_briefs)


def capture_scheduled_candidates(monkeypatch: pytest.MonkeyPatch, failing_titles: tuple[str, ...] = ()) -> list[Any]:
    """The writer replaced: records (ranked candidate ids, groups used elsewhere) and names the first candidate."""
    captured = []

    def fake_writer(
        chat: Any, planned_path: dict[str, Any], ranked: list[str], used: list[Any], **options: Any
    ) -> dict[str, Any] | None:
        captured.append((ranked, used))
        if planned_path["title"] in failing_titles:
            return None
        first_group = options["index"]["objects"][ranked[0]]
        named = [{"mitre_id": get_mitre_id(first_group), "name": first_group["name"]}]
        return {"attack_techniques": planned_path_techniques(planned_path), "relevant_groups": named}

    patch_writer(monkeypatch, fake_writer)
    return captured


def always_naming(*groups: tuple[str, str], only_zeta_title: str = "") -> Any:
    """A writer naming the given groups (only Zeta for the path titled only_zeta_title)."""

    def fake_writer(
        chat: Any, planned_path: dict[str, Any], ranked: list[str], used: list[Any], **_: Any
    ) -> dict[str, Any]:
        named = []
        for name, mitre_id in groups if planned_path["title"] != only_zeta_title else (("Zeta", "G0101"),):
            named.append({"mitre_id": mitre_id, "name": name})
        return {"attack_techniques": planned_path_techniques(planned_path), "relevant_groups": named}

    return fake_writer


def test_paths_sharing_a_top_group_get_different_first_candidates(
    index: MitreIndex, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured = capture_scheduled_candidates(monkeypatch)
    selection = selection_of((ZETA, 5), (GAMMA, 4))
    run_writers(index, fake_paths(2), 2, selection, mitre_parallel_writers=1, max_scenario_share_per_group=1.0)
    assert captured[0] == ([ZETA, GAMMA, ALPHA], [])
    # one call writes the set: P1 is ranked with P0's first candidate counted as used (both are in the request)
    assert captured[1][0][0] == GAMMA and captured[1][1] == []

    captured = capture_scheduled_candidates(monkeypatch, failing_titles=("P0",))
    run_writers(index, fake_paths(2), 1, selection, mitre_parallel_writers=1)
    assert captured[0][0][0] == ZETA and captured[1][0][0] == ZETA  # P0 failed, so Zeta was not used


def test_a_group_at_its_share_of_scenarios_is_no_longer_offered(monkeypatch: pytest.MonkeyPatch) -> None:
    samples = documents()
    samples["enterprise"] += [
        group("intrusion-set--delta", "Delta", "G0105", "Delta"),
        relationship("d1", "intrusion-set--delta", PHISHING),
    ]
    four_group_index = build_mitre_index(samples, settings())
    captured = []
    zeta_writer = always_naming(("Zeta", "G0101"))

    def recording_writer(
        chat: Any, planned_path: dict[str, Any], ranked: list[str], used: list[Any], **options: Any
    ) -> dict[str, Any]:
        captured.append(ranked)
        return zeta_writer(chat, planned_path, ranked, used, **options)

    patch_writer(monkeypatch, recording_writer)
    run_writers(four_group_index, fake_paths(4), 4, mitre_parallel_writers=1)
    assert ZETA in captured[0] and ZETA in captured[1]  # named in 2 of 4 scenarios: its 0.5 share
    assert ZETA not in captured[2] and ZETA not in captured[3] and len(captured[2]) == 3


def test_the_share_cap_is_strict_even_when_few_groups_are_documented(
    index: MitreIndex, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Zeta is named in 2 of 4 scenarios (its 0.5 share). A later path documented by Zeta and Gamma gets only
    # Gamma; a path only Zeta is documented for still gets Zeta.
    captured = []
    zeta_writer = always_naming(("Zeta", "G0101"))

    def recording_writer(
        chat: Any, planned_path: dict[str, Any], ranked: list[str], used: list[Any], **options: Any
    ) -> dict[str, Any]:
        captured.append(ranked)
        return zeta_writer(chat, planned_path, ranked, used, **options)

    patch_writer(monkeypatch, recording_writer)
    zeta_and_gamma = {
        **fake_paths(1)[0],
        "title": "P2",
        "category": "Denial of Service",
        "technique_stix_ids": [CONTROL_LOGIC, DENIAL_OF_CONTROL],
    }
    only_zeta = {**fake_paths(1)[0], "title": "P3", "technique_stix_ids": [CONTROL_LOGIC, LOSS_OF_AVAILABILITY]}
    run_writers(index, [*fake_paths(2), zeta_and_gamma, only_zeta], 4, mitre_parallel_writers=1)
    assert captured[2] == [GAMMA] and captured[3] == [ZETA]


def test_the_share_cap_holds_for_paths_written_in_one_call(index: MitreIndex, monkeypatch: pytest.MonkeyPatch) -> None:
    # Four writers at once all name Zeta first: with a 0.5 share of 4 scenarios only two keep Zeta; the others keep
    # their other verified group, and a scenario naming only Zeta gets the best verified alternative instead.
    patch_writer(monkeypatch, always_naming(("Zeta", "G0101"), ("Gamma", "G0104"), only_zeta_title="P3"))
    paths = fake_paths(4)
    result, saved = run_writers(index, paths, 4, mitre_parallel_writers=4)
    zeta_count = 0
    for _, scenario in result["written"]:
        names = []
        for relevant_group in scenario["relevant_groups"]:
            names.append(relevant_group["name"])
        assert names  # never left without a group
        zeta_count += "Zeta" in names
    assert zeta_count == 2 and result["groups_removed_over_share"] >= 2 and sorted(saved) == ["P0", "P1", "P2", "P3"]


def test_a_sole_group_over_its_share_is_replaced_by_a_verified_candidate(
    index: MitreIndex, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_writer(monkeypatch, always_naming(("Zeta", "G0101")))
    result, _ = run_writers(index, fake_paths(2), 2, selection_of((ZETA, 5), (GAMMA, 3)), mitre_parallel_writers=1)
    second_group = result["written"][1][1]["relevant_groups"][0]
    assert second_group["name"] == "Gamma" and second_group["relevance"].startswith(
        'MITRE describes it: "a quote from MITRE". MITRE documents it using Phishing'
    )  # never the selection AI's own reason
    assert result["groups_removed_over_share"] == 1


def test_the_share_counts_the_scenarios_of_earlier_sets(index: MitreIndex, monkeypatch: pytest.MonkeyPatch) -> None:
    captured = capture_scheduled_candidates(monkeypatch)
    run_writers(index, fake_paths(1), 1, group_usage={"G0101": 2}, run_target=4, mitre_parallel_writers=1)
    assert ZETA not in captured[0][0] and captured[0][1] == [{"mitre_id": "G0101", "name": "Zeta"}]


def test_the_run_writes_the_goal_and_backfills_failures(index: MitreIndex, monkeypatch: pytest.MonkeyPatch) -> None:
    capture_scheduled_candidates(monkeypatch, failing_titles=("P1",))
    paths = fake_paths(3)
    result, saved = run_writers(index, paths, 2, max_scenario_share_per_group=1.0)
    assert (
        written_titles(result, paths) == ["P0", "P2"]
        and result["failed_positions"] == [1]
        and sorted(saved) == ["P0", "P2"]
    )


def test_a_crossing_path_is_written_first_while_the_rule_is_unmet(
    index: MitreIndex, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture_scheduled_candidates(monkeypatch, failing_titles=("P0",))
    paths = fake_paths(4, crossing_positions=(0, 3))
    result, _ = run_writers(
        index, paths, 2, crossing_required=True, mitre_parallel_writers=1, max_scenario_share_per_group=1.0
    )
    assert written_titles(result, paths) == ["P1", "P3"]  # P3 (a crossing) backfills P0, not P2


def test_a_required_crossing_works_when_the_set_is_split_into_calls(
    index: MitreIndex, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture_scheduled_candidates(monkeypatch)
    result, _ = run_writers(
        index, fake_paths(4, crossing_positions=(2,)), 3, crossing_required=True, mitre_parallel_writers=3
    )
    assert len(result["written"]) == 3


def test_a_set_written_together_with_the_real_writer_and_one_failing_path(index: MitreIndex) -> None:
    chat = MitreChat()

    def answer_for(user_prompt: str) -> dict[str, Any]:
        title = json.loads(user_prompt)["plan"]["title"]
        if title == "P1":
            return {"scenarios": [writer_answer(title=title, groups=(("Beta", "G0103"),))]}  # never right: dropped
        return {"scenarios": [writer_answer(title=title)]}

    chat.responders[AiTask.MITRE_WRITE] = answer_for
    paths = fake_paths(4, crossing_positions=(0, 1, 2, 3))
    result, saved = run_writers(index, paths, 3, chat=chat, max_scenario_share_per_group=1.0)
    assert written_titles(result, paths) == ["P0", "P2", "P3"] and result["failed_positions"] == [1]
    for _, scenario in result["written"]:
        assert scenario["relevant_groups"][0]["name"] == "Zeta" and scenario["mitigations"]
    assert sorted(saved) == ["P0", "P2", "P3"] and ASSET["asset_name"] in chat.asked(AiTask.MITRE_WRITE)[0]
    assert chat.writer_calls == 3  # P0-P2 together, P1 re-asked once, then P3 backfills it


def test_a_set_is_one_writer_call_and_its_failed_paths_are_re_asked_together(index: MitreIndex) -> None:
    """The set's 3 paths go in one call with the shared input once; the 2 that fail their checks are re-asked
    together in one more call, each with its draft and problems. Mutation: a call per path, or a re-ask per path."""
    chat, first_answers = MitreChat(), {"P0", "P1"}

    def answer_for(user_prompt: str) -> dict[str, Any]:
        title = json.loads(user_prompt)["plan"]["title"]
        if title in first_answers:  # wrong once: a group MITRE does not document for the path
            first_answers.discard(title)
            return {"scenarios": [writer_answer(title=title, groups=(("Beta", "G0103"),))]}
        return {"scenarios": [writer_answer(title=title)]}

    chat.responders[AiTask.MITRE_WRITE] = answer_for
    paths = fake_paths(3)
    result, saved = run_writers(index, paths, 3, chat=chat, max_scenario_share_per_group=1.0)
    assert written_titles(result, paths) == ["P0", "P1", "P2"] and chat.writer_calls == 2
    first_call, re_ask = json.loads(chat.writer_prompts[0]), json.loads(chat.writer_prompts[-1])
    assert [path["slot"] for path in first_call["paths"]] == ["path-1", "path-2", "path-3"]
    assert "asset_context" in first_call and "asset_context" not in first_call["paths"][0]
    assert [path["slot"] for path in re_ask["paths"]] == ["path-1", "path-2"]
    assert re_ask["paths"][0]["problems_to_fix"] and re_ask["paths"][0]["previous_draft"]["slot"] == "path-1"


def test_a_regenerate_of_many_paths_is_written_one_set_a_call(index: MitreIndex) -> None:
    """CII_ANSWER_TOKENS_MITRE_WRITE fits one set's answer: 7 paths with sets of 3 go in calls of 3, 3 and 1.
    Mutation: split only by MITRE_WRITE_CALL_TOKENS_LIMIT and all 7 go in one call, whose answer is cut off."""
    chat = MitreChat()

    def answer_for(user_prompt: str) -> dict[str, Any]:
        return {"scenarios": [writer_answer(title=json.loads(user_prompt)["plan"]["title"])]}

    chat.responders[AiTask.MITRE_WRITE] = answer_for
    paths = fake_paths(7)
    result, saved = run_writers(
        index, paths, 7, chat=chat, initial_set_size=3, next_set_size=3, max_scenario_share_per_group=1.0
    )
    sizes = []
    for prompt in chat.writer_prompts:
        sizes.append(len(json.loads(prompt)["paths"]))
    assert sizes == [3, 3, 1] and len(saved) == 7 and not result["failed_positions"]
