"""The MITRE run's engine (ADR-010): the AI selects the relevant actors from every MITRE actor, plans attack paths
over the whole MITRE Enterprise and ICS catalogue, and writes one scenario per path; code checks every quote,
technique, group and system against MITRE and the asset before anything is kept.

The asset context is the engine's own shape: asset_name, asset_description, asset_type ("IT" or "OT"), sector,
subsector, service_name, service_description, data_handled and supporting_systems ([{name, description, type
("IT" or "OT"), technology_used, accessibility_channel, interface_description, ...}]), never a contact name."""

import itertools
import json
import math
import re
from collections.abc import Callable, Sequence
from functools import partial
from typing import Any

import structlog
from pydantic import ValidationError

from app.ai import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core import constants as c
from app.core.config import Settings
from app.core.exceptions import JobFailed
from app.core.prompts import MITRE_PROMPTS
from app.domain.shared.ask_ai import (
    ChatPrompt,
    answers_for_asked_slots,
    ask_ai_and_check,
    call_tokens,
    within_call_limit,
)
from app.domain.shared.names import threat_name_key
from app.domain.shared.parallel import run_in_parallel
from app.schemas.mitre.mitre_scenarios import Scenario
from app.search.mitre.mitre_index import (
    MitreIndex,
    clean_mitre_text,
    get_mitre_id,
    get_mitre_url,
    opening_sentences,
    shorten_at_word_boundary,
)

log = structlog.get_logger(__name__)

MITRE_ID_PATTERN = re.compile(r"\b(?:T\d{4}(?:\.\d{3})?|G\d{4}|S\d{4}|C\d{4}|M\d{4}|TA\d{4})\b")
STRIDE_BY_LOWERCASE = {category.casefold(): str(category) for category in c.StrideCategory}
ALL_STRIDE_CATEGORIES = "all STRIDE categories"


def list_or_empty(value: Any) -> list[Any]:
    """An answer's field when it is a list, else an empty list (the AI may answer anything)."""
    return value if isinstance(value, list) else []


def to_user_prompt(data: dict[str, Any]) -> str:
    """The user message of every MITRE call: the input as compact JSON."""
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"), default=str)


def fold_name(name: str) -> str:
    """A name compared ignoring case and spacing."""
    return " ".join(name.split()).casefold()


def system_name_by_folded_name(asset_context: dict[str, Any]) -> dict[str, str]:
    names = {}
    for supporting_system in asset_context["supporting_systems"]:
        names[fold_name(supporting_system["name"])] = supporting_system["name"]
    return names


def asset_and_system_types(asset_context: dict[str, Any]) -> set[str]:
    """The IT/OT types of the asset and its supporting systems."""
    asset_types = {asset_context["asset_type"]}
    for supporting_system in asset_context["supporting_systems"]:
        asset_types.add(supporting_system["type"])
    return asset_types


def technique_targeted_asset_names(technique_id: str, index: MitreIndex) -> list[str]:
    """'A0003 Programmable Logic Controller (PLC)', ... for every MITRE ICS asset type the technique targets."""
    asset_names = []
    for asset_mitre_id in index["asset_mitre_ids_by_technique"].get(technique_id, []):
        asset_names.append(f"{asset_mitre_id} {index['objects'][index['asset_by_mitre_id'][asset_mitre_id]]['name']}")
    return asset_names


def path_has_both_it_and_ot_techniques(technique_ids: list[str], index: MitreIndex) -> bool:
    """True when the techniques include an Enterprise-only (IT) and an ICS (OT) one: an IT/OT crossing path."""
    has_it_technique = False
    has_ot_technique = False
    for technique_id in technique_ids:
        if "ics" in index["domains"][technique_id]:
            has_ot_technique = True
        else:
            has_it_technique = True
    return has_it_technique and has_ot_technique


def documented_techniques_of_group(group_id: str, technique_ids: list[str], index: MitreIndex) -> list[dict[str, Any]]:
    """The techniques among technique_ids MITRE documents the group for, with the software when indirect."""
    documented = []
    used_techniques = index["techniques_by_actor"][group_id]
    for technique_id in technique_ids:
        if technique_id in used_techniques:
            technique = index["objects"][technique_id]
            documented.append(
                {
                    "mitre_id": get_mitre_id(technique),
                    "name": technique["name"],
                    "domain": "+".join(sorted(index["domains"][technique_id])),
                    "via_software": used_techniques[technique_id],
                }
            )
    return documented


def evidence_type(documented_techniques: list[dict[str, Any]]) -> str:
    for evidence in documented_techniques:
        if evidence["via_software"] is None:
            return "direct"
    return "indirect"


# ----------------------------------------------------------------------------- actor selection


def select_relevant_actors_from_all_mitre_actors(
    chat: ChatModel, asset_context: dict[str, Any], index: MitreIndex, settings: Settings
) -> dict[str, Any]:
    """The actors the AI chose from every MITRE group and campaign as relevant to this asset.

    The profile lines are sent in slices that fit MITRE_ACTOR_SLICE_TOKENS_LIMIT, all at once. An actor is kept
    only when its quote really is in its MITRE description; a relevant campaign lifts the groups it is
    attributed to. Returns {actors: {actor_id: {relevance, evidence_quote, reason, matched_fields}},
    ranked_actor_ids, status: complete | empty | partial (n of m slices) | failed, rejected_rows: {reason: n}}."""
    prompt = MITRE_PROMPTS["actors"]["text"]
    slices = pack_actor_profiles_into_slices(chat, prompt, asset_context, index, settings)
    ask_slice = partial(ask_one_actor_slice, chat, prompt, asset_context)
    answers = run_in_parallel(ask_slice, slices, max(1, len(slices)), "mitre-actors")
    chosen: dict[str, dict[str, Any]] = {}
    rejected_rows: dict[str, int] = {}
    succeeded_slices = 0
    for actor_slice, rows in zip(slices, answers, strict=True):
        if rows is None:
            continue
        succeeded_slices += 1
        keep_actor_rows_backed_by_mitre_text(rows, actor_slice, index, settings, chosen, rejected_rows)
    lift_groups_through_campaigns(chosen, index)
    if succeeded_slices == len(slices):
        status = "complete" if chosen else "empty"
    elif succeeded_slices:
        status = f"partial ({succeeded_slices} of {len(slices)} slices)"
    else:
        status = "failed"
    ranked_actor_ids = rank_selected_actors(chosen, index)
    return {"actors": chosen, "ranked_actor_ids": ranked_actor_ids, "status": status, "rejected_rows": rejected_rows}


def actor_slice_prompt(prompt: str, asset_context: dict[str, Any], profiles: list[dict[str, Any]]) -> ChatPrompt:
    lines = []
    for profile in profiles:
        lines.append(profile["line"])
    return prompt, to_user_prompt({"asset_context": asset_context, "actor_profiles": "\n".join(lines)})


def pack_actor_profiles_into_slices(
    chat: ChatModel, prompt: str, asset_context: dict[str, Any], index: MitreIndex, settings: Settings
) -> list[list[dict[str, Any]]]:
    """Profile lines packed by their counted tokens, then every slice re-checked with the real prompt: one still
    over the limit moves its last line on to the next slice, so no actor is ever lost."""
    limit, task = settings.mitre_actor_slice_tokens_limit, c.AiTask.MITRE_ACTOR_SELECTION
    empty_slice_tokens = call_tokens(actor_slice_prompt(prompt, asset_context, []), chat, task)
    slices: list[list[dict[str, Any]]] = []
    current_slice: list[dict[str, Any]] = []
    current_tokens = empty_slice_tokens
    for profile in index["actor_profiles"]:
        if current_slice and current_tokens + profile["tokens"] + 1 > limit:
            slices.append(current_slice)
            current_slice, current_tokens = [], empty_slice_tokens
        current_slice.append(profile)
        current_tokens += profile["tokens"] + 1
    if current_slice:
        slices.append(current_slice)
    slice_number = 0
    while slice_number < len(slices):
        actor_slice = slices[slice_number]
        too_large = call_tokens(actor_slice_prompt(prompt, asset_context, actor_slice), chat, task) > limit
        if too_large and len(actor_slice) > 1:
            if slice_number + 1 == len(slices):
                slices.append([])
            slices[slice_number + 1].insert(0, actor_slice.pop())
            continue
        slice_number += 1
    return slices


def read_relevant_actor_rows(answer: dict[str, Any]) -> tuple[list[Any] | None, list[str]]:
    rows = answer.get("relevant_actors")
    if not isinstance(rows, list):
        return None, [c.MitreProblem.ANSWER_LAYOUT.format(key="relevant_actors")]
    return rows, []


def ask_one_actor_slice(
    chat: ChatModel, prompt: str, asset_context: dict[str, Any], actor_slice: list[dict[str, Any]]
) -> list[Any] | None:
    """One slice's relevant_actors rows; None when the AI gave no usable answer (only this slice's actors lost)."""
    slice_prompt = actor_slice_prompt(prompt, asset_context, actor_slice)
    task = c.AiTask.MITRE_ACTOR_SELECTION
    try:
        rows: list[Any] = ask_ai_and_check(
            chat, task, slice_prompt, read_relevant_actor_rows, reuse_earlier_answer=True
        )
    except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
        log.warning(c.LogEvent.MITRE_ACTOR_SLICE_FAILED, error_type=type(exc).__name__)
        return None
    return rows


def quote_is_in_description(quote: str, description: str) -> bool:
    """True when every part of the quote (a quote may be shortened with "...") appears in order."""
    folded_description, search_from = description.casefold(), 0
    for quote_part in quote.casefold().split("..."):
        quote_part = quote_part.strip(" \"'.,;")
        if not quote_part:
            continue
        try:  # str.index, not .find: the convention guard reads .find() as a MongoDB call
            found_at = folded_description.index(quote_part, search_from)
        except ValueError:
            return False
        search_from = found_at + len(quote_part)
    return True


def check_actor_row(
    row: Any, actor_id_by_mitre_id: dict[str, str], index: MitreIndex, settings: Settings
) -> tuple[str | None, dict[str, Any], str | None]:
    """(actor_id, choice, None) for a row backed by MITRE text, else (None, {}, the rejection reason). Quote and
    description are compared as cleaned text, so formatting differences still count as MITRE's words."""
    if not isinstance(row, dict):
        return None, {}, c.MitreProblem.NOT_AN_OBJECT
    actor_id = actor_id_by_mitre_id.get(str(row.get("mitre_id") or "").strip().upper())
    relevance = row.get("relevance")
    quote = clean_mitre_text(str(row.get("evidence_quote") or "")).strip(" \"'.")
    reason = " ".join(str(row.get("reason") or "").split())
    least, most = settings.mitre_relevance_bounds
    rejection: str | None = None
    if actor_id is None:
        rejection = c.MitreProblem.UNKNOWN_ACTOR
    elif isinstance(relevance, bool) or not isinstance(relevance, int) or not least <= relevance <= most:
        rejection = c.MitreProblem.RELEVANCE_OUT_OF_RANGE.format(least=least, most=most)
    elif len(quote.split()) < settings.mitre_minimum_quote_words:
        rejection = c.MitreProblem.QUOTE_TOO_SHORT.format(words=settings.mitre_minimum_quote_words)
    elif not reason:
        rejection = c.MitreProblem.NO_REASON
    elif not quote_is_in_description(quote, index["objects"][actor_id].get("description") or ""):
        rejection = c.MitreProblem.QUOTE_NOT_IN_DESCRIPTION
    else:
        for mitre_id in MITRE_ID_PATTERN.findall(reason):
            if mitre_id not in index["known_mitre_ids"]:
                rejection = c.MitreProblem.INVENTED_ID_IN_REASON
    if rejection is not None or actor_id is None:
        return None, {}, rejection
    matched_fields: list[str] = []
    listed_fields = list_or_empty(row.get("matched_fields"))
    for field_name in listed_fields:
        if field_name in c.MITRE_ASSET_FIELDS_TO_MATCH and field_name not in matched_fields:
            matched_fields.append(field_name)
    return (
        actor_id,
        {"relevance": relevance, "evidence_quote": quote, "reason": reason, "matched_fields": matched_fields},
        None,
    )


def keep_actor_rows_backed_by_mitre_text(
    rows: list[Any],
    actor_slice: list[dict[str, Any]],
    index: MitreIndex,
    settings: Settings,
    chosen: dict[str, dict[str, Any]],
    rejected_rows: dict[str, int],
) -> None:
    """Adds each row backed by MITRE text to chosen (the highest relevance wins); counts each rejected row."""
    actor_id_by_mitre_id = {}
    for profile in actor_slice:  # an ID listed by another slice is not this slice's actor
        actor_id_by_mitre_id[profile["mitre_id"]] = profile["actor_id"]
    for row in rows:
        actor_id, choice, rejection = check_actor_row(row, actor_id_by_mitre_id, index, settings)
        if actor_id is None:
            rejection = rejection or c.MitreProblem.UNKNOWN_ACTOR
            rejected_rows[rejection] = rejected_rows.get(rejection, 0) + 1
            continue
        if actor_id not in chosen or choice["relevance"] > chosen[actor_id]["relevance"]:
            chosen[actor_id] = choice


def lift_groups_through_campaigns(chosen: dict[str, dict[str, Any]], index: MitreIndex) -> None:
    """A relevant campaign lifts the groups it is attributed to."""
    for campaign_id, group_ids in index["campaign_groups"].items():
        if campaign_id not in chosen:
            continue
        campaign_choice = chosen[campaign_id]
        for group_id in group_ids:
            if group_id not in chosen:
                campaign_name = index["objects"][campaign_id]["name"]
                lifted_reason = f"{campaign_choice['reason']} (through the {campaign_name} campaign)"
                chosen[group_id] = {**campaign_choice, "reason": lifted_reason}
            elif campaign_choice["relevance"] > chosen[group_id]["relevance"]:
                chosen[group_id] = {**chosen[group_id], "relevance": campaign_choice["relevance"]}


def rank_selected_actors(chosen: dict[str, dict[str, Any]], index: MitreIndex) -> list[str]:
    """Highest relevance first, then the most documented techniques, then the name."""
    ranking = []
    for actor_id, choice in chosen.items():
        technique_count = len(index["techniques_by_actor"][actor_id])
        ranking.append((-choice["relevance"], -technique_count, index["objects"][actor_id]["name"], actor_id))
    ranking.sort()
    ranked_actor_ids = []
    for row in ranking:
        ranked_actor_ids.append(row[3])
    return ranked_actor_ids


# ----------------------------------------------------------------------------- planning


def plan_attack_paths(
    chat: ChatModel,
    asset_context: dict[str, Any],
    index: MitreIndex,
    settings: Settings,
    actor_selection: dict[str, Any],
) -> dict[str, Any]:
    """The planner's ranked attack paths over the whole MITRE catalogue, each checked by code.

    Returns {paths: [{title, objective, category, technique_stix_ids, supporting_systems, has_it_and_ot}],
    invalid_paths: {reason: n}, it_ot_crossing_required, it_ot_crossing_reason, planner_calls,
    system_mitre_assets: {supporting system name: [MITRE ICS asset IDs]}}. No valid path at all raises
    JobFailed(GENERATION_FAILED, NO_PATHS)."""
    asset_types = asset_and_system_types(asset_context)
    it_only = asset_types == {"IT"}
    actor_lines = planner_actor_lines(actor_selection, index, settings, it_only)
    paths, invalid_paths, answers, planner_calls = plan_paths_in_rounds(
        chat, asset_context, index, settings, actor_lines, asset_types
    )
    if not paths:
        raise JobFailed(c.ErrorCode.GENERATION_FAILED, c.MitreMessage.NO_PATHS)
    crossing_required, crossing_reason = decide_it_ot_crossing(asset_types, answers, settings)
    return {
        "paths": paths,
        "invalid_paths": invalid_paths,
        "it_ot_crossing_required": crossing_required,
        "it_ot_crossing_reason": crossing_reason,
        "planner_calls": planner_calls,
        "system_mitre_assets": map_systems_to_mitre_assets(answers, asset_context, index),
    }


def planner_actor_lines(
    actor_selection: dict[str, Any], index: MitreIndex, settings: Settings, it_only: bool
) -> list[str]:
    """One line per top-ranked selected actor, with the quote it was kept for and all its documented techniques."""
    lines = []
    for actor_id in actor_selection["ranked_actor_ids"][: settings.planner_relevant_actors]:
        if actor_id not in index["techniques_by_actor"]:  # revoked by an import since the run chose it: left out
            continue
        documented_ids = []
        for technique_id in index["techniques_by_actor"][actor_id]:
            if not it_only or "enterprise" in index["domains"][technique_id]:
                documented_ids.append(str(get_mitre_id(index["objects"][technique_id])))
        documented_ids.sort()
        actor = index["objects"][actor_id]
        choice = actor_selection["actors"][actor_id]
        matched = ", ".join(choice.get("matched_fields") or []) or "not stated"
        lines.append(
            f"{get_mitre_id(actor)} {actor['name']} ({actor['type']}) | relevance {choice['relevance']} | "
            f'MITRE: "{choice["evidence_quote"]}" | matched: {matched} | '
            f"reason: {choice['reason']} | techniques: {','.join(documented_ids)}"
        )
    return lines


def planner_prompt(settings: Settings) -> str:
    """The plan prompt with ATTACK_PATH_TECHNIQUES filled in; the planner aims one below the maximum (it tends to
    go one over), code enforces the range."""
    fewest_techniques, most_techniques = settings.attack_path_technique_range
    aimed_most = max(fewest_techniques, most_techniques - 1)
    path_techniques = f"{fewest_techniques} to {aimed_most} techniques (never more than {most_techniques})"
    return str(MITRE_PROMPTS["plan"]["text"]).replace("<path_techniques>", path_techniques)


def crossing_instruction(asset_types: set[str]) -> str:
    if asset_types == {"IT", "OT"}:
        return "required"
    if asset_types == {"IT"}:
        return "not applicable"
    return "decide from the context"


def plan_paths_in_rounds(
    chat: ChatModel,
    asset_context: dict[str, Any],
    index: MitreIndex,
    settings: Settings,
    actor_lines: list[str],
    asset_types: set[str],
) -> tuple[list[dict[str, Any]], dict[str, int], list[dict[str, Any]], int]:
    """(paths, invalid_paths, answers, planner calls). One call over all STRIDE categories, or one per category
    for a run above MITRE_PLANNER_SINGLE_CALL_LIMIT; "all paths" (TOTAL_SCENARIO_COUNT=0) is one call with no
    number, then later sets' further rounds (plan_further_paths). An empty round is asked again once."""
    wanted, single_call_limit = settings.total_scenario_count, settings.mitre_planner_single_call_limit
    rounds = [list(c.StrideCategory)] if wanted > single_call_limit else [[ALL_STRIDE_CATEGORIES]]
    prompt, it_only = planner_prompt(settings), asset_types == {"IT"}
    paths: list[dict[str, Any]] = []
    invalid_paths: dict[str, int] = {}
    answers: list[dict[str, Any]] = []
    planner_calls, retried_empty_round, round_number = 0, False, 0
    while round_number < len(rounds):
        scopes = [str(scope) for scope in rounds[round_number]]
        planner_inputs, actor_lines = fit_planner_inputs_to_call_limit(
            chat, prompt, scopes, asset_context, index, settings, actor_lines, crossing_instruction(asset_types)
        )
        ask_scope = partial(ask_one_planner_scope, chat, prompt, not retried_empty_round)
        round_answers = run_in_parallel(ask_scope, planner_inputs, len(planner_inputs), "mitre-plan")
        planner_calls += len(planner_inputs)
        answers.extend(round_answers)
        keep_valid_unique_paths(chat, round_answers, asset_context, index, settings, it_only, paths, invalid_paths)
        if not paths and not retried_empty_round:
            retried_empty_round = True
            continue
        round_number += 1
    return paths, invalid_paths, answers, planner_calls


def plan_further_paths(
    chat: ChatModel,
    asset_context: dict[str, Any],
    index: MitreIndex,
    settings: Settings,
    actor_selection: dict[str, Any],
    planned: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, int], bool]:
    """One "any others?" round of an "all paths" run: the planner gets every path planned so far (planned_already)
    and lists only further relevant ones, never a number; (new valid paths, rejected plans by reason, whether
    the answer was read: a lost one, unreadable or cut off, is not "none left")."""
    asset_types = asset_and_system_types(asset_context)
    it_only, prompt = asset_types == {"IT"}, planner_prompt(settings)
    actor_lines = planner_actor_lines(actor_selection, index, settings, it_only)
    crossing, already = crossing_instruction(asset_types), planned_already_lines(planned, index)
    planner_inputs, _ = fit_planner_inputs_to_call_limit(
        chat, prompt, [ALL_STRIDE_CATEGORIES], asset_context, index, settings, actor_lines, crossing, already
    )
    answer = ask_one_planner_scope(chat, prompt, True, planner_inputs[0])
    paths = list(planned)  # every planned path, written or failed too: no near copy of one
    invalid_paths: dict[str, int] = {}
    keep_valid_unique_paths(chat, [answer], asset_context, index, settings, it_only, paths, invalid_paths)
    return paths[len(planned) :], invalid_paths, bool(answer)  # {} only when the answer was lost


def planned_already_lines(planned: list[dict[str, Any]], index: MitreIndex) -> list[str]:
    """One short line per planned path, "id | category | title | systems attacked | technique IDs" (no scenario
    text: about 30 tokens)."""
    lines = []
    for position, path in enumerate(planned, start=1):
        mitre_ids = []
        for technique_id in path["technique_stix_ids"]:
            mitre_ids.append(str(get_mitre_id(index["objects"][technique_id])))
        systems = ", ".join(path["supporting_systems"]) or "the asset"
        title = path["title"] or path["objective"]
        lines.append(f"P{position} | {path['category']} | {title} | {systems} | {', '.join(mitre_ids)}")
    return lines


def planner_paths_requested(scope_count: int, settings: Settings) -> str:
    """How many paths each planner call is asked for: TOTAL_SCENARIO_COUNT plus spares, or for 0 "all" with no
    number (a number makes the model pad the list; further rounds find the rest)."""
    wanted = settings.total_scenario_count
    if wanted == 0:
        return "all"
    if scope_count > 1:
        return f"at least {math.ceil(wanted / scope_count) + settings.mitre_extra_paths_per_scope}"
    return f"at least {wanted + settings.mitre_extra_paths_in_one_call}"


def fit_planner_inputs_to_call_limit(
    chat: ChatModel,
    prompt: str,
    scopes: list[str],
    asset_context: dict[str, Any],
    index: MitreIndex,
    settings: Settings,
    actor_lines: list[str],
    crossing: str,
    planned_already: list[str] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """One planner input per scope, the lowest-ranked actor lines dropped until every call fits
    MITRE_PLAN_CALL_TOKENS_LIMIT (planned_already, a further round's, is never cut); with the actor lines kept."""
    paths_requested = "all further" if planned_already else planner_paths_requested(len(scopes), settings)
    while True:
        planner_inputs, largest_call_tokens = [], 0
        for scope in scopes:
            planner_input = {
                "asset_context": asset_context,
                "stride_scope": scope,
                "paths_requested": paths_requested,
                "catalogue_legend": index["catalogue_legend"],
                "techniques": "\n".join(index["technique_catalogue"]),
                "it_ot_crossing": crossing,
                "relevant_actors": actor_lines,
            }
            if asset_and_system_types(asset_context) != {"IT"}:
                planner_input["ics_assets"] = "\n".join(index["ics_assets"])
            if planned_already:
                planner_input["planned_already"] = planned_already
            planner_inputs.append(planner_input)
            scope_tokens = call_tokens((prompt, to_user_prompt(planner_input)), chat, c.AiTask.MITRE_PLAN)
            largest_call_tokens = max(largest_call_tokens, scope_tokens)
        if largest_call_tokens <= settings.mitre_plan_call_tokens_limit or not actor_lines:
            return planner_inputs, actor_lines
        actor_lines = actor_lines[:-1]


def read_planner_answer(answer: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    if not isinstance(answer.get("plans"), list):
        return answer, [c.MitreProblem.ANSWER_LAYOUT.format(key="plans")]
    return answer, []


def ask_one_planner_scope(
    chat: ChatModel, prompt: str, reuse_earlier_answer: bool, planner_input: dict[str, Any]
) -> dict[str, Any]:
    """One scope's planner answer; {} when the AI gave no usable answer (only this scope is lost)."""
    scope_prompt = (prompt, to_user_prompt(planner_input))
    try:
        answer: dict[str, Any] = ask_ai_and_check(
            chat, c.AiTask.MITRE_PLAN, scope_prompt, read_planner_answer, reuse_earlier_answer=reuse_earlier_answer
        )
    except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
        log.warning(c.LogEvent.MITRE_PLANNER_SCOPE_FAILED, error_type=type(exc).__name__)
        return {}
    return answer


def keep_valid_unique_paths(
    chat: ChatModel,
    round_answers: list[dict[str, Any]],
    asset_context: dict[str, Any],
    index: MitreIndex,
    settings: Settings,
    it_only: bool,
    paths: list[dict[str, Any]],
    invalid_paths: dict[str, int],
) -> None:
    """keep_valid_planned_paths, then the round's new paths the AI judges a repeat in meaning are dropped."""
    before = len(paths)
    keep_valid_planned_paths(round_answers, asset_context, index, settings, it_only, paths, invalid_paths)
    kept, dropped = drop_paths_repeating_others(chat, paths[:before], paths[before:])
    paths[before:] = kept
    if dropped:
        invalid_paths[c.MitreProblem.SAME_SCENARIO] = invalid_paths.get(c.MitreProblem.SAME_SCENARIO, 0) + dropped


def drop_paths_repeating_others(
    chat: ChatModel, planned: list[dict[str, Any]], new_paths: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], int]:
    """The new paths without those the AI judges the same scenario as a planned or a higher-ranked new one: the
    same target and the same result, whatever the way in. (kept, dropped); a lost answer keeps them all."""
    if not new_paths:
        return [], 0
    prompt = str(MITRE_PROMPTS["duplicates"]["text"])
    asked = {"planned": numbered_path_lines("P", planned), "new": numbered_path_lines("N", new_paths)}
    read = partial(read_duplicate_answer, len(planned), len(new_paths))
    try:
        repeated: set[str] = ask_ai_and_check(
            chat, c.AiTask.MITRE_DUPLICATE_CHECK, (prompt, to_user_prompt(asked)), read, reuse_earlier_answer=True
        )
    except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
        log.warning(c.LogEvent.MITRE_DUPLICATE_CHECK_FAILED, error_type=type(exc).__name__)
        return list(new_paths), 0
    kept = []
    for position, path in enumerate(new_paths, start=1):
        if f"N{position}" not in repeated:
            kept.append(path)
    return kept, len(new_paths) - len(kept)


def numbered_path_lines(prefix: str, paths: list[dict[str, Any]]) -> list[str]:
    """One line a path for the duplicate check: "id | category | title | objective | systems attacked"."""
    lines = []
    for position, path in enumerate(paths, start=1):
        systems = ", ".join(path["supporting_systems"]) or "the asset"
        lines.append(f"{prefix}{position} | {path['category']} | {path['title']} | {path['objective']} | {systems}")
    return lines


def read_duplicate_answer(planned_count: int, new_count: int, answer: dict[str, Any]) -> tuple[set[str], list[str]]:
    """The new ids judged a repeat, and each verdict naming no planned id or earlier new id (re-asked once)."""
    verdicts = answer.get("new")
    if not isinstance(verdicts, list):
        return set(), [c.MitreProblem.ANSWER_LAYOUT.format(key="new")]
    repeated, problems = set(), []
    for verdict in verdicts:
        new_id = str(verdict.get("id") or "") if isinstance(verdict, dict) else ""
        position = path_position(new_id, "N", new_count)
        duplicate_of = verdict.get("duplicate_of") if position else None
        if not duplicate_of:
            continue  # not a new path, or a scenario of its own
        earlier_new = path_position(str(duplicate_of), "N", new_count)
        if path_position(str(duplicate_of), "P", planned_count) or 0 < earlier_new < position:
            repeated.add(new_id)
        else:
            problems.append(c.MitreProblem.DUPLICATE_OF_UNKNOWN.format(id=new_id, duplicate_of=duplicate_of))
    return repeated, problems


def path_position(path_id: str, prefix: str, count: int) -> int:
    """The 1-based position an id like "N3" names in a list of `count` paths, else 0."""
    normalized = path_id.strip().upper()
    number = normalized.removeprefix(prefix)
    if not normalized.startswith(prefix) or not number.isdigit():
        return 0
    return int(number) if 1 <= int(number) <= count else 0


def keep_valid_planned_paths(
    round_answers: list[dict[str, Any]],
    asset_context: dict[str, Any],
    index: MitreIndex,
    settings: Settings,
    it_only: bool,
    paths: list[dict[str, Any]],
    invalid_paths: dict[str, int],
) -> None:
    """Adds each valid plan to paths, ranked across scopes (every scope's first plan, then every second, ...);
    counts each rejected plan under its reason."""
    ranked_plans = []
    for scope_position, answer in enumerate(round_answers):
        plans = list_or_empty(answer.get("plans"))
        for plan_position, plan in enumerate(plans):
            if isinstance(plan, dict):
                ranked_plans.append((plan_position, scope_position, plan))
    ranked_plans.sort(key=plan_rank)
    system_names = system_name_by_folded_name(asset_context)
    for _, _, plan in ranked_plans:
        technique_ids = resolve_planned_techniques(plan, index, it_only)
        category = STRIDE_BY_LOWERCASE.get(str(plan.get("category") or "").strip().casefold())
        supporting_systems = planned_supporting_systems(plan, system_names)
        reaches_ot = path_reaches_ot(asset_context, supporting_systems)
        reason = planned_path_rejection(technique_ids, category, paths, index, settings, reaches_ot)
        if reason is not None:
            invalid_paths[reason] = invalid_paths.get(reason, 0) + 1
            continue
        paths.append(
            {
                "title": str(plan.get("title") or ""),
                "objective": str(plan.get("objective") or ""),
                "category": category,
                "technique_stix_ids": technique_ids,
                "supporting_systems": supporting_systems,
                "has_it_and_ot": path_has_both_it_and_ot_techniques(technique_ids, index),
            }
        )


def plan_rank(ranked_plan: tuple[int, int, dict[str, Any]]) -> tuple[int, int]:
    """(plan position, scope position): the plans themselves are never compared."""
    return ranked_plan[0], ranked_plan[1]


def resolve_planned_techniques(plan: dict[str, Any], index: MitreIndex, it_only: bool) -> list[str]:
    """The plan's real techniques as STIX ids, once each; Enterprise ones only for an IT-only asset."""
    technique_ids: list[str] = []
    listed_ids = list_or_empty(plan.get("technique_ids"))
    for mitre_id in listed_ids:
        if not isinstance(mitre_id, str):
            continue
        technique_id = index["technique_by_mitre_id"].get(mitre_id.strip().upper())
        is_new = technique_id is not None and technique_id not in technique_ids
        if is_new and (not it_only or "enterprise" in index["domains"][technique_id]):
            technique_ids.append(technique_id)
    return technique_ids


def planned_supporting_systems(plan: dict[str, Any], system_names: dict[str, str]) -> list[str]:
    """The plan's supporting systems that are the asset's own, with the asset's names; anything else ignored."""
    planned_systems = []
    listed_systems = list_or_empty(plan.get("supporting_systems"))
    for system_name in listed_systems:
        input_system_name = system_names.get(fold_name(system_name)) if isinstance(system_name, str) else None
        if input_system_name and input_system_name not in planned_systems:
            planned_systems.append(input_system_name)
    return planned_systems


def path_reaches_ot(asset_context: dict[str, Any], planned_systems: list[str]) -> bool:
    """True when the path attacks OT: the asset is OT, or a supporting system the plan names is OT."""
    if asset_context["asset_type"] == "OT":
        return True
    for supporting_system in asset_context["supporting_systems"]:
        if supporting_system["name"] in planned_systems and supporting_system["type"] == "OT":
            return True
    return False


def planned_path_rejection(
    technique_ids: list[str],
    category: str | None,
    paths: list[dict[str, Any]],
    index: MitreIndex,
    settings: Settings,
    reaches_ot: bool,
) -> str | None:
    """Why a plan is rejected, or None for a valid one. Only a path that attacks OT needs an ICS technique."""
    fewest_techniques, most_techniques = settings.attack_path_technique_range
    has_ics_technique = False
    for technique_id in technique_ids:
        if "ics" in index["domains"][technique_id]:
            has_ics_technique = True
    if len(technique_ids) < fewest_techniques:
        return c.MitreProblem.TOO_FEW_TECHNIQUES.format(count=fewest_techniques)
    if len(technique_ids) > most_techniques:
        return c.MitreProblem.TOO_MANY_TECHNIQUES.format(count=most_techniques)
    if reaches_ot and not has_ics_technique:
        return c.MitreProblem.NO_ICS_TECHNIQUE
    if not category:
        return c.MitreProblem.NO_STRIDE_CATEGORY
    documented_group_found = False
    for actor_id, used_techniques in index["techniques_by_actor"].items():
        if index["objects"][actor_id]["type"] == "intrusion-set" and set(technique_ids) & set(used_techniques):
            documented_group_found = True
            break
    if not documented_group_found:
        return c.MitreProblem.NO_DOCUMENTED_GROUP
    for accepted_path in paths:
        accepted_ids = set(accepted_path["technique_stix_ids"])
        overlap = len(accepted_ids & set(technique_ids)) / len(accepted_ids | set(technique_ids))
        if overlap >= settings.mitre_duplicate_technique_overlap:  # in any STRIDE category: the same attack retold
            return c.MitreProblem.DUPLICATE_PATH
    return None


def map_systems_to_mitre_assets(
    answers: list[dict[str, Any]], asset_context: dict[str, Any], index: MitreIndex
) -> dict[str, list[str]]:
    """Which MITRE ICS asset types each supporting system is (the planner's mapping, by meaning), kept only for
    the asset's own systems and real MITRE asset IDs; the first answer naming a system wins."""
    system_names, system_mitre_assets = system_name_by_folded_name(asset_context), {}
    for answer in answers:
        mappings = list_or_empty(answer.get("system_assets"))
        for mapping in mappings:
            if not isinstance(mapping, dict) or not isinstance(mapping.get("supporting_system"), str):
                continue
            input_system_name = system_names.get(fold_name(mapping["supporting_system"]))
            if input_system_name is None or input_system_name in system_mitre_assets:
                continue
            listed_asset_ids = list_or_empty(mapping.get("mitre_asset_ids"))
            asset_ids: list[str] = []
            for listed_asset_id in listed_asset_ids:
                asset_mitre_id = str(listed_asset_id).strip().upper()
                if asset_mitre_id in index["asset_by_mitre_id"] and asset_mitre_id not in asset_ids:
                    asset_ids.append(asset_mitre_id)
            if asset_ids:
                system_mitre_assets[input_system_name] = asset_ids
    return system_mitre_assets


def decide_it_ot_crossing(
    asset_types: set[str], answers: list[dict[str, Any]], settings: Settings
) -> tuple[bool, str | None]:
    """Is an IT/OT crossing path required? Mixed IT and OT: yes. All IT: no. All OT: as the planner judged, its
    reason cut to MITRE_CROSSING_REASON_CHARACTERS."""
    if asset_types == {"IT", "OT"}:
        return True, c.MitreProblem.CROSSING_MIXED_TYPES
    if asset_types == {"IT"}:
        return False, None
    for answer in answers:
        if answer.get("it_ot_crossing_relevant") is True:
            reason = str(answer.get("it_ot_crossing_reason") or c.MitreProblem.CROSSING_JUDGED_BY_PLANNER)
            return True, shorten_at_word_boundary(reason, settings.mitre_crossing_reason_characters)
    return False, None


# ----------------------------------------------------------------------------- writing one scenario


def writer_prompt(settings: Settings) -> str:
    """The writer prompt with the word ranges filled in. Models write more words than they aim for, so they
    aim for the low end and a number of short sentences; code enforces the maximum."""
    scenario_low, scenario_high = settings.mitre_scenario_words
    scenario_sentences = max(
        settings.mitre_minimum_scenario_sentences, round(scenario_low / settings.mitre_words_per_sentence)
    )
    risk_low, risk_high = settings.mitre_risk_words
    scenario_size = (
        f"about {scenario_sentences} short sentences of about {scenario_low} words in total "
        f"(between {scenario_low} and {scenario_high}, never more than {scenario_high})"
    )
    risk_size = f"about {risk_low} words (between {risk_low} and {risk_high}, never more than {risk_high})"
    risk_title_low, risk_title_high = settings.mitre_risk_title_words
    scenario_title_low, scenario_title_high = settings.mitre_scenario_title_words
    prompt = str(MITRE_PROMPTS["writer"]["text"])
    prompt = prompt.replace("<scenario_words>", scenario_size).replace("<risk_words>", risk_size)
    prompt = prompt.replace("<risk_title_words>", f"{risk_title_low} to {risk_title_high} words")
    return prompt.replace("<scenario_title_words>", f"{scenario_title_low} to {scenario_title_high} words")


def writer_techniques(technique_ids: list[str], index: MitreIndex, settings: Settings) -> list[dict[str, Any]]:
    """The path's MITRE technique pages (each description's opening sentences, within
    WRITER_TECHNIQUE_DESCRIPTION_CHARACTERS), with the domain attack_techniques must use and the ICS assets targeted."""
    techniques = []
    for technique_id in technique_ids:
        technique = index["objects"][technique_id]
        tactics = []
        for phase in technique.get("kill_chain_phases") or []:
            tactics.append(phase["phase_name"])
        techniques.append(
            {
                "stix_id": technique_id,
                "mitre_id": get_mitre_id(technique),
                "name": technique["name"],
                "description": opening_sentences(
                    technique.get("description") or "", settings.writer_technique_description_characters
                ),
                "domain": "ics" if "ics" in index["domains"][technique_id] else "enterprise",
                "tactics": tactics,
                "platforms": technique.get("x_mitre_platforms"),
                "targets_ics_assets": technique_targeted_asset_names(technique_id, index),
            }
        )
    return techniques


def writer_procedures(
    technique_ids: list[str],
    index: MitreIndex,
    selected_actors: dict[str, Any],
    candidate_ids: set[str],
    procedures_limit: int,
) -> list[dict[str, Any]]:
    """Up to procedures_limit procedure examples per technique: selected actors first, then candidate groups,
    then the rest (each newest first)."""
    procedures = []
    for technique_id in technique_ids:
        from_selected_actors, from_candidates, from_others = [], [], []
        for procedure in index["procedures_by_technique"][technique_id]:
            if procedure["actor_stix_id"] in selected_actors:
                from_selected_actors.append(procedure)
            elif procedure["actor_stix_id"] in candidate_ids:
                from_candidates.append(procedure)
            else:
                from_others.append(procedure)
        procedures.extend((from_selected_actors + from_candidates + from_others)[:procedures_limit])
    return procedures


def writer_candidates(
    candidate_ids: list[str],
    technique_ids: list[str],
    index: MitreIndex,
    selected_actors: dict[str, Any],
    settings: Settings,
) -> list[dict[str, Any]]:
    """The candidate groups as the writer sees them, with the targeting quote they were selected for."""
    candidates = []
    for actor_id in candidate_ids:
        documented_for = []
        for evidence in documented_techniques_of_group(actor_id, technique_ids, index):
            documented_for.append(
                {
                    "technique": evidence["mitre_id"],
                    "domain": evidence["domain"],
                    "via_software": evidence["via_software"],
                }
            )
        actor = index["objects"][actor_id]
        choice = selected_actors.get(actor_id) or {}
        description_limit = settings.writer_candidate_description_characters
        candidates.append(
            {
                "mitre_id": get_mitre_id(actor),
                "name": actor["name"],
                "description": shorten_at_word_boundary(actor.get("description") or "", description_limit),
                "targeting": choice.get("evidence_quote"),
                "matched_fields": choice.get("matched_fields"),
                "documented_for": documented_for,
            }
        )
    return candidates


def software_used_in_procedures(procedures: list[dict[str, Any]], index: MitreIndex) -> dict[str, str]:
    """The MITRE description of each software the procedures name, by name."""
    software_names = set()
    for procedure in procedures:
        if procedure["via_software"]:
            software_names.add(procedure["via_software"])
    software = {}
    for name in sorted(software_names):
        software[name] = index["software_descriptions"].get(name, "")
    return software


def build_writer_input_within_call_limit(
    chat: ChatModel,
    prompt: str,
    planned_path: dict[str, Any],
    ranked_candidate_ids: list[str],
    groups_used_in_other_scenarios: list[dict[str, str]],
    asset_context: dict[str, Any],
    index: MitreIndex,
    settings: Settings,
    selected_actors: dict[str, Any],
    threat_types: list[tuple[int, str]],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]] | None:
    """(writer input, procedures, candidates) within MITRE_WRITE_CALL_TOKENS_LIMIT, trimmed by halving; or None."""
    technique_ids = planned_path["technique_stix_ids"]
    techniques = writer_techniques(technique_ids, index, settings)
    procedures_limit, candidates_limit = settings.procedures_per_technique, len(ranked_candidate_ids)
    while True:
        candidate_ids = ranked_candidate_ids[:candidates_limit]
        procedures = writer_procedures(
            technique_ids, index, selected_actors, set(ranked_candidate_ids), procedures_limit
        )
        writer_input = {
            "asset_context": asset_context,
            "plan": {field: planned_path[field] for field in ("title", "objective", "category", "supporting_systems")},
            "techniques": techniques,
            "procedures": procedures,
            "candidate_actors": writer_candidates(candidate_ids, technique_ids, index, selected_actors, settings),
            "groups_used_in_other_scenarios": groups_used_in_other_scenarios,
            "software": software_used_in_procedures(procedures, index),
            "threat_types": [name for _, name in threat_types],
        }
        input_tokens = call_tokens((prompt, to_user_prompt(writer_input)), chat, c.AiTask.MITRE_WRITE)
        if input_tokens <= settings.mitre_write_call_tokens_limit:
            return writer_input, procedures, candidate_ids
        if procedures_limit > 1:
            procedures_limit = max(1, procedures_limit // 2)
        elif candidates_limit > settings.mitre_minimum_candidates_after_trim:
            candidates_limit = max(settings.mitre_minimum_candidates_after_trim, candidates_limit // 2)
        else:
            return None


def scenario_word_problems(answer: dict[str, Any], settings: Settings) -> list[str]:
    """Only the maximum of each word range is enforced, MITRE_WORD_LIMIT_SLACK over it allowed; the minimum is
    prompt guidance."""
    word_limits = (
        ("threat_scenario", settings.mitre_scenario_words),
        ("risk_statement", settings.mitre_risk_words),
        ("threat_scenario_description", settings.mitre_risk_title_words),
        ("scenario_title", settings.mitre_scenario_title_words),
    )
    problems = []
    for field, (_, maximum) in word_limits:
        word_count = len(str(answer.get(field, "")).split())
        if word_count > maximum * (1 + settings.mitre_word_limit_slack):
            problems.append(c.MitreProblem.WORD_LIMIT.format(field=field, words=word_count, maximum=maximum))
    return problems


def schema_problems(error: ValidationError) -> list[str]:
    """The failing fields and error types (never the input values, which repeat the answer)."""
    failing_fields = []
    for schema_error in error.errors(include_input=False, include_context=False, include_url=False):
        location = ".".join(str(part) for part in schema_error["loc"])
        failing_fields.append(c.MitreProblem.SCHEMA_FAILED.format(location=location, error_type=schema_error["type"]))
    return failing_fields


def check_written_techniques(
    scenario: Scenario, planned_path: dict[str, Any], index: MitreIndex, settings: Settings
) -> tuple[list[dict[str, Any]], list[dict[str, str]], list[str]]:
    """(the path's own techniques, the ones left out, problems). A technique is kept when its stix_id and mitre_id
    are one of the planned techniques, its name and domain then taken from MITRE; any other is left out (code
    only removes, never adds). Re-asked only when fewer than ATTACK_PATH_TECHNIQUES' minimum are left."""
    verified_techniques, dropped, problems = [], [], []
    for technique in scenario.attack_techniques:
        known_technique = index["techniques"].get(technique.stix_id)
        is_planned = technique.stix_id in planned_path["technique_stix_ids"]
        known_name = known_technique["name"] if known_technique is not None else technique.name
        if (
            known_technique is None
            or not is_planned
            or get_mitre_id(known_technique) != technique.mitre_id.strip().upper()
        ):
            dropped.append({"mitre_id": technique.mitre_id, "name": known_name})
            problems.append(c.MitreProblem.TECHNIQUE_NOT_PLANNED.format(mitre_id=technique.mitre_id))
            continue
        domain = "ics" if "ics" in index["domains"][technique.stix_id] else "enterprise"
        verified = {**technique.model_dump(), "mitre_id": get_mitre_id(known_technique), "name": known_name}
        verified_techniques.append({**verified, "domain": domain})
    fewest_techniques, _ = settings.attack_path_technique_range
    if len(verified_techniques) >= fewest_techniques:
        problems = []  # ponytail: the unplanned ones are simply left out
    return verified_techniques, dropped, problems


def check_written_groups(
    scenario: Scenario, technique_ids: list[str], index: MitreIndex, settings: Settings, candidate_ids: list[str]
) -> tuple[list[dict[str, Any]], list[dict[str, str]], list[str]]:
    """(the verified groups, the ones left out, problems). A group is kept when it is a supplied candidate
    documented in MITRE for a kept technique (an Enterprise step counts for an OT asset as well as an ICS step),
    its name taken from MITRE; the first MITRE_GROUPS_PER_SCENARIO are kept, a repeat is skipped and any other
    is left out. Re-asked only when no group is left."""
    verified_groups: list[dict[str, Any]] = []
    dropped, problems, seen_group_ids = [], [], set()
    for group in scenario.relevant_groups:
        group_id = index["group_by_mitre_id"].get(group.mitre_id.strip().upper())
        if group_id in seen_group_ids:
            continue
        if group_id is None or group_id not in candidate_ids:
            dropped.append({"mitre_id": group.mitre_id, "name": group.name})
            problems.append(c.MitreProblem.GROUP_NOT_A_CANDIDATE.format(name=group.name, mitre_id=group.mitre_id))
            continue
        documented_techniques = documented_techniques_of_group(group_id, technique_ids, index)
        if not documented_techniques:
            dropped.append({"mitre_id": group.mitre_id, "name": group.name})
            problems.append(c.MitreProblem.GROUP_NOT_DOCUMENTED.format(name=group.name))
            continue
        if len(verified_groups) == settings.mitre_groups_per_scenario:
            break  # ponytail: the first N kept; a later valid group is MITRE-documented, so its text stays true
        seen_group_ids.add(group_id)
        group_object = index["objects"][group_id]
        verified_groups.append(
            {
                **group.model_dump(),
                "name": group_object["name"],
                "mitre_id": get_mitre_id(group_object),
                "evidence_type": evidence_type(documented_techniques),
                "documented_techniques": documented_techniques,
            }
        )
    return verified_groups, dropped, [] if verified_groups else problems


def text_naming_dropped_items(answer: dict[str, Any], dropped: list[dict[str, str]]) -> list[str]:
    """A problem for each left-out technique or group the scenario's text still names (its MITRE ID or name):
    the text must never tell of what the card no longer lists, so that answer is re-asked instead."""
    text_parts = []
    for field in ("scenario_title", "threat_scenario_description", "threat_scenario", "risk_statement"):
        text_parts.append(str(answer.get(field, "")))
    text = " ".join(text_parts).casefold()
    problems = []
    for item in dropped:
        for word in (item["mitre_id"].strip(), item["name"].strip()):
            if word and word.casefold() in text:
                problems.append(c.MitreProblem.DROPPED_ITEM_IN_TEXT.format(name=word))
                break
    return problems


def check_written_scenario(
    answer: dict[str, Any],
    planned_path: dict[str, Any],
    asset_context: dict[str, Any],
    index: MitreIndex,
    settings: Settings,
    candidate_ids: list[str],
) -> tuple[dict[str, Any] | None, list[str]]:
    """(the checked scenario, []) or (None, the problems the writer is asked to fix)."""
    problems = scenario_word_problems(answer, settings)
    try:
        scenario = Scenario.model_validate(answer)
    except ValidationError as error:
        return None, problems + schema_problems(error)
    verified_techniques, verified_groups, fact_problems = check_written_mitre_facts(
        scenario, answer, planned_path, index, settings, candidate_ids
    )
    problems += fact_problems
    technique_ids = []
    for technique in verified_techniques:
        technique_ids.append(technique["stix_id"])
    system_names, verified_systems = system_name_by_folded_name(asset_context), []
    for system_name in scenario.supporting_systems:
        input_system_name = system_names.get(fold_name(system_name))
        if fold_name(system_name) == fold_name(asset_context["asset_name"]):
            continue  # the asset itself, listed with its systems: not an invented system
        if input_system_name is None:
            problems.append(c.MitreProblem.SYSTEM_NOT_THE_ASSETS.format(name=system_name))
        elif input_system_name not in verified_systems:
            verified_systems.append(input_system_name)
    if planned_path["has_it_and_ot"] and not path_has_both_it_and_ot_techniques(technique_ids, index):
        problems.append(c.MitreProblem.CROSSING_TECHNIQUES_DROPPED)
    for mitre_id in MITRE_ID_PATTERN.findall(json.dumps(answer, ensure_ascii=False)):
        if mitre_id not in index["known_mitre_ids"]:
            problems.append(c.MitreProblem.INVENTED_ID.format(mitre_id=mitre_id))
    if problems:
        return None, problems
    checked = {**answer, **scenario.model_dump(), "attack_techniques": verified_techniques}
    return {**checked, "relevant_groups": verified_groups, "supporting_systems": verified_systems}, []


def check_written_mitre_facts(
    scenario: Scenario,
    answer: dict[str, Any],
    planned_path: dict[str, Any],
    index: MitreIndex,
    settings: Settings,
    candidate_ids: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """(techniques, groups, problems): an unplanned technique or a group that fails its checks is left out rather
    than re-asked (code only removes, never adds), unless too few are left or the text still names it."""
    techniques, dropped_techniques, problems = check_written_techniques(scenario, planned_path, index, settings)
    technique_ids = []
    for technique in techniques:
        technique_ids.append(technique["stix_id"])
    groups, dropped_groups, group_problems = check_written_groups(
        scenario, technique_ids, index, settings, candidate_ids
    )
    problems = problems + group_problems + text_naming_dropped_items(answer, dropped_techniques + dropped_groups)
    if not problems and (dropped_techniques or dropped_groups):
        log.info(
            c.LogEvent.MITRE_WRITER_ANSWER_REPAIRED,
            techniques_dropped=len(dropped_techniques),
            groups_dropped=len(dropped_groups),
        )
    return techniques, groups, problems


def read_written_scenario(
    planned_path: dict[str, Any],
    asset_context: dict[str, Any],
    index: MitreIndex,
    settings: Settings,
    candidate_ids: list[str],
    threat_types: list[tuple[int, str]],
    written: dict[str, Any],
) -> tuple[dict[str, Any] | None, list[str]]:
    """One written scenario of the writer's answer, checked, with the path's category, the prompt version and the
    library threat type it copied (threat_type, threat_type_id; none to copy when the library has no types)."""
    scenario = {**written, "category": planned_path["category"], "prompt_version": c.PromptVersion.MITRE_WRITER}
    scenario.pop("slot", None)
    scenario["supporting_systems"] = system_names_as_written(scenario.get("supporting_systems"))
    checked, problems = check_written_scenario(scenario, planned_path, asset_context, index, settings, candidate_ids)
    threat_type = find_listed_threat_type(scenario.get("threat_type"), threat_types)
    if threat_types and threat_type is None:
        problems = [*problems, c.MitreProblem.THREAT_TYPE_NOT_LISTED]
    if problems or checked is None:
        return None, problems
    type_id, type_name = threat_type or (None, "")
    return {**checked, "threat_type": type_name, "threat_type_id": type_id}, []


def system_names_as_written(systems: object) -> object:
    """The writer's supporting systems with a system written as {"name": ...} read as its name (not re-asked);
    anything else as given, for the schema check to judge."""
    if not isinstance(systems, list):
        return systems
    names = []
    for system in systems:
        names.append(system["name"] if isinstance(system, dict) and isinstance(system.get("name"), str) else system)
    return names


def find_listed_threat_type(given: object, threat_types: list[tuple[int, str]]) -> tuple[int, str] | None:
    """The library's (type_id, name) the writer copied, matched as the ATT&CK writer's is; None when not listed."""
    key = threat_name_key(given) if isinstance(given, str) else ""
    for type_id, name in threat_types:
        if key and threat_name_key(name) == key:
            return type_id, name
    return None


def systems_targeted(
    scenario: dict[str, Any], index: MitreIndex, system_mitre_assets: dict[str, list[str]]
) -> list[dict[str, Any]]:
    """Per technique and supporting system: the MITRE ICS asset types the technique targets that the system is."""
    targeted = []
    for technique in scenario["attack_techniques"]:
        targeted_asset_ids = index["asset_mitre_ids_by_technique"].get(technique["stix_id"], [])
        for system_name in scenario["supporting_systems"]:
            asset_names = []
            for asset_mitre_id in system_mitre_assets.get(system_name, []):
                if asset_mitre_id in targeted_asset_ids:
                    asset_name = index["objects"][index["asset_by_mitre_id"][asset_mitre_id]]["name"]
                    asset_names.append(f"{asset_mitre_id} {asset_name}")
            if asset_names:
                targeted.append(
                    {"technique": technique["mitre_id"], "supporting_system": system_name, "mitre_assets": asset_names}
                )
    return targeted


def technique_mitigations(technique: dict[str, Any], index: MitreIndex) -> dict[str, Any]:
    """A technique's MITRE mitigations as the card keeps them; a sub-technique with none of its own carries its
    parent's, naming the parent in inherited_from (owner 2026-11-24)."""
    entry = {
        "technique": technique["mitre_id"],
        "technique_name": index["objects"][technique["stix_id"]]["name"],
        "mitigations": index["mitigations_by_technique"][technique["stix_id"]],
    }
    parent = index.get("mitigations_inherited_from", {}).get(technique["stix_id"])
    if parent is not None:
        entry["inherited_from"] = parent
    return entry


def add_mitre_evidence_to_scenario(
    scenario: dict[str, Any],
    procedures: list[dict[str, Any]],
    index: MitreIndex,
    actor_selection: dict[str, Any],
    system_mitre_assets: dict[str, list[str]],
) -> dict[str, Any]:
    """The checked scenario with what the reader is shown beside it, for the techniques it kept only: the systems
    each targets, each group's selection quote and relevance in MITRE's own words, the procedures, the MITRE
    mitigations and the attack.mitre.org page (url) of each technique and group."""
    selected_actors = actor_selection["actors"]
    for group in scenario["relevant_groups"]:
        group_id = index["group_by_mitre_id"][group["mitre_id"]]
        choice = selected_actors.get(group_id) or {}
        group["url"] = get_mitre_url(index["objects"][group_id])
        group["mitre_targeting_quote"] = choice.get("evidence_quote")
        group["matched_fields"] = choice.get("matched_fields") or []
        group["relevance"] = relevance_from_mitre(
            group.get("documented_techniques") or [], choice.get("evidence_quote")
        )
        for documented in group.get("documented_techniques") or []:
            documented["url"] = technique_url(index, documented["mitre_id"])
    kept_ids, mitigations = set(), []
    for technique in scenario["attack_techniques"]:
        technique["url"] = get_mitre_url(index["objects"][technique["stix_id"]])
        kept_ids.add(technique["mitre_id"])
        mitigations.append(technique_mitigations(technique, index))
    kept_procedures = [procedure for procedure in procedures if procedure["technique"] in kept_ids]
    targeted = systems_targeted(scenario, index, system_mitre_assets)
    return {**scenario, "systems_targeted": targeted, "procedures": kept_procedures, "mitigations": mitigations}


def relevance_from_mitre(documented_techniques: list[dict[str, Any]], targeting_quote: str | None) -> str:
    """Why a group is listed, in MITRE's words only: its checked targeting quote, then the scenario techniques
    MITRE documents it for (with the software where indirect). No AI text."""
    uses = []
    for evidence in documented_techniques:
        software = evidence.get("via_software")
        uses.append(f"{evidence['name']} (via {software})" if software else evidence["name"])
    documented = f"MITRE documents it using {', '.join(uses)}."
    if targeting_quote:
        return f'MITRE describes it: "{targeting_quote}". {documented}'
    return f"Listed because {documented}"


def technique_url(index: MitreIndex, mitre_id: str) -> str | None:
    """A technique's attack.mitre.org page by its ATT&CK ID, or None for an ID the index does not hold."""
    technique_id = index["technique_by_mitre_id"].get(mitre_id)
    return get_mitre_url(index["objects"][technique_id]) if technique_id else None


#: The writer input fields of one path; the rest (SHARED_INPUT_FIELDS) is sent once a call.
PATH_INPUT_FIELDS = ("plan", "techniques", "procedures", "candidate_actors", "software")
SHARED_INPUT_FIELDS = ("asset_context", "groups_used_in_other_scenarios", "threat_types")


def build_path_brief(
    chat: ChatModel,
    prompt: str,
    taken: tuple[int, dict[str, Any], list[str]],
    groups_used: list[dict[str, str]],
    writing: dict[str, Any],
) -> dict[str, Any] | None:
    """One taken path's part of a writer call, trimmed so that a call with it alone fits
    MITRE_WRITE_CALL_TOKENS_LIMIT: {slot, position, path, input, shared, procedures, candidate_ids}; None when it
    never fits."""
    position, planned_path, ranked_candidate_ids = taken
    retired = retired_techniques_of(planned_path, writing["index"])
    if retired:  # owner 2026-11-27: an import since planning retired them; written, the path would fail every set
        log.warning(c.LogEvent.MITRE_PATH_DROPPED, reason="technique_retired", retired=retired)
        return None
    built = build_writer_input_within_call_limit(
        chat,
        prompt,
        planned_path,
        ranked_candidate_ids,
        groups_used,
        writing["asset_context"],
        writing["index"],
        writing["settings"],
        writing["actor_selection"]["actors"],
        writing["threat_types"],
    )
    if built is None:
        log.warning(c.LogEvent.MITRE_PATH_DROPPED, reason="writer_input_over_call_limit")
        return None
    writer_input, procedures, candidate_ids = built
    slot = f"path-{position + 1}"
    path_input = {"slot": slot, **fields_of(writer_input, PATH_INPUT_FIELDS)}
    brief = {"slot": slot, "position": position, "path": planned_path, "input": path_input}
    shared = fields_of(writer_input, SHARED_INPUT_FIELDS)
    return brief | {"shared": shared, "procedures": procedures, "candidate_ids": candidate_ids}


def retired_techniques_of(planned_path: dict[str, Any], index: MitreIndex) -> list[str]:
    """The path's techniques (STIX ids) the MITRE data in use no longer holds: an ATT&CK import since the run was
    planned revoked or deprecated them. [] for a path that can still be written."""
    retired = []
    for technique_id in planned_path["technique_stix_ids"]:
        if technique_id not in index["techniques"] or technique_id not in index["procedures_by_technique"]:
            retired.append(technique_id)
    return retired


def fields_of(data: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """The named fields of `data`, in that order."""
    picked = {}
    for field in fields:
        picked[field] = data[field]
    return picked


def writer_call_prompt(prompt: str, briefs: Sequence[dict[str, Any]]) -> ChatPrompt:
    """One writer call: the shared input once, then each path's own part under "paths"."""
    paths = []
    for brief in briefs:
        paths.append(brief["input"])
    return prompt, to_user_prompt({**briefs[0]["shared"], "paths": paths})


def read_written_slots(asked: set[str], answer: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """The answer's scenarios by slot. Only a reply not shaped {"scenarios": [...]} is asked again here; a slot
    left out or failing its checks is re-asked with the set's other failures."""
    if not isinstance(answer.get("scenarios"), list):
        return {}, [c.MitreProblem.ANSWER_LAYOUT.format(key="scenarios")]
    items, _ = answers_for_asked_slots(answer, "scenarios", asked)
    by_slot = {}
    for item in items:
        by_slot[str(item["slot"])] = item
    return by_slot, []


def ask_writer_for_part(chat: ChatModel, prompt: str, part: Sequence[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """One writer call's scenarios by slot; {} when the AI gave no usable answer (the part's paths fail)."""
    asked = set()
    for brief in part:
        asked.add(brief["slot"])
    read_answer = partial(read_written_slots, asked)
    try:
        written: dict[str, dict[str, Any]] = ask_ai_and_check(
            chat, c.AiTask.MITRE_WRITE, writer_call_prompt(prompt, part), read_answer, reuse_earlier_answer=True
        )
    except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
        log.warning(c.LogEvent.MITRE_PATH_DROPPED, error_type=type(exc).__name__, paths=len(part))
        return {}
    return written


def ask_writer_for_briefs(
    chat: ChatModel, prompt: str, briefs: list[dict[str, Any]], settings: Settings
) -> dict[str, dict[str, Any]]:
    """Every brief's written scenario by slot: at most one set's paths a call (CII_ANSWER_TOKENS_MITRE_WRITE is
    sized for one set's answer: a regenerate may ask for many more), each call split again only above
    MITRE_WRITE_CALL_TOKENS_LIMIT; at most MITRE_PARALLEL_WRITERS calls at once."""
    limit, per_call = settings.mitre_write_call_tokens_limit, max(settings.initial_set_size, settings.next_set_size)
    parts: list[Sequence[dict[str, Any]]] = []
    for chunk in itertools.batched(briefs, per_call):
        parts.extend(within_call_limit(chunk, partial(writer_call_prompt, prompt), chat, c.AiTask.MITRE_WRITE, limit))
    ask_part = partial(ask_writer_for_part, chat, prompt)
    written: dict[str, dict[str, Any]] = {}
    for answer in run_in_parallel(ask_part, parts, settings.mitre_parallel_writers, "mitre-writer"):
        written |= answer
    return written


def check_brief_answer(
    brief: dict[str, Any], written: dict[str, Any] | None, writing: dict[str, Any]
) -> tuple[dict[str, Any] | None, list[str]]:
    """The brief's written scenario checked and given its MITRE evidence, or (None, the problems to fix)."""
    if written is None:
        return None, [c.MitreProblem.NO_SCENARIO_FOR_PATH]
    scenario, problems = read_written_scenario(
        brief["path"],
        writing["asset_context"],
        writing["index"],
        writing["settings"],
        brief["candidate_ids"],
        writing["threat_types"],
        written,
    )
    if scenario is None:
        return None, problems
    with_evidence = add_mitre_evidence_to_scenario(
        scenario, brief["procedures"], writing["index"], writing["actor_selection"], writing["system_mitre_assets"]
    )
    return with_evidence, []


def write_briefs(
    chat: ChatModel, prompt: str, briefs: list[dict[str, Any]], writing: dict[str, Any]
) -> dict[str, dict[str, Any] | None]:
    """Each brief's checked scenario by slot, None when it never passes: written together, then every failed one
    re-asked together once with its draft and its problems."""
    answers = ask_writer_for_briefs(chat, prompt, briefs, writing["settings"])
    checked: dict[str, dict[str, Any] | None] = {}
    to_fix = []
    for brief in briefs:
        scenario, problems = check_brief_answer(brief, answers.get(brief["slot"]), writing)
        checked[brief["slot"]] = scenario
        if scenario is None:
            fix: dict[str, Any] = {"problems_to_fix": problems[: c.AiLimits.REASK_MAX_PROBLEMS]}
            if brief["slot"] in answers:
                fix["previous_draft"] = answers[brief["slot"]]
            to_fix.append(brief | {"input": brief["input"] | fix})
    if to_fix:
        fixed = ask_writer_for_briefs(chat, prompt, to_fix, writing["settings"])
        for brief in to_fix:
            checked[brief["slot"]], _ = check_brief_answer(brief, fixed.get(brief["slot"]), writing)
    return checked


# ----------------------------------------------------------------------------- writing a set


def start_schedule(
    group_usage: dict[str, int], index: MitreIndex, settings: Settings, run_target: int
) -> dict[str, Any]:
    """The set's writing state. group_usage: the scenarios already written in this run that name each group, by
    MITRE group ID."""
    accepted_group_count: dict[str, int] = {}
    groups_used_in_other_scenarios = []
    for mitre_id, count in group_usage.items():
        group_id = index["group_by_mitre_id"].get(mitre_id)
        if group_id is None or count <= 0:
            continue
        accepted_group_count[group_id] = count
        groups_used_in_other_scenarios.append({"mitre_id": mitre_id, "name": index["objects"][group_id]["name"]})
    return {
        "running": {},
        "written": [],
        "failed_positions": [],
        "group_use_count": dict(accepted_group_count),  # accepted + taken paths' first candidate
        "accepted_group_count": accepted_group_count,  # accepted only: the share cap after writing
        "groups_used_in_other_scenarios": groups_used_in_other_scenarios,
        "groups_removed_over_share": 0,
        "most_scenarios_per_group": max(1, math.ceil(run_target * settings.max_scenario_share_per_group)),
    }


def rank_candidate_groups(
    planned_path: dict[str, Any],
    index: MitreIndex,
    selected_actors: dict[str, Any],
    schedule: dict[str, Any],
    settings: Settings,
) -> list[str]:
    """Every MITRE group documented for any path technique, ranked by relevance minus use, then use, then coverage.
    A group at its share is left out (strictly); only a path with no other documented group gets the least used."""
    group_use_count, most_per_group = schedule["group_use_count"], schedule["most_scenarios_per_group"]
    candidate_rows = []
    for actor_id, used_techniques in index["techniques_by_actor"].items():
        if index["objects"][actor_id]["type"] != "intrusion-set":
            continue
        covered = 0
        for technique_id in planned_path["technique_stix_ids"]:
            if technique_id in used_techniques:
                covered += 1
        if not covered:
            continue
        relevance = selected_actors[actor_id]["relevance"] if actor_id in selected_actors else 0
        uses = group_use_count.get(actor_id, 0)
        candidate_rows.append((-max(0, relevance - uses), uses, -covered, index["objects"][actor_id]["name"], actor_id))
    candidate_rows.sort()
    within_share = []
    for row in candidate_rows:
        if group_use_count.get(row[4], 0) < most_per_group:
            within_share.append(row)
    if not within_share and candidate_rows:
        least_used = candidate_rows[0]
        for row in candidate_rows:
            if (row[1], row[0]) < (least_used[1], least_used[0]):
                least_used = row
        within_share = [least_used]
    ranked_candidate_ids = []
    for row in within_share[: settings.candidate_groups_per_scenario]:
        ranked_candidate_ids.append(row[4])
    return ranked_candidate_ids


def replacement_group_under_share(
    scenario: dict[str, Any],
    sole_group_id: str,
    path_candidate_ids: list[str],
    schedule: dict[str, Any],
    index: MitreIndex,
    selected_actors: dict[str, Any],
) -> dict[str, Any] | None:
    """The best-ranked candidate of the path still under its share and documented for the scenario's techniques,
    as a relevant group; None when there is none."""
    technique_ids = []
    for technique in scenario["attack_techniques"]:
        technique_ids.append(technique["stix_id"])
    for candidate_id in path_candidate_ids:
        if candidate_id == sole_group_id:
            continue
        if schedule["accepted_group_count"].get(candidate_id, 0) >= schedule["most_scenarios_per_group"]:
            continue
        documented_techniques = documented_techniques_of_group(candidate_id, technique_ids, index)
        if not documented_techniques:
            continue
        quote = (selected_actors.get(candidate_id) or {}).get("evidence_quote")
        candidate = index["objects"][candidate_id]
        return {
            "name": candidate["name"],
            "mitre_id": get_mitre_id(candidate),
            "relevance": relevance_from_mitre(documented_techniques, quote),
            "evidence_type": evidence_type(documented_techniques),
            "documented_techniques": documented_techniques,
        }
    return None


def enforce_group_share_after_writing(
    scenario: dict[str, Any],
    path_candidate_ids: list[str],
    schedule: dict[str, Any],
    index: MitreIndex,
    selected_actors: dict[str, Any],
) -> dict[str, Any]:
    """The share cap on what was really written, in the order scenarios finish: a group at its share is removed
    while another verified group remains (the text never names groups); a sole group at its share is replaced by
    the best verified candidate under its share, and kept only when there is none."""
    accepted_group_count, most_per_group = schedule["accepted_group_count"], schedule["most_scenarios_per_group"]
    groups = scenario["relevant_groups"]
    kept_groups: list[dict[str, Any]] = []
    for position, group in enumerate(groups):
        group_id = index["group_by_mitre_id"][group["mitre_id"]]
        groups_still_to_check = len(groups) - position - 1
        if accepted_group_count.get(group_id, 0) >= most_per_group and (kept_groups or groups_still_to_check):
            schedule["groups_removed_over_share"] += 1
            continue
        kept_groups.append(group)
    sole_group_id = index["group_by_mitre_id"][kept_groups[0]["mitre_id"]]
    if len(kept_groups) == 1 and accepted_group_count.get(sole_group_id, 0) >= most_per_group:
        replacement = replacement_group_under_share(
            scenario, sole_group_id, path_candidate_ids, schedule, index, selected_actors
        )
        if replacement is not None:
            kept_groups = [replacement]
            schedule["groups_removed_over_share"] += 1
    return {**scenario, "relevant_groups": kept_groups}


def next_waiting_position(
    waiting: list[tuple[int, dict[str, Any]]],
    schedule: dict[str, Any],
    paths: list[dict[str, Any]],
    crossing_required: bool,
) -> int:
    """0, or, while a crossing path is required and none is taken or written, the first waiting crossing path."""
    if not crossing_required:
        return 0
    positions_taken = list(schedule["running"])  # the taken paths, by position
    for position, _ in schedule["written"]:
        positions_taken.append(position)
    for position in positions_taken:
        if paths[position]["has_it_and_ot"]:
            return 0
    for waiting_position, (_, waiting_path) in enumerate(waiting):
        if waiting_path["has_it_and_ot"]:
            return waiting_position
    return 0


def take_next_path(
    schedule: dict[str, Any],
    waiting: list[tuple[int, dict[str, Any]]],
    paths: list[dict[str, Any]],
    writing: dict[str, Any],
    crossing_required: bool,
) -> tuple[int, dict[str, Any], list[str]]:
    """The next waiting path with its candidate groups ranked now; its first candidate (the group the writer names
    first) counts as used until it is written, so the set's other paths prefer other groups."""
    index, settings, selected_actors = writing["index"], writing["settings"], writing["actor_selection"]["actors"]
    position, planned_path = waiting.pop(next_waiting_position(waiting, schedule, paths, crossing_required))
    ranked_candidate_ids = rank_candidate_groups(planned_path, index, selected_actors, schedule, settings)
    expected_groups = ranked_candidate_ids[:1]
    for group_id in expected_groups:
        schedule["group_use_count"][group_id] = schedule["group_use_count"].get(group_id, 0) + 1
    taken = {"expected_groups": expected_groups, "candidate_ids": ranked_candidate_ids}
    schedule["running"][position] = taken
    return position, planned_path, ranked_candidate_ids


def accept_written_path(
    schedule: dict[str, Any],
    position: int,
    scenario: dict[str, Any] | None,
    paths: list[dict[str, Any]],
    writing: dict[str, Any],
    save_card: Callable[[dict[str, Any], dict[str, Any]], None],
) -> None:
    """One written path: a dropped one is counted, a scenario is capped by group share, saved and counted."""
    index, selected_actors = writing["index"], writing["actor_selection"]["actors"]
    taken = schedule["running"].pop(position)
    for group_id in taken["expected_groups"]:  # the expectation is replaced by what was really named
        schedule["group_use_count"][group_id] -= 1
    if scenario is None:
        schedule["failed_positions"].append(position)
        return
    scenario = enforce_group_share_after_writing(scenario, taken["candidate_ids"], schedule, index, selected_actors)
    save_card(paths[position], scenario)
    schedule["written"].append((position, scenario))
    for group in scenario["relevant_groups"]:
        group_id = index["group_by_mitre_id"][group["mitre_id"]]
        schedule["accepted_group_count"][group_id] = schedule["accepted_group_count"].get(group_id, 0) + 1
        schedule["group_use_count"][group_id] = schedule["group_use_count"].get(group_id, 0) + 1
        named_group = {"mitre_id": group["mitre_id"], "name": group["name"]}
        if named_group not in schedule["groups_used_in_other_scenarios"]:
            schedule["groups_used_in_other_scenarios"].append(named_group)


def write_next_paths_together(
    chat: ChatModel,
    schedule: dict[str, Any],
    waiting: list[tuple[int, dict[str, Any]]],
    paths: list[dict[str, Any]],
    goal: int,
    save_card: Callable[[dict[str, Any], dict[str, Any]], None],
    writing: dict[str, Any],
    crossing_required: bool,
) -> None:
    """The next waiting paths still needed for goal, written together and each accepted."""
    taken_paths: list[tuple[int, dict[str, Any], list[str]]] = []
    while waiting and len(taken_paths) < goal - len(schedule["written"]):
        taken_paths.append(take_next_path(schedule, waiting, paths, writing, crossing_required))
    prompt, groups_used = writer_prompt(writing["settings"]), list(schedule["groups_used_in_other_scenarios"])
    briefs = []
    for taken in taken_paths:
        brief = build_path_brief(chat, prompt, taken, groups_used, writing)
        if brief is None:
            accept_written_path(schedule, taken[0], None, paths, writing, save_card)
        else:
            briefs.append(brief)
    checked = write_briefs(chat, prompt, briefs, writing) if briefs else {}
    for brief in briefs:
        accept_written_path(schedule, brief["position"], checked[brief["slot"]], paths, writing, save_card)


def write_scenario_set(
    chat: ChatModel,
    paths: list[dict[str, Any]],
    goal: int,
    group_usage: dict[str, int],
    save_card: Callable[[dict[str, Any], dict[str, Any]], None],
    *,
    run_target: int,
    crossing_required: bool,
    **writing: Any,
) -> dict[str, Any]:
    """The set written as the shared pipeline writes one: its goal paths in one writer call (more only above
    MITRE_WRITE_CALL_TOKENS_LIMIT), the failed ones re-asked together once; while fewer than goal pass, the next
    waiting paths are written the same way (a required crossing path first). `writing`: asset_context, index,
    settings, actor_selection, system_mitre_assets, threat_types. Groups capped at MAX_SCENARIO_SHARE_PER_GROUP
    of run_target; save_card(path, scenario) per kept one. {written: [(position, scenario)] in path order,
    failed_positions, groups_removed_over_share}."""
    schedule = start_schedule(group_usage, writing["index"], writing["settings"], run_target)
    waiting = list(enumerate(paths))
    while waiting and len(schedule["written"]) < goal:
        write_next_paths_together(chat, schedule, waiting, paths, goal, save_card, writing, crossing_required)
    schedule["written"].sort(key=written_position)
    return {
        "written": schedule["written"],
        "failed_positions": schedule["failed_positions"],
        "groups_removed_over_share": schedule["groups_removed_over_share"],
    }


def written_position(written: tuple[int, dict[str, Any]]) -> int:
    return written[0]
