"""Controls for a written ATT&CK set: code shortlists each scenario's, one AI call picks per sentence, code checks."""

from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field, replace
from typing import Any

import structlog

from app.ai import RerankModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.ai.chat import get_scenario_chat_model
from app.core import constants as c
from app.core import metrics
from app.core.asset_types import asset_type_fits, place_asset_types
from app.core.config import get_settings
from app.core.prompts import MITRE_PROMPTS, PROMPTS
from app.core.redaction import redact
from app.crud.attack import get_control_link_repository
from app.domain.scenario.write import (
    build_control_item,
    build_control_query,
    map_controls,
    read_control_search_settings,
    read_control_twin_key,
    split_sentences,
)
from app.domain.shared import names as name_forms
from app.domain.shared.ask_ai import ask_ai_and_check
from app.domain.shared.prompt_redaction import redacted
from app.schemas.library import LibraryControl
from app.schemas.scenario_internal import ControlQuery, FrozenContext
from app.search.snapshot import LibrarySnapshot

log = structlog.get_logger(__name__)
_SYSTEM_PROMPT: str = PROMPTS["controls"]["picks"]["text"]
_EFFECTS = frozenset(effect.value for effect in c.ControlEffect)
_PICK_FIELDS = ("sentence", "label", "effect")
_Fits = Callable[[LibraryControl], bool]


def is_attack_scenario(scenario: dict[str, Any]) -> bool:
    """Whether MITRE ATT&CK confirmed the scenario (POST /v1/create_session): its controls are picked."""
    return "attack" in (scenario.get("content") or {})


@dataclass(frozen=True)
class _Prepared:
    """What the whole set shares, read once: the library's rows and the prepared links of its mitigations."""

    by_id: dict[int, LibraryControl]
    twins: dict[str, list[LibraryControl]]  # the rows of one control text: its IT and its OT copy
    links: dict[str, list[dict[str, Any]]]  # a mitigation's ATT&CK ID -> its prepared links

    def list_linked_rows(self, mitigation_ids: Iterable[str]) -> list[LibraryControl]:
        """The library rows prepared for these mitigations, best reranked first."""
        linked = [link for mitigation in dict.fromkeys(mitigation_ids) for link in self.links.get(mitigation, [])]
        linked.sort(key=lambda link: (-link["rerank"], link["control_id"]))
        return [self.by_id[link["control_id"]] for link in linked if link["control_id"] in self.by_id]

    def find_fitting_row(self, control: LibraryControl, fits: _Fits) -> LibraryControl | None:
        """`control` when it fits, else its copy of another IT/OT type that does, else None."""
        return next((row for row in (control, *self.twins[read_control_twin_key(control)]) if fits(row)), None)

    def list_fitting_rows(self, controls: Iterable[LibraryControl], fits: _Fits) -> list[LibraryControl]:
        """Each control's fitting row, in order, one per control text."""
        unique: dict[str, LibraryControl] = {}
        for control in controls:
            row = self.find_fitting_row(control, fits)
            if row is not None:
                unique.setdefault(read_control_twin_key(row), row)
        return list(unique.values())


@dataclass(frozen=True)
class _Offer:
    """One scenario as the pick call reads it, and what code checks its picks against."""

    scenario: dict[str, Any]
    sentences: dict[str, str]  # S1 ... the statement's sentences, R1 ... the risk statement's
    places: dict[str, frozenset[str]]  # a sentence naming systems -> the AssetType values that fit them
    allowed: frozenset[str]  # the AssetType values that fit the scenario's systems
    query: ControlQuery  # the search's own query: whether the threat is about AI, and the search if picks fail
    controls: dict[str, LibraryControl] = field(default_factory=dict)  # C1 ...: one row per control text

    def is_offerable(self, control: LibraryControl) -> bool:
        """Whether the row may be offered: its IT/OT type fits, an AI-domain row only for an AI threat."""
        is_wanted_domain = self.query.is_about_ai or control.domain != c.Controls.AI_DOMAIN
        return is_wanted_domain and asset_type_fits(control.asset_type, self.allowed)

    def list_searched_texts(self) -> list[str]:
        """The texts searched by meaning: the risk statement, then each sentence of the statement."""
        prefix = c.ControlLinks.SCENARIO_SENTENCE_PREFIX
        told = [text for label, text in self.sentences.items() if label.startswith(prefix)]
        risk = self.scenario["content"].get("risk_statement") or ""
        return [redact(text) for text in (risk, *told) if text.strip()]


def pick_set_controls(
    rerank: RerankModel, scenarios: list[dict[str, Any]], context: FrozenContext, snapshot: LibrarySnapshot
) -> dict[str, dict[str, Any]]:
    """Each scenario's stored controls record by its id. A MITRE card's are chosen per technique among the controls
    linked to its MITRE mitigations (MITRE_CONTROLS_BY_TECHNIQUE, owner 2026-11-24); every other card's per
    sentence, and one of those whose picks cannot be read is mapped by the search."""
    by_technique: list[dict[str, Any]] = []
    by_sentence: list[dict[str, Any]] = []
    for scenario in scenarios:
        if "mitre" in scenario["content"] and get_settings().mitre_controls_by_technique:
            by_technique.append(scenario)
        else:
            by_sentence.append(scenario)
    records = _pick_controls_per_sentence(rerank, by_sentence, context, snapshot)
    records |= _pick_controls_per_technique(rerank, by_technique, context, snapshot)
    return records


def _pick_controls_per_sentence(
    rerank: RerankModel, scenarios: list[dict[str, Any]], context: FrozenContext, snapshot: LibrarySnapshot
) -> dict[str, dict[str, Any]]:
    """Each scenario's stored controls record by its id; one whose picks cannot be read is mapped by the search."""
    if not scenarios:
        return {}
    prepared = _read_prepared_links(scenarios, snapshot)
    offers = _offer_controls(scenarios, context, snapshot, prepared)
    try:
        answers, error_type = _ask_for_picks(offers), None
    except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
        answers, error_type = {}, type(exc).__name__
    settings, searched = get_settings(), read_control_search_settings(snapshot)
    made_with = {
        "chat_model": settings.chat_of(c.ChatModule.SCENARIO).model,
        "embedding_model": searched["embedding_model"],
        "library": searched["library"],
        "max_controls": settings.max_controls,
    }
    records = {
        offer.scenario["_id"]: _build_picked_record(offer, answers[slot], prepared, made_with)
        for slot, offer in offers.items()
        if slot in answers
    }
    log.info(c.LogEvent.CONTROLS_PICKED, count=len(records), controls=sum(len(r["items"]) for r in records.values()))
    unread = [offer for slot, offer in offers.items() if slot not in answers]
    if unread:
        log.warning(c.LogEvent.CONTROLS_PICK_UNUSABLE, count=len(unread), error_type=error_type)
        snapshot.embed_control_queries([offer.query.text for offer in unread])
    for offer in unread:
        found = map_controls(rerank, offer.scenario, context, snapshot, offer.query)
        records[offer.scenario["_id"]] = found | {"picks": [], "dropped": [], "technique_states": []}
    return records


def _read_prepared_links(scenarios: list[dict[str, Any]], snapshot: LibrarySnapshot) -> _Prepared:
    """Read, in one read for the set, the prepared links of every mitigation of its scenarios."""
    wanted = {mitigation for scenario in scenarios for mitigation in _list_mitigations(scenario)}
    links = get_control_link_repository().find_links(wanted)
    controls = snapshot.library.control_library
    twins: dict[str, list[LibraryControl]] = {}
    for control in controls:
        twins.setdefault(read_control_twin_key(control), []).append(control)
    return _Prepared({control.control_id: control for control in controls}, twins, links)


def _list_mitigations(scenario: dict[str, Any]) -> list[str]:
    """The scenario's mitigations by ATT&CK ID: those it names, then those ATT&CK records for its techniques."""
    card = scenario["content"]["attack"]
    named = [mitigation["id"] for mitigation in card["mitigations"]]
    return [*named, *(recorded for technique in card["techniques"] for recorded in technique["mitigations"])]


def _offer_controls(
    scenarios: list[dict[str, Any]], context: FrozenContext, snapshot: LibrarySnapshot, prepared: _Prepared
) -> dict[str, _Offer]:
    """Each scenario's offer by its slot (SC1 ...): every text of the set is searched in one embedding call."""
    offers = [_read_scenario(scenario, context) for scenario in scenarios]
    searched = [offer.list_searched_texts() for offer in offers]
    # ponytail: one search over every type of control, then code keeps the fitting of each text's
    # ControlLinks.SHORTLIST nearest; a mask per scenario needs per-query scopes in find_controls.
    found = iter(snapshot.find_controls([text for texts in searched for text in texts], c.ControlLinks.SHORTLIST))
    by_slot: dict[str, _Offer] = {}
    for number, (offer, texts) in enumerate(zip(offers, searched, strict=True), 1):
        nearest = [[control for control, _ in next(found)] for _ in texts]
        shortlist = _shortlist_controls(offer, prepared, nearest)
        labelled = {f"{c.ControlLinks.LABEL_PREFIX}{place}": row for place, row in enumerate(shortlist, 1)}
        by_slot[f"SC{number}"] = replace(offer, controls=labelled)
    return by_slot


def _read_scenario(scenario: dict[str, Any], context: FrozenContext) -> _Offer:
    """The scenario's numbered sentences, the IT/OT types that fit its systems, and each sentence's own."""
    content, asset_type = scenario["content"], context.asset.get("category_code")
    systems = context.find_systems(system["id"] for system in content.get("systems") or [])
    sentences: dict[str, str] = {}
    for prefix, text in (
        (c.ControlLinks.SCENARIO_SENTENCE_PREFIX, content.get("statement")),
        (c.ControlLinks.RISK_SENTENCE_PREFIX, content.get("risk_statement")),
    ):
        sentences |= {f"{prefix}{number}": part for number, part in enumerate(split_sentences(text or ""), 1)}
    places: dict[str, frozenset[str]] = {}
    for label, text in sentences.items():
        named = [system for system in systems if name_forms.find_name_mentions(system["name"], text)]
        if named:
            places[label] = place_asset_types(asset_type, (system.get("category_code") for system in named))
    allowed = place_asset_types(asset_type, (system.get("category_code") for system in systems))
    return _Offer(scenario, sentences, places, allowed, build_control_query(content, context))


def _shortlist_controls(
    offer: _Offer, prepared: _Prepared, nearest: list[list[LibraryControl]]
) -> list[LibraryControl]:
    """Up to ControlLinks.SHORTLIST fitting rows: its mitigations' links, then each text's nearest in turn."""
    fits = offer.is_offerable
    linked = prepared.list_fitting_rows(prepared.list_linked_rows(_list_mitigations(offer.scenario)), fits)
    chosen = {read_control_twin_key(row): row for row in linked[: c.ControlLinks.SHORTLIST]}

    def take_next(rows: Iterator[LibraryControl]) -> bool:
        for row in rows:
            if read_control_twin_key(row) not in chosen:
                chosen[read_control_twin_key(row)] = row
                return True
        return False

    turns = [iter(prepared.list_fitting_rows(found, fits)[: c.ControlLinks.MEANING_HITS]) for found in nearest]
    while turns and len(chosen) < c.ControlLinks.SHORTLIST:
        turns = [rows for rows in turns if len(chosen) < c.ControlLinks.SHORTLIST and take_next(rows)]
    return list(chosen.values())


def _ask_for_picks(offers: dict[str, _Offer]) -> dict[str, list[Any]]:
    """Each slot's picks in one AI call; a slot left out is asked for again once, the others keep theirs."""
    asked = [
        {
            "slot": slot,
            "SENTENCES": offer.sentences,
            "CONTROLS": [
                {
                    "label": label,
                    "name": control.name,
                    "description": (control.description or "")[: c.ControlLinks.CARD_TEXT_CHARS],
                }
                for label, control in offer.controls.items()
            ],
        }
        for slot, offer in offers.items()
    ]
    return _ask_slots(_SYSTEM_PROMPT, asked, list(offers))


def _ask_slots(system_prompt: str, asked: list[dict[str, Any]], slots: list[str]) -> dict[str, list[Any]]:
    """Each slot's picks in one AI call; a slot left out is asked for again once, the others keep theirs."""
    first: dict[str, list[Any]] = {}  # the first answer's picks: a re-ask may answer only the slots left out

    def list_slots_left_out(answer: dict[str, Any]) -> list[str]:
        first.update(_read_picks(answer)[0])
        return [f"slot {slot}: {c.AttackMessage.SLOT_MISSING}" for slot in slots if slot not in first]

    prompt = (system_prompt, f"SCENARIOS:\n{name_forms.as_json(redacted(asked))}")
    kept: dict[str, list[Any]] = ask_ai_and_check(
        get_scenario_chat_model(), c.AiTask.PICK_CONTROLS, prompt, _read_picks, list_slots_left_out
    )
    picks = kept | first  # a slot the first answer held keeps its picks: the re-ask is for the slots left out
    return {slot: picks[slot] for slot in slots if slot in picks}


def _read_picks(answer: dict[str, Any]) -> tuple[dict[str, list[Any]], list[str]]:
    """Each answered slot's picks, and the answer's problem when it is not in the shape asked."""
    items = answer.get("scenarios")
    if not isinstance(items, list) or not all(
        isinstance(item, dict) and isinstance(item.get("picks", []), list) for item in items
    ):
        return {}, [c.ControlPickMessage.SCENARIOS_NOT_A_LIST.value]
    return {str(item.get("slot")): item.get("picks", []) for item in items}, []


def _build_picked_record(
    offer: _Offer, picks: list[Any], prepared: _Prepared, made_with: dict[str, Any]
) -> dict[str, Any]:
    """One scenario's stored controls record: its kept picks as items, risk-sentence picks first, none padded."""
    kept, dropped = _check_picks(offer, picks, prepared)
    for drop in dropped:
        log.info(c.LogEvent.CONTROLS_PICK_DROPPED, scenario_id=offer.scenario["_id"], message=drop["reason"])
    risk = c.ControlLinks.RISK_SENTENCE_PREFIX
    ordered = sorted(kept, key=lambda pick: (not pick["sentence"].startswith(risk), int(pick["sentence"][1:])))
    shown = ordered[: made_with["max_controls"]]
    items = [
        build_control_item(
            prepared.by_id[pick["control_id"]],
            rank,
            None,
            c.ControlMatch.EXACT,
            c.ControlPickMessage.PICKED_REASON.format(effect=pick["effect"], sentence=pick["text"]),
        )
        for rank, pick in enumerate(shown, 1)
    ]
    return {
        "items": items,
        "query": None,  # no single query was searched: a plan searches its alternatives afresh
        "shortlist": [{"control_id": control.control_id, "score": None} for control in offer.controls.values()],
        "made_with": made_with | {"ai_controls": offer.query.is_about_ai},
        "picks": kept,
        "dropped": dropped,
        "technique_states": _list_technique_states(offer, shown, prepared),  # a pick cut by the limit matches none
    }


def _check_picks(
    offer: _Offer, picks: list[Any], prepared: _Prepared
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The picks kept and the ones dropped with the reason, in the answer's order."""
    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    used: Counter[str] = Counter()  # the picks kept on each label and on each sentence
    for given in picks:
        answered = given if isinstance(given, dict) else {}
        sentence, label, effect = (
            answered.get(key) if isinstance(answered.get(key), str) else None for key in _PICK_FIELDS
        )
        listed, place = offer.controls.get(label or ""), offer.places.get(sentence or "")
        control = listed
        if listed is not None and place is not None:  # its copy of the type the sentence's systems take
            control = prepared.find_fitting_row(listed, replace(offer, allowed=place).is_offerable)
        reason = _find_drop_reason(offer, (sentence, label, effect), listed, control, used)
        if reason is not None or control is None or sentence is None or label is None:
            dropped.append({"sentence": sentence, "label": label, "effect": effect, "reason": reason})
            continue
        used.update((label, sentence))
        kept.append(
            {
                "sentence": sentence,
                "text": offer.sentences[sentence],
                "control_id": control.control_id,
                "code": control.code,
                "name": control.name,
                "effect": effect,
            }
        )
    return kept, dropped


def _find_drop_reason(
    offer: _Offer,
    pick: tuple[str | None, str | None, str | None],
    listed: LibraryControl | None,
    fitting: LibraryControl | None,
    used: Counter[str],
) -> str | None:
    """Why code drops a pick (a ControlPickDrop's text), or None when it is kept."""
    sentence, label, effect = pick
    if sentence not in offer.sentences:
        return c.ControlPickDrop.NO_SENTENCE.value
    if listed is None:
        return c.ControlPickDrop.NOT_LISTED.value
    if effect not in _EFFECTS:
        return c.ControlPickDrop.BAD_EFFECT.value
    if fitting is None:
        return c.ControlPickDrop.WRONG_TYPE.value
    if used[label or ""]:
        return c.ControlPickDrop.TWICE.value
    if used[sentence or ""] >= c.ControlLinks.PER_SENTENCE:
        return c.ControlPickDrop.TOO_MANY.format(most=c.ControlLinks.PER_SENTENCE)
    return None


def _list_technique_states(offer: _Offer, shown: list[dict[str, Any]], prepared: _Prepared) -> list[dict[str, str]]:
    """What the picks shown as items gave each technique of the scenario: a gap is named, never filled."""
    picked = {read_control_twin_key(prepared.by_id[pick["control_id"]]) for pick in shown}
    offered = {read_control_twin_key(row) for row in offer.controls.values()}
    states = []
    for technique in offer.scenario["content"]["attack"]["techniques"]:
        mitigations = technique["mitigations"]
        linked = prepared.list_linked_rows(mitigations)
        fitting = {read_control_twin_key(row) for row in prepared.list_fitting_rows(linked, offer.is_offerable)}
        typed = prepared.list_fitting_rows(linked, lambda row: asset_type_fits(row.asset_type, offer.allowed))
        if fitting & picked:
            state = c.TechniqueControlState.MATCHED
        elif not mitigations:
            state = c.TechniqueControlState.NO_KNOWN_DEFENCE
        elif not linked and not all(mitigation in prepared.links for mitigation in mitigations):
            state = c.TechniqueControlState.NOT_PREPARED
        elif not linked:
            state = c.TechniqueControlState.NO_LIBRARY_CONTROL
        elif not typed:
            state = c.TechniqueControlState.TYPE_MISMATCH
        elif not fitting & offered:
            state = c.TechniqueControlState.NOT_OFFERED
        else:
            state = c.TechniqueControlState.NOT_PICKED
        states.append({"id": technique["id"], "state": state.value})
    return states


# ----------------------------------------------------------------------------- a MITRE card's controls, per technique


@dataclass(frozen=True)
class _TechniqueChoice:
    """One MITRE card as the per-technique pick reads it: each technique's candidate controls (the library rows
    linked to its MITRE mitigations, best link first, of an IT/OT type its systems take) and what code checks."""

    scenario: dict[str, Any]
    technique_names: dict[str, str]  # technique ID -> its name, in the path's order
    controls: dict[str, LibraryControl]  # C1 ...: every candidate row of the card, labelled once
    candidates: dict[str, list[str]]  # technique ID -> its candidate labels, best link first
    # (technique ID, label) -> (its mitigation's ID, the mitigation as its reason names it, the link's effect)
    carried_out: dict[tuple[str, str], tuple[str, str, str]]
    mitigations: dict[str, list[dict[str, str]]]  # technique ID -> its linked mitigations: id, name, MITRE's words
    inherited: dict[str, str]  # technique ID -> the parent technique whose mitigations it carries (MITRE has none)


def _pick_controls_per_technique(
    rerank: RerankModel, scenarios: list[dict[str, Any]], context: FrozenContext, snapshot: LibrarySnapshot
) -> dict[str, dict[str, Any]]:
    """Each MITRE card's stored controls record by its id: the AI chooses, in one call for the set, among each
    technique's own linked controls; a technique left without an exact pick (none fitted, or the answer could not
    be read) shows its best MITRE link as NEAREST, and a card short of MIN_CONTROLS is topped up by the search."""
    if not scenarios:
        return {}
    prepared = _read_prepared_links(scenarios, snapshot)
    choices: dict[str, _TechniqueChoice] = {}
    for number, scenario in enumerate(scenarios, 1):
        choices[f"SC{number}"] = _build_technique_choice(scenario, context, prepared)
    answers = _ask_technique_picks(choices)
    made_with = _technique_made_with(snapshot)
    records: dict[str, dict[str, Any]] = {}
    for slot, choice in choices.items():
        kept: list[dict[str, Any]] = []  # the answer could not be read: every technique gets its nearest link
        dropped: list[dict[str, Any]] = []
        picked_with = made_with | {"picked_by": c.ControlLinks.PICKED_BY_LINK}
        if slot in answers:
            (kept, dropped), picked_with = _check_technique_picks(choice, answers[slot]), made_with
        picks = kept + _nearest_for_unpicked(choice, kept)
        records[choice.scenario["_id"]] = _build_technique_record(choice, picks, dropped, prepared, picked_with)
    _top_up_by_search(rerank, scenarios, records, (context, snapshot, prepared))
    count = sum(len(record["items"]) for record in records.values())
    log.info(c.LogEvent.CONTROLS_PICKED_BY_TECHNIQUE, count=len(records), controls=count)
    return records


def _technique_made_with(snapshot: LibrarySnapshot) -> dict[str, Any]:
    settings, searched = get_settings(), read_control_search_settings(snapshot)
    return {
        "chat_model": settings.chat_of(c.ChatModule.SCENARIO).model,
        "library": searched["library"],
        "max_controls": settings.max_controls,
        "picked_by": c.ControlLinks.PICKED_BY_TECHNIQUE,
    }


def _build_technique_choice(scenario: dict[str, Any], context: FrozenContext, prepared: _Prepared) -> _TechniqueChoice:
    """The card's techniques with their candidates: at most CONTROLS_PER_TECHNIQUE_CANDIDATES each."""
    content, most = scenario["content"], get_settings().controls_per_technique_candidates
    mitigation_names, about_ai = _name_mitigations(content), build_control_query(content, context).is_about_ai
    mitre_words = _read_mitigation_texts(content)
    choice = _TechniqueChoice(scenario, {}, {}, {}, {}, {}, {})
    label_of: dict[int, str] = {}  # a library row -> its label: a row linked to two techniques is labelled once
    for technique in content["attack"]["techniques"]:
        technique_id, parent = technique["id"], technique.get("mitigations_from")
        choice.technique_names[technique_id] = technique["name"]
        if parent:  # MITRE lists none of its own: its parent technique's
            choice.inherited[technique_id] = parent
        labels: list[str] = []
        fits = _fits_technique_systems(content, context, technique_id, about_ai)
        for row, mitigation, effect in _list_linked_controls(technique, prepared, fits)[:most]:
            if row.control_id not in label_of:
                label_of[row.control_id] = f"{c.ControlLinks.LABEL_PREFIX}{len(label_of) + 1}"
                choice.controls[label_of[row.control_id]] = row
            label = label_of[row.control_id]
            labels.append(label)
            name = mitigation_names.get(mitigation, "")
            named = f"{mitigation} {name}".strip() + (f", for parent {parent}" if parent else "")
            choice.carried_out[(technique_id, label)] = (mitigation, named, effect)
            listed = choice.mitigations.setdefault(technique_id, [])
            if all(known["id"] != mitigation for known in listed):
                words = mitre_words.get((technique_id, mitigation))  # none on a card stored before 2026-11-24
                listed.append({"id": mitigation, "name": name} | ({"mitre_says": words} if words else {}))
        choice.candidates[technique_id] = labels
    return choice


def _name_mitigations(content: dict[str, Any]) -> dict[str, str]:
    """Each MITRE mitigation's name by its ID, from the card's own MITRE record."""
    names = {mitigation["id"]: mitigation["name"] for mitigation in content["attack"].get("mitigations") or []}
    for technique in (content.get("mitre") or {}).get("mitigations") or []:
        for mitigation in technique.get("mitigations") or []:
            names.setdefault(mitigation["mitre_id"], mitigation["name"])
    return names


def _read_mitigation_texts(content: dict[str, Any]) -> dict[tuple[str, str], str]:
    """MITRE's own words on how each mitigation defends each technique of the card, by (technique, mitigation);
    a card stored before they were kept (2026-11-24) has none."""
    texts = {}
    for technique in (content.get("mitre") or {}).get("mitigations") or []:
        for mitigation in technique.get("mitigations") or []:
            texts[(technique["technique"], mitigation["mitre_id"])] = mitigation.get("text") or ""
    return texts


def _fits_technique_systems(
    content: dict[str, Any], context: FrozenContext, technique_id: str, about_ai: bool
) -> _Fits:
    """Whether a library row may defend this technique: its IT/OT type fits the systems the technique acts on (the
    card's MITRE systems_targeted for it, else every system of the card), and an AI-domain row only for an AI
    threat."""
    card_systems = context.find_systems(system["id"] for system in content.get("systems") or [])
    targeted = set()
    for target in (content.get("mitre") or {}).get("systems_targeted") or []:
        if target.get("technique") == technique_id:
            targeted.add(target.get("supporting_system"))
    acted_on = [system for system in card_systems if system["name"] in targeted] or card_systems
    codes = [system.get("category_code") for system in acted_on]
    allowed = place_asset_types(context.asset.get("category_code"), codes)

    def fits(control: LibraryControl) -> bool:
        is_wanted_domain = about_ai or control.domain != c.Controls.AI_DOMAIN
        return is_wanted_domain and asset_type_fits(control.asset_type, allowed)

    return fits


def _list_linked_controls(
    technique: dict[str, Any], prepared: _Prepared, fits: _Fits
) -> list[tuple[LibraryControl, str, str]]:
    """(fitting library row, its MITRE mitigation, the link's effect) for the technique's defending mitigations,
    best reranked link first, one row per control text."""
    links = []
    for mitigation in technique["mitigations"]:
        if mitigation in c.ControlLinks.NOT_MITIGATIONS:  # "limited or not effective", "pre-compromise": no defence
            continue
        for link in prepared.links.get(mitigation, []):
            links.append((-link["rerank"], link["control_id"], mitigation, link["effect"]))
    links.sort()
    found: list[tuple[LibraryControl, str, str]] = []
    texts: set[str] = set()
    for _, control_id, mitigation, effect in links:
        listed = prepared.by_id.get(control_id)
        row = prepared.find_fitting_row(listed, fits) if listed is not None else None
        if row is not None and read_control_twin_key(row) not in texts:
            texts.add(read_control_twin_key(row))
            found.append((row, mitigation, effect))
    return found


def _ask_technique_picks(choices: dict[str, _TechniqueChoice]) -> dict[str, list[Any]]:
    """Each slot's picks in one AI call; a card without candidates is not asked (it has nothing to choose). A slot
    missing from the result had an unreadable answer."""
    answers: dict[str, list[Any]] = {}
    asked = []
    for slot, choice in choices.items():
        described = _describe_technique_choice(slot, choice)
        if described["TECHNIQUES"]:
            asked.append(described)
        else:
            answers[slot] = []
    if not asked:
        return answers
    per_technique = str(get_settings().controls_per_technique)
    prompt = str(MITRE_PROMPTS["controls"]["text"]).replace("<per_technique>", per_technique)
    try:
        answers |= _ask_slots(prompt, asked, [item["slot"] for item in asked])
    except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
        log.warning(c.LogEvent.CONTROLS_LINK_FALLBACK, count=len(asked), error_type=type(exc).__name__)
    return answers


def _describe_technique_choice(slot: str, choice: _TechniqueChoice) -> dict[str, Any]:
    """One slot of the pick call: the scenario's text, and each technique that has candidates, with its MITRE
    mitigations in MITRE's own words and the controls linked to them."""
    techniques = []
    for technique_id, labels in choice.candidates.items():
        if not labels:
            continue
        controls = []
        for label in labels:
            control = choice.controls[label]
            controls.append(
                {
                    "label": label,
                    "name": control.name,
                    "description": (control.description or "")[: c.ControlLinks.CARD_TEXT_CHARS],
                    "mitigation": choice.carried_out[(technique_id, label)][0],
                }
            )
        technique = {"id": technique_id, "name": choice.technique_names[technique_id]}
        if technique_id in choice.inherited:
            technique["mitigations_of_parent"] = choice.inherited[technique_id]
        techniques.append(technique | {"MITIGATIONS": choice.mitigations[technique_id], "CONTROLS": controls})
    return {"slot": slot, "SCENARIO": choice.scenario["content"].get("statement") or "", "TECHNIQUES": techniques}


def _check_technique_picks(
    choice: _TechniqueChoice, picks: list[Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The picks kept and the ones dropped with the reason, in the answer's order."""
    most = get_settings().controls_per_technique
    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    used: Counter[str] = Counter()  # picks kept per technique, and per "technique label"
    for given in picks:
        answered = given if isinstance(given, dict) else {}
        technique, label, effect = (
            answered.get(key) if isinstance(answered.get(key), str) else None
            for key in ("technique", "label", "effect")
        )
        reason = _find_technique_drop_reason(choice, (technique, label, effect), used, most)
        if reason is not None or technique is None or label is None or effect is None:
            dropped.append({"technique": technique, "label": label, "effect": effect, "reason": reason})
            log.info(c.LogEvent.CONTROLS_PICK_DROPPED, scenario_id=choice.scenario["_id"], message=reason)
            continue
        used.update((technique, f"{technique} {label}"))
        kept.append(_kept_technique_pick(choice, technique, label, effect))
    return kept, dropped


def _find_technique_drop_reason(
    choice: _TechniqueChoice, pick: tuple[str | None, str | None, str | None], used: Counter[str], most: int
) -> str | None:
    """Why code drops a per-technique pick (a ControlPickDrop's text), or None when it is kept."""
    technique, label, effect = pick
    labels = choice.candidates.get(technique or "") or []
    if not labels:
        return c.ControlPickDrop.NO_TECHNIQUE.value
    if label not in labels:
        return c.ControlPickDrop.NOT_THIS_TECHNIQUE.value
    if effect not in _EFFECTS:
        return c.ControlPickDrop.BAD_EFFECT.value
    if used[f"{technique} {label}"]:
        return c.ControlPickDrop.TWICE_FOR_TECHNIQUE.value
    if used[technique or ""] >= most:
        return c.ControlPickDrop.TOO_MANY_FOR_TECHNIQUE.format(most=most)
    return None


def _kept_technique_pick(choice: _TechniqueChoice, technique: str, label: str, effect: str) -> dict[str, Any]:
    """A kept pick; an effect its control's library domain cannot have is set to one it can, and noted."""
    control = choice.controls[label]
    pick = {
        "technique": technique,
        "technique_name": choice.technique_names[technique],
        "mitigation": choice.carried_out[(technique, label)][1],
        "control_id": control.control_id,
        "code": control.code,
        "name": control.name,
        "effect": effect,
    }
    possible = c.ControlLinks.EFFECTS_BY_DOMAIN.get(control.domain or "")
    if possible and effect not in possible:
        pick |= {"effect": possible[0], "effect_corrected_from": effect}
        log.info(c.LogEvent.CONTROLS_EFFECT_CORRECTED, code=control.code, given=effect, kept=possible[0])
        metrics.CONTROL_PICKS.labels(c.ControlLinks.EFFECT_CORRECTED).inc()
    return pick


def _nearest_for_unpicked(choice: _TechniqueChoice, kept: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Each technique with linked candidates but no exact pick (none fitted, or the AI's answer could not be read)
    gets its best MITRE link, with the link's own effect, as a nearest pick (owner 2026-11-24: a step is never left
    without a control while one is linked to its mitigations)."""
    picked = {pick["technique"] for pick in kept}
    nearest = []
    for technique, labels in choice.candidates.items():
        if labels and technique not in picked:
            effect = choice.carried_out[(technique, labels[0])][2]
            nearest.append(_kept_technique_pick(choice, technique, labels[0], effect) | {"nearest": True})
    metrics.CONTROL_PICKS.labels(c.ControlLinks.PICKED_BY_LINK).inc(len(nearest))
    return nearest


def _order_by_technique(choice: _TechniqueChoice, kept: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The kept picks in the path's technique order, each technique's in the answer's order."""
    ordered = []
    for technique in choice.technique_names:
        for pick in kept:
            if pick["technique"] == technique:
                ordered.append(pick)
    return ordered


def _group_picks_by_control(
    choice: _TechniqueChoice, picks: list[dict[str, Any]], prepared: _Prepared
) -> tuple[dict[str, LibraryControl], dict[str, list[str]], dict[str, set[tuple[str, bool]]]]:
    """Per control text, in the path's technique order: its row (an exact pick's first, else the first nearest
    pick's: the IT/OT copy an exact pick fitted wins), its reasons (one per technique it defends, naming the MITRE
    mitigation) and the techniques it defends, each with whether as a nearest pick."""
    rows: dict[str, LibraryControl] = {}
    reasons: dict[str, list[str]] = {}
    defends: dict[str, set[tuple[str, bool]]] = {}
    for pick in _order_by_technique(choice, picks):
        row = prepared.by_id[pick["control_id"]]
        text = read_control_twin_key(row)
        if text not in rows or (not pick.get("nearest") and all(nearest for _, nearest in defends[text])):
            rows[text] = row
        reason = c.ControlPickMessage.TECHNIQUE_REASON.format(
            effect=pick["effect"],
            technique=pick["technique"],
            technique_name=pick["technique_name"],
            mitigation=pick["mitigation"],
        )
        if pick.get("nearest"):
            reason = c.ControlPickMessage.LINK_SCORE_REASON.format(reason=reason)
        reasons.setdefault(text, []).append(reason)
        defends.setdefault(text, set()).add((pick["technique"], bool(pick.get("nearest"))))
    return rows, reasons, defends


def _build_technique_record(
    choice: _TechniqueChoice,
    picks: list[dict[str, Any]],
    dropped: list[dict[str, Any]],
    prepared: _Prepared,
    made_with: dict[str, Any],
) -> dict[str, Any]:
    """One card's stored controls record: one item per control text, the exact picks first, then the nearest (a cut
    at MAX_CONTROLS drops a nearest one first), each in the path's technique order, its reason naming every
    technique it defends and the MITRE mitigation it carries out. A control picked exactly for any technique is
    EXACT."""
    rows, reasons, defends = _group_picks_by_control(choice, picks, prepared)
    exact = [text for text in rows if any(not nearest for _, nearest in defends[text])]
    shown = [*exact, *(text for text in rows if text not in exact)][: made_with["max_controls"]]
    items = []
    defended: set[tuple[str, bool]] = set()
    for rank, text in enumerate(shown, 1):
        match = c.ControlMatch.EXACT if text in exact else c.ControlMatch.NEAREST
        items.append(build_control_item(rows[text], rank, None, match, "; ".join(reasons[text])))
        defended |= defends[text]
    if made_with["picked_by"] == c.ControlLinks.PICKED_BY_TECHNIQUE:
        metrics.CONTROL_PICKS.labels(c.ControlLinks.PICKS_KEPT).inc(sum(not pick.get("nearest") for pick in picks))
        metrics.CONTROL_PICKS.labels(c.ControlLinks.PICKS_DROPPED).inc(len(dropped))
    return {
        "items": items,
        "query": None,
        "shortlist": [{"control_id": control.control_id, "score": None} for control in choice.controls.values()],
        "made_with": made_with,
        "picks": picks,
        "dropped": dropped,
        "technique_states": _list_states_per_technique(choice, defended, prepared),
    }


def _top_up_by_search(
    rerank: RerankModel,
    scenarios: list[dict[str, Any]],
    records: dict[str, dict[str, Any]],
    searched_in: tuple[FrozenContext, LibrarySnapshot, _Prepared],
) -> None:
    """A card with fewer than MIN_CONTROLS (its techniques' MITRE links gave too few) is topped up to it with the
    library search's nearest controls, marked NEAREST (owner 2026-11-24: a card never shows no control). Their
    queries are embedded in one call."""
    context, snapshot, prepared = searched_in
    least = get_settings().min_controls
    short = [scenario for scenario in scenarios if len(records[scenario["_id"]]["items"]) < least]
    if not short:
        return
    queries = {scenario["_id"]: build_control_query(scenario["content"], context) for scenario in short}
    snapshot.embed_control_queries([query.text for query in queries.values()])
    for scenario in short:
        record = records[scenario["_id"]]
        found = map_controls(rerank, scenario, context, snapshot, queries[scenario["_id"]])
        shown = {read_control_twin_key(prepared.by_id[item["control_id"]]) for item in record["items"]}
        for item in found["items"]:
            text = read_control_twin_key(prepared.by_id[item["control_id"]])
            if len(record["items"]) < least and text not in shown:
                shown.add(text)
                reason = c.ControlPickMessage.SEARCH_TOP_UP_REASON.format(reason=item["rationale"])
                row, rank = prepared.by_id[item["control_id"]], len(record["items"]) + 1
                record["items"].append(build_control_item(row, rank, item["score"], c.ControlMatch.NEAREST, reason))
        record["query"] = found["query"]
        log.info(c.LogEvent.CONTROLS_TOPPED_UP_BY_SEARCH, scenario_id=scenario["_id"], controls=len(record["items"]))


def _list_states_per_technique(
    choice: _TechniqueChoice, defended: set[tuple[str, bool]], prepared: _Prepared
) -> list[dict[str, str]]:
    """What each technique got: an exact control, its nearest MITRE link, or why none was."""
    states = []
    for technique in choice.scenario["content"]["attack"]["techniques"]:
        defending = [
            mitigation for mitigation in technique["mitigations"] if mitigation not in c.ControlLinks.NOT_MITIGATIONS
        ]
        if (technique["id"], False) in defended:
            state = c.TechniqueControlState.MATCHED
        elif (technique["id"], True) in defended:
            state = c.TechniqueControlState.NEAREST
        elif not defending:
            state = c.TechniqueControlState.NO_KNOWN_DEFENCE
        elif not prepared.list_linked_rows(defending):
            every_prepared = all(mitigation in prepared.links for mitigation in defending)
            state = (
                c.TechniqueControlState.NO_LIBRARY_CONTROL if every_prepared else c.TechniqueControlState.NOT_PREPARED
            )
        elif not choice.candidates.get(technique["id"]):
            state = c.TechniqueControlState.TYPE_MISMATCH
        else:
            state = c.TechniqueControlState.NOT_PICKED
        states.append({"id": technique["id"], "state": state.value})
    return states
