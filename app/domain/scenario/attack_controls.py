"""Controls for a written ATT&CK set: code shortlists each scenario's, one AI call picks per sentence, code checks."""

from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field, replace
from itertools import chain
from typing import Any

import structlog

from app.ai import RerankModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.ai.chat import get_scenario_chat_model
from app.core import constants as c
from app.core.asset_types import asset_type_fits, place_asset_types
from app.core.config import get_settings
from app.core.prompts import PROMPTS
from app.core.redaction import redact
from app.crud.attack import get_attack_repository, get_control_link_repository
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
from app.search.mitre.mitre_index import opening_sentences
from app.search.snapshot import LibrarySnapshot

log = structlog.get_logger(__name__)
_SYSTEM_PROMPT: str = PROMPTS["controls"]["picks"]["text"]
_EFFECTS = frozenset(effect.value for effect in c.ControlEffect)
_PICK_FIELDS = ("sentence", "label", "effect")
_Fits = Callable[[LibraryControl], bool]


def is_attack_scenario(scenario: dict[str, Any]) -> bool:
    """Whether MITRE ATT&CK confirmed the scenario (POST /v1/create_session): its controls are picked."""
    return "attack" in (scenario.get("content") or {})


def is_mitre_card(scenario: dict[str, Any]) -> bool:
    """Whether a MITRE run wrote the card: its remediation plan identifies its controls (owner 2026-11-27). Never
    is_attack_scenario, which a POST /v1/create_session card is too."""
    return "mitre" in (scenario.get("content") or {})


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
    """Each scenario's stored controls record by its id, picked per sentence; one whose picks cannot be read is
    mapped by the search. A MITRE card is never claimed for this (owner 2026-11-27): its plan identifies its
    controls (gather_plan_candidates)."""
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


# ----------------------------------------------------------------------------- a MITRE card's steps, as its plan reads


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
    """Whether a library row may defend this technique: its IT/OT type fits the systems the technique acts on, and
    an AI-domain row only for an AI threat."""
    codes = [system.get("category_code") for system in _list_systems_acted_on(content, context, technique_id)]
    allowed = place_asset_types(context.asset.get("category_code"), codes)

    def fits(control: LibraryControl) -> bool:
        is_wanted_domain = about_ai or control.domain != c.Controls.AI_DOMAIN
        return is_wanted_domain and asset_type_fits(control.asset_type, allowed)

    return fits


def _list_systems_acted_on(content: dict[str, Any], context: FrozenContext, technique_id: str) -> list[dict[str, Any]]:
    """The card's systems the technique acts on: the card's MITRE systems_targeted for it, else every system of
    the card."""
    card_systems = context.find_systems(system["id"] for system in content.get("systems") or [])
    targeted = set()
    for target in (content.get("mitre") or {}).get("systems_targeted") or []:
        if target.get("technique") == technique_id:
            targeted.add(target.get("supporting_system"))
    return [system for system in card_systems if system["name"] in targeted] or card_systems


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


# ----------------------------------------------------------------------------- a MITRE plan's candidates

#: One step's candidates of one kind, in order: (library row, found by: its MITRE mitigation's ID, or "meaning").
_Found = list[tuple[LibraryControl, str]]


def gather_plan_candidates(
    scenario: dict[str, Any], context: FrozenContext, snapshot: LibrarySnapshot
) -> list[dict[str, Any]]:
    """A MITRE card's remediation candidates (owner 2026-11-27): per attack step, the library controls linked to its
    MITRE mitigations, best link first, and those nearest it by meaning, each of an IT/OT type the step's systems
    take, one per control text and none the card already has; at most PLAN_CANDIDATES_LIMIT, each step's share
    fair. One row per control, naming every step it is offered for."""
    if not snapshot.library.control_library:
        return []
    content, prepared = scenario["content"], _read_prepared_links([scenario], snapshot)
    about_ai = build_control_query(content, context).is_about_ai
    taken = _list_card_control_texts(scenario, prepared)
    steps = content["attack"]["techniques"]
    found: list[tuple[str, _Found, _Found]] = []
    for step, nearest in zip(steps, _find_steps_by_meaning(content, context, snapshot), strict=True):
        fits = _fits_technique_systems(content, context, step["id"], about_ai)
        found.append((step["id"], *_list_step_candidates(step, prepared, fits, nearest, taken)))
    rows = _share_candidates(found)
    offered = {entry["technique"] for row in rows for entry in row["offered_for"]}
    log.info(
        c.LogEvent.PLAN_CANDIDATES_GATHERED,
        scenario_id=scenario["_id"],
        linked=sum(len(linked) for _, linked, _ in found),
        meaning=sum(len(meaning) for _, _, meaning in found),
        offered=len(rows),
        steps_without=[step["id"] for step in steps if step["id"] not in offered],
    )
    return rows


def describe_attack_steps(scenario: dict[str, Any]) -> list[dict[str, Any]]:
    """The card's attack steps as its plan reads them, once per plan: each technique by its ATT&CK ID and name,
    with its defending MITRE mitigations in MITRE's own words, unredacted (none on a card stored before
    2026-11-24: no mitre_says)."""
    content = scenario["content"]
    names, texts = _name_mitigations(content), _read_mitigation_texts(content)
    steps = []
    for technique in content["attack"]["techniques"]:
        mitigations = [
            {"mitigation": mitigation, "name": names.get(mitigation, "")}
            | ({"mitre_says": words} if (words := texts.get((technique["id"], mitigation))) else {})
            for mitigation in technique["mitigations"]
            if mitigation not in c.ControlLinks.NOT_MITIGATIONS
        ]
        steps.append({"technique": technique["id"], "name": technique["name"], "mitigations": mitigations})
    return steps


def _list_card_control_texts(scenario: dict[str, Any], prepared: _Prepared) -> set[str]:
    """The control texts of the card's own done controls (an older MITRE card's): never a candidate too."""
    controls = scenario.get("controls") or {}
    if controls.get("status") != c.Status.DONE:
        return set()
    rows = (prepared.by_id.get(item["control_id"]) for item in controls.get("items") or [])
    return {read_control_twin_key(row) for row in rows if row is not None}


def _find_steps_by_meaning(
    content: dict[str, Any], context: FrozenContext, snapshot: LibrarySnapshot
) -> list[list[LibraryControl]]:
    """Each attack step's library rows, nearest first, in one search of the local vectors (no rerank): its name
    and its MITRE description's opening sentences, with the card's systems it acts on, redacted."""
    steps = content["attack"]["techniques"]
    described: dict[str, str] = {}
    for found in get_attack_repository().find_objects([step["id"] for step in steps], ()):
        if found.get("description"):  # an object both sources hold comes once per source
            described.setdefault(found["attack_id"], found["description"])
    most = get_settings().writer_technique_description_characters
    queries = []
    for step in steps:
        opening = opening_sentences(described.get(step["id"], ""), most)
        systems = ", ".join(system["name"] for system in _list_systems_acted_on(content, context, step["id"]))
        queries.append(redact(" ".join(part for part in (f"{step['name']}:", opening, f"Systems: {systems}") if part)))
    hits = snapshot.find_controls(queries, len(snapshot.library.control_library))
    return [[row for row, _ in found] for found in hits]


def _list_step_candidates(
    step: dict[str, Any], prepared: _Prepared, fits: _Fits, nearest: list[LibraryControl], taken: set[str]
) -> tuple[_Found, _Found]:
    """A step's fitting rows linked to its MITRE mitigations (best link first, at most
    PLAN_LINKED_CONTROLS_PER_TECHNIQUE) and nearest it by meaning (at most CONTROLS_PER_TECHNIQUE_BY_MEANING): one
    per control text, none of `taken`."""
    settings, seen = get_settings(), set(taken)

    def keep_new(pairs: Iterable[tuple[LibraryControl, str]], most: int) -> _Found:
        kept: _Found = []
        for row, found_by in pairs:
            if len(kept) < most and read_control_twin_key(row) not in seen:
                seen.add(read_control_twin_key(row))
                kept.append((row, found_by))
        return kept

    linked = ((row, mitigation) for row, mitigation, _ in _list_linked_controls(step, prepared, fits))
    meaning = ((row, c.ControlLinks.FOUND_BY_MEANING) for row in prepared.list_fitting_rows(nearest, fits))
    most_linked, most_meaning = settings.plan_linked_controls_per_technique, settings.controls_per_technique_by_meaning
    return keep_new(linked, most_linked), keep_new(meaning, most_meaning)


def _share_candidates(found: list[tuple[str, _Found, _Found]]) -> list[dict[str, Any]]:
    """The candidate rows, at most PLAN_CANDIDATES_LIMIT: each step's share is the limit over the steps, half
    linked, half by meaning; slots one kind leaves go to the other, then, a slot each in turn, to the other steps.
    A row an earlier step took takes no slot: it names this step too, even once the limit is reached."""
    limit = get_settings().plan_candidates_limit
    rows: dict[int, dict[str, Any]] = {}

    def take(technique: str, queue: Iterator[tuple[LibraryControl, str]], most: int) -> int:
        used = 0
        while used < most and (pair := next(queue, None)) is not None:
            row, entry = pair[0], {"technique": technique, "found_by": pair[1]}
            if row.control_id in rows:
                rows[row.control_id]["offered_for"].append(entry)
                continue
            if len(rows) >= limit:  # full: the rest of the queue only names its step on rows already offered
                continue
            match = c.ControlLinks.PLAN_CANDIDATE_MATCH
            rows[row.control_id] = {"control_id": row.control_id, "code": row.code, "score": None, "match": match}
            rows[row.control_id]["offered_for"] = [entry]
            used += 1
        return used

    share, queues = (limit // len(found) if found else 0), []
    for technique, linked, meaning in found:
        linked_left, meaning_left = iter(linked), iter(meaning)
        used = take(technique, linked_left, share // 2)
        used += take(technique, meaning_left, share - used)
        take(technique, linked_left, share - used)
        queues.append((technique, chain(linked_left, meaning_left)))
    while queues:  # the slots the steps left, one each in turn
        queues = [(technique, queue) for technique, queue in queues if take(technique, queue, 1)]
    return list(rows.values())
