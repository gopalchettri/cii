"""One run: a prompt of the catalog that fits the model, the AI's checked answer, matched to the catalog."""

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import asdict, dataclass, replace
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.ai.attempts import one_ask
from app.ai.chat import ChatModel
from app.core.constants import AiTask
from app.core.prompts import PROMPTS
from app.domain.service_mapper.catalog import CatalogService, CatalogSnapshot, candidates
from app.domain.shared.names import are_one_name, as_json, is_same_name, name_match_key, shorten_text
from app.domain.shared.prompt_redaction import redacted
from app.schemas.service_mapper import BLANK, CreateMappingRequest

_SYSTEM: str = PROMPTS["service_mapper"]["generate"]["text"]
_RECORD_CHARS = 240  # each catalog service's description and recorded upstream / downstream text


def generate_result(chat: ChatModel, catalog: CatalogSnapshot, record: dict, run: int) -> dict:
    """The reconciled new dependencies of (mapping_id, run) that the mapping does not hold yet."""
    request = CreateMappingRequest.model_validate(record["request"])
    counts = (record["limits"]["max_upstream"], record["limits"]["max_downstream"])
    held = (record.get("result") or {}).get("dependencies") or []
    held_ids = {dependency["service_id"] for dependency in held}
    services = [service for service in _most_relevant_first(request, catalog) if service.service_id not in held_ids]
    prompt = _fitted_prompt(chat, request, catalog, services, counts, held)

    def check(answer: dict[str, Any]) -> list[str]:
        try:
            GeneratedAnswer.model_validate(answer)
        except ValidationError as exc:  # at most 10 answer-format errors go back in the re-ask
            return [str(error["loc"]) + ": " + error["msg"] for error in exc.errors()[:10]]
        return []

    def dropped_items(answer: dict[str, Any]) -> list[str]:
        return answer_problems(request, GeneratedAnswer.model_validate(answer), catalog)

    with one_ask():  # every attempt of it (retries, a re-ask): one ask in tsg_ai_usage
        answer = chat.ask_for_checked_json(  # a retry of this run takes the answers it already got
            AiTask.SERVICE_MAPPER, _SYSTEM, prompt, check, dropped_items, reuse_earlier_answer=True
        )
    return reconcile(record["_id"], run, request, GeneratedAnswer.model_validate(answer), catalog, *counts, held)


def _fitted_prompt(
    chat: ChatModel,
    request: CreateMappingRequest,
    catalog: CatalogSnapshot,
    services: list[CatalogService],
    counts: tuple[int, int],
    held: Sequence[dict],
) -> str:
    budget = min(int(chat.max_prompt_chars * 0.55), chat.max_prompt_chars - len(_SYSTEM) - 4_000)
    prompt = _user_prompt(request, catalog, services, counts, held)
    if len(_SYSTEM) + len(prompt) > budget:
        # ponytail: a catalog too large for one prompt keeps its services most similar to the selected one.
        prompt = _user_prompt(request, catalog, [], counts, held)
        for kept in range(1, len(services) + 1):
            longer = _user_prompt(request, catalog, services[:kept], counts, held)
            if len(_SYSTEM) + len(longer) > budget:
                break
            prompt = longer
    return prompt


def _most_relevant_first(request: CreateMappingRequest, catalog: CatalogSnapshot) -> list[CatalogService]:
    text = redacted(request.model_dump())
    group = " / ".join(filter(None, (text["sector"], text["subsector"])))
    role = f"{text['service_name']}. {text['service_description']}. {group}"
    queries = [
        role,
        f"Direct upstream services and operational inputs needed by: {role}",
        f"Direct downstream services consuming the outputs or capabilities of: {role}",
    ]
    rank = {service.service_id: place for place, service in enumerate(candidates(catalog, queries))}
    return sorted(
        (service for service in catalog.services if not are_one_name(service.service_name, request.service_name)),
        key=lambda service: rank.get(service.service_id, len(rank)),
    )


def _user_prompt(
    request: CreateMappingRequest,
    catalog: CatalogSnapshot,
    services: list[CatalogService],
    counts: tuple[int, int],
    held: Sequence[dict],
) -> str:
    selected = redacted(request.model_dump())
    if not selected["subsector"]:  # none given: the AI is not shown an empty one
        del selected["subsector"]
    if service := selected_service(request, catalog):  # its own records: the catalog list leaves it out
        known = {"known_upstream": service.upstream_context, "known_downstream": service.downstream_context}
        selected |= {key: shorten_text(text, 1_000) for key, text in known.items() if text}
    already: dict[str, list[str]] = {"upstream": [], "downstream": []}  # names only: no id reaches the AI
    for dependency in held:
        for direction in dependency["relations"]:
            already[direction].append(dependency["service_name"])
    return as_json(
        {
            "selected_service": selected,
            "upstream_count": counts[0],
            "downstream_count": counts[1],
            **({"already_mapped": already} if held else {}),
            "catalog": _catalog_groups(catalog, services),
        }
    )


def _catalog_groups(catalog: CatalogSnapshot, services: list[CatalogService]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str | None], list[dict[str, Any]]] = {}
    for service in services:
        for place, group in enumerate(service.sectors):
            entry = _service_entry(service) if place == 0 else {"service_name": service.service_name}
            groups.setdefault((group.sector_name, group.subsector_name), []).append(entry)
    for group in sorted(catalog.sector_groups, key=lambda group: (group.sector_name, group.subsector_name or "")):
        groups.setdefault((group.sector_name, group.subsector_name), [])
    with_subsectors = {sector for sector, subsector in groups if subsector}
    return [
        {"sector": sector, "subsector": subsector, "services": entries}
        for (sector, subsector), entries in groups.items()
        if subsector or entries or sector not in with_subsectors
    ]


def _service_entry(service: CatalogService) -> dict[str, Any]:
    entry: dict[str, Any] = {"service_name": service.service_name}
    if service.description and service.description.casefold() != service.service_name.casefold():
        entry["description"] = shorten_text(service.description, _RECORD_CHARS)
    if service.upstream_context:
        entry["known_upstream"] = shorten_text(service.upstream_context, _RECORD_CHARS)
    if service.downstream_context:
        entry["known_downstream"] = shorten_text(service.downstream_context, _RECORD_CHARS)
    return entry


_TOO_VAGUE: str = PROMPTS["service_mapper"]["generate"]["too_vague"]
_REASK_NAMES_SHOWN = 8  # catalog services named in one re-ask problem
#: Words too common in service names to show two services are the same one.
_GENERIC_WORDS = frozenset(
    {
        "and", "of", "the", "for", "service", "services", "operation", "operations", "management", "system",
        "systems", "network", "networks", "supply", "supplies", "control", "centre", "center", "public",
        "government",
    }
)  # fmt: skip


class ProposedDependency(BaseModel):  # its field names and limits reach the AI in a re-ask
    model_config = ConfigDict(extra="forbid")

    service_name: str = Field(min_length=2, max_length=255)
    sector: str | None = Field(default=None, max_length=255)
    subsector: str | None = Field(default=None, max_length=255)
    dependency_reason: str = Field(min_length=20, max_length=800)
    applicability: str | None = Field(default=None, max_length=500)

    @field_validator("service_name", "dependency_reason")
    def required_text(cls, value: str) -> str:
        value = " ".join(value.split())
        if not value:
            raise ValueError(BLANK)
        return value


class GeneratedAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operational_context: str = Field(min_length=30, max_length=1_500)
    upstream_services: list[ProposedDependency] = Field(max_length=200)
    downstream_services: list[ProposedDependency] = Field(max_length=200)


@dataclass(frozen=True)
class ResolvedDependency:
    dependency_reason: str
    applicability: str | None
    rank: int
    identity: str
    service_id: int | None
    service_name: str
    sector: str | None
    subsector: str | None
    ai_suggested: bool


def reconcile(
    mapping_id: str,
    generation: int,
    request: CreateMappingRequest,
    answer: GeneratedAnswer,
    catalog: CatalogSnapshot,
    max_upstream: int,
    max_downstream: int,
    held: Sequence[dict] = (),
) -> dict:
    """The run's new dependencies (none the mapping holds already), each direction capped at its count."""
    (upstream, _), (downstream, _) = resolve_both(request, answer, catalog)
    upstream, downstream = _one_direction(upstream, downstream)
    upstream, downstream = (_not_held(upstream, held)[:max_upstream], _not_held(downstream, held)[:max_downstream])
    selected = selected_service(request, catalog)
    return {
        "selected_service": request.model_dump()
        | {"service_id": selected and selected.service_id, "operational_context": answer.operational_context},
        "dependencies": _merge(mapping_id, generation, upstream, downstream, catalog),
        "catalog_version": catalog.version,
    }


def answer_problems(request: CreateMappingRequest, answer: GeneratedAnswer, catalog: CatalogSnapshot) -> list[str]:
    """What reconcile would drop or leave without a sector, for the AI's one corrective re-ask."""
    (upstream, upstream_dropped), (downstream, downstream_dropped) = resolve_both(request, answer, catalog)
    new_items = [item for item in (*upstream, *downstream) if item.ai_suggested]
    service = selected_service(request, catalog)  # its recorded text, padded: a phrase of it copies a heading
    record = name_match_key(f"{service.upstream_context} | {service.downstream_context}") if service else ""
    record = f" {record} " if record else ""
    return [
        *(f"upstream_services: {problem}" for problem in upstream_dropped),
        *(f"downstream_services: {problem}" for problem in downstream_dropped),
        *(
            f'"{item.service_name}" needs a sector from catalog'
            for item in new_items
            if item.sector is None and catalog.sector_names
        ),
        *filter(None, (_catalog_alternative(item, catalog, request.service_name) for item in new_items)),
        *(
            f'"{item.service_name}" copies the recorded text, not a service: name the specific service that provides it'
            for item in new_items
            if record and f" {name_match_key(item.service_name)} " in record
        ),
    ]


def _catalog_alternative(item: ResolvedDependency, catalog: CatalogSnapshot, selected_name: str) -> str | None:
    if item.sector is None:
        return None
    words = _distinctive_words(item.service_name)
    names = [
        service.service_name
        for service in catalog.services
        if not is_same_name(service.service_name, selected_name)
        and words & _distinctive_words(service.service_name)
        and any(
            group.sector_name == item.sector and (item.subsector is None or group.subsector_name == item.subsector)
            for group in service.sectors
        )
    ]
    if not names:
        return None
    where = f"{item.sector} / {item.subsector}" if item.subsector else item.sector
    listed = ", ".join(f'"{name}"' for name in names[:_REASK_NAMES_SHOWN])
    return (
        f'"{item.service_name}" is new, but catalog {where} already has {listed}: '
        f'use the one that provides it, or keep "{item.service_name}" only if none does'
    )


def _distinctive_words(name: str) -> set[str]:
    return set(name_match_key(name).split()) - _GENERIC_WORDS


def selected_service(request: CreateMappingRequest, catalog: CatalogSnapshot) -> CatalogService | None:
    """The catalog's selected service, when exactly one service has its name, sector and subsector (any
    subsector of that sector when none is given)."""
    sector = name_match_key(request.sector)
    matches = [
        service
        for service in catalog.services
        if is_same_name(service.service_name, request.service_name)
        and (
            _in_group(service, request.sector, request.subsector)
            if request.subsector
            else any(name_match_key(group.sector_name) == sector for group in service.sectors)
        )
    ]
    return matches[0] if len(matches) == 1 else None


def _in_group(service: CatalogService, sector: str | None, subsector: str | None) -> bool:
    sector, subsector = name_match_key(sector or ""), name_match_key(subsector or "")
    return any(
        name_match_key(group.sector_name) == sector and name_match_key(group.subsector_name or "") == subsector
        for group in service.sectors
    )


def resolve_both(
    request: CreateMappingRequest, answer: GeneratedAnswer, catalog: CatalogSnapshot
) -> tuple[tuple[list[ResolvedDependency], list[str]], tuple[list[ResolvedDependency], list[str]]]:
    selected = selected_service(request, catalog)
    selected_id = selected.service_id if selected else None
    upstream, up_dropped = resolve_proposals(answer.upstream_services, catalog, request.service_name, selected_id)
    downstream, down_dropped = resolve_proposals(answer.downstream_services, catalog, request.service_name, selected_id)
    downstream = [
        next((replace(item, identity=up.identity) for up in upstream if _same_new_service(up, item)), item)
        for item in downstream
    ]
    upstream = _recorded_only_with_a_record(
        upstream,
        selected.upstream_context if selected else "",
        {service.service_id: service.downstream_context for service in catalog.services},
    )
    downstream = _recorded_only_with_a_record(
        downstream,
        selected.downstream_context if selected else "",
        {service.service_id: service.upstream_context for service in catalog.services},
    )
    return (upstream, up_dropped), (downstream, down_dropped)


def _recorded_only_with_a_record(
    items: list[ResolvedDependency], selected_record: str, other_records: dict[int, str]
) -> list[ResolvedDependency]:
    # ponytail: any record in that direction counts; free text cannot be matched to one service reliably.
    return [
        replace(item, dependency_reason="Inferred:" + item.dependency_reason.removeprefix("Recorded:"))
        if item.dependency_reason.startswith("Recorded:")
        and not (selected_record or other_records.get(item.service_id or 0))
        else item
        for item in items
    ]


def _same_new_service(a: ResolvedDependency, b: ResolvedDependency) -> bool:
    return a.ai_suggested and b.ai_suggested and are_one_name(a.service_name, b.service_name)


def resolve_proposals(
    proposals: list[ProposedDependency], catalog: CatalogSnapshot, selected_name: str, selected_id: int | None
) -> tuple[list[ResolvedDependency], list[str]]:
    by_name: dict[str, list[CatalogService]] = defaultdict(list)
    for service in catalog.services:
        by_name[name_match_key(service.service_name)].append(service)
    labels = {
        name_match_key(name)
        for group in catalog.sector_groups
        for name in (group.sector_name, group.subsector_name)
        if name
    }
    kept: dict[str, ResolvedDependency] = {}
    dropped: list[str] = []
    for rank, proposal in enumerate(proposals):
        name = f'"{proposal.service_name}"'
        matches = _catalog_matches(proposal, by_name, catalog.services)
        if len(matches) > 1:  # a shared name never becomes a guessed or invented service
            dropped.append(f"{name} names several catalog services: copy the sector and subsector of the one meant")
        elif (matches and matches[0].service_id == selected_id) or are_one_name(proposal.service_name, selected_name):
            continue  # never a dependency of itself
        elif not matches and name_match_key(proposal.service_name) in labels:
            dropped.append(f"{name} is a sector or subsector name, not a service: name the service")
        elif (resolved := _resolve_one(proposal, matches[0] if matches else None, catalog, rank)) is None:
            dropped.append(f"{name} {_TOO_VAGUE}")
        elif resolved.identity in kept or any(_same_new_service(item, resolved) for item in kept.values()):
            continue  # the first, stronger mention stays
        else:
            kept[resolved.identity] = resolved
    return list(kept.values()), dropped


def _one_direction(
    upstream: list[ResolvedDependency], downstream: list[ResolvedDependency]
) -> tuple[list[ResolvedDependency], list[ResolvedDependency]]:
    up_rank = {item.identity: item.rank for item in upstream}
    down_rank = {item.identity: item.rank for item in downstream}
    return (
        [item for item in upstream if item.rank <= down_rank.get(item.identity, item.rank)],
        [item for item in downstream if item.rank < up_rank.get(item.identity, item.rank + 1)],
    )


def _not_held(items: list[ResolvedDependency], held: Sequence[dict]) -> list[ResolvedDependency]:
    ids = {dependency.get("identity") for dependency in held}
    named = [dependency["service_name"] for dependency in held if dependency["ai_suggested"]]
    fresh = [item for item in items if item.identity not in ids]
    return [item for item in fresh if not any(are_one_name(name, item.service_name) for name in named)]


def _catalog_matches(
    proposal: ProposedDependency, by_name: dict[str, list[CatalogService]], services: tuple[CatalogService, ...]
) -> list[CatalogService]:
    matches = by_name.get(name_match_key(proposal.service_name)) or [
        service for service in services if is_same_name(service.service_name, proposal.service_name)
    ]
    narrowed = [service for service in matches if _in_group(service, proposal.sector, proposal.subsector)]
    return narrowed if len(matches) > 1 and len(narrowed) == 1 else matches


def _resolve_one(
    proposal: ProposedDependency, service: CatalogService | None, catalog: CatalogSnapshot, rank: int
) -> ResolvedDependency | None:
    key = name_match_key(proposal.service_name)
    named: tuple[str, int | None, str, str | None, str | None, bool]
    if service is not None:
        named = (f"id:{service.service_id}", service.service_id, service.service_name, *service.primary_names, False)
    elif len(key.split()) < 2:
        return None  # an unmatched one-word capability is too vague to present as a service
    else:
        named = (f"name:{key}", None, proposal.service_name, *_taxonomy(proposal, catalog), True)
    return ResolvedDependency(proposal.dependency_reason, proposal.applicability, rank, *named)


def _taxonomy(proposal: ProposedDependency, catalog: CatalogSnapshot) -> tuple[str | None, str | None]:
    wanted = name_match_key(proposal.sector or "")
    sector = next((name for name in catalog.sector_names if name_match_key(name) == wanted), None)
    if sector is None:
        return None, None
    wanted = name_match_key(proposal.subsector or "")
    matching = [
        group.subsector_name
        for group in catalog.sector_groups
        if group.sector_name == sector and group.subsector_name and name_match_key(group.subsector_name) == wanted
    ]
    return sector, matching[0] if len(matching) == 1 else None


def _merge(
    mapping_id: str,
    generation: int,
    upstream: list[ResolvedDependency],
    downstream: list[ResolvedDependency],
    catalog: CatalogSnapshot,
) -> list[dict]:
    records: dict[str, dict] = {}
    by_id: dict[int | None, CatalogService] = {service.service_id: service for service in catalog.services}
    for direction, items in (("upstream", upstream), ("downstream", downstream)):
        for item in items:
            record = records.setdefault(
                item.identity, _record(mapping_id, generation, item, by_id.get(item.service_id))
            )
            record["relations"][direction] = {
                "dependency_reason": item.dependency_reason,
                "applicability": item.applicability,
                **dict.fromkeys(("isAccepted", "accepted_datetime", "accepted_by", "reviewed_datetime", "reviewed_by")),
            }
    return sorted(records.values(), key=lambda item: (item["rank"], item["dependency_id"]))


def _record(mapping_id: str, generation: int, item: ResolvedDependency, matched: CatalogService | None) -> dict:
    return {
        "dependency_id": uuid5(NAMESPACE_URL, f"{mapping_id}:{item.identity}").hex,  # one id per service
        "generation": generation,  # the run that found it
        "identity": item.identity,
        "service_id": item.service_id,
        "service_name": item.service_name,
        "sector": item.sector,
        "subsector": item.subsector,
        "ai_suggested": item.ai_suggested,
        "rank": item.rank,
        "additional_sector_associations": [asdict(group) for group in matched.sectors[1:]] if matched else [],
        "entity_associations": [asdict(entity) for entity in matched.entities] if matched else [],
        "relations": {},
    }
