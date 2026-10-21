"""Turn one persisted generation into the minimal public JSON shape."""

from app.core.constants import Status
from app.models.jobs.views import retry_notice_of
from app.models.service_mapper.contract import (
    BidirectionalService,
    DependencyService,
    DirectionalDependency,
    MappingListItem,
    MappingSummary,
    MappingView,
    SelectedService,
)


def pending_relationships(result: dict) -> list[dict[str, str]]:
    """Every relationship of a generation still without a decision, as {dependency_id, direction}."""
    return [
        {"dependency_id": dependency["dependency_id"], "direction": direction}
        for dependency in result.get("dependencies", [])
        for direction, relation in dependency["relations"].items()
        if relation["isAccepted"] is None
    ]


def approved_relationships(record: dict) -> list[tuple[dict, str]]:
    """The (dependency, direction) pairs an approved dependency graph may use: none unless the mapping is
    accepted, then only the relationships a reviewer accepted. Every graph consumer reads through this."""
    if record.get("review") != "accepted":
        return []
    return [
        (dependency, direction)
        for dependency in (record.get("result") or {}).get("dependencies", [])
        for direction, relation in dependency["relations"].items()
        if relation["isAccepted"] is True
    ]


def mapping_view(record: dict) -> MappingView:
    result = record.get("result") or {}
    upstream: list[DependencyService] = []
    downstream: list[DependencyService] = []
    bidirectional: list[BidirectionalService] = []
    for dependency in result.get("dependencies", []):
        common = _common(dependency)
        relations = dependency["relations"]
        if "upstream" in relations and "downstream" in relations:
            bidirectional.append(
                BidirectionalService(
                    **common,
                    upstream=DirectionalDependency.model_validate(relations["upstream"]),
                    downstream=DirectionalDependency.model_validate(relations["downstream"]),
                )
            )
        elif "upstream" in relations:
            upstream.append(DependencyService(**common, **relations["upstream"]))
        elif "downstream" in relations:
            downstream.append(DependencyService(**common, **relations["downstream"]))
    summary = result.get("summary") or _empty_summary(record.get("limits") or {})
    return MappingView(
        mapping_id=record["_id"],
        status=record["status"],
        generation=record["generation"],
        review=record["review"],
        selected_service=_selected(record),
        upstream_services=upstream,
        downstream_services=downstream,
        bidirectional_services=bidirectional,
        summary=MappingSummary.model_validate(summary),
        prompts=result.get("prompts"),
        error=record.get("job", {}).get("error") if record["status"] == Status.FAILED else None,
        retrying=retry_notice_of(record["status"], record.get("job", {}).get("retry")),
        created_at=record["created_at"],
        updated_at=record["updated_at"],
    )


def _empty_summary(limits: dict) -> dict:
    """The summary of a generation that has no result yet."""
    return {
        "unique_services": 0,
        "upstream_count": 0,
        "downstream_count": 0,
        "max_upstream": limits.get("max_upstream", 0),
        "max_downstream": limits.get("max_downstream", 0),
    }


def mapping_list_item(record: dict) -> MappingListItem:
    return MappingListItem(
        mapping_id=record["_id"],
        status=record["status"],
        generation=record["generation"],
        review=record["review"],
        selected_service=_selected(record),
        created_at=record["created_at"],
        updated_at=record["updated_at"],
    )


def _selected(record: dict) -> SelectedService:
    return SelectedService.model_validate(
        (record.get("result") or {}).get("selected_service")
        or (record["request"] | {"service_id": None, "operational_context": None})
    )


def _common(dependency: dict) -> dict:
    return {
        key: dependency[key]
        for key in ("dependency_id", "service_id", "service_name", "sector", "subsector", "ai_suggested")
    }
