"""Turn one persisted generation into the minimal public JSON shape."""

from app.core.constants import MappingOverall, Status
from app.models.jobs.views import retry_notice_of
from app.models.service_mapper.contract import (
    DependencyService,
    MappingListItem,
    MappingProgress,
    MappingStatus,
    MappingSummary,
    MappingView,
    RelationshipCounts,
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
    """The (dependency, direction) pairs an approved dependency graph may use: the current generation's
    relationships a reviewer accepted. Every graph consumer reads through this."""
    return [
        (dependency, direction)
        for dependency in (record.get("result") or {}).get("dependencies", [])
        for direction, relation in dependency["relations"].items()
        if relation["isAccepted"] is True
    ]


def mapping_view(record: dict) -> MappingView:
    result = record.get("result") or {}
    by_direction: dict[str, list[DependencyService]] = {"upstream": [], "downstream": []}
    for dependency in result.get("dependencies", []):
        for direction, relation in dependency["relations"].items():  # one, or both in an older record
            by_direction[direction].append(DependencyService(**_common(dependency), **relation))
    summary = result.get("summary") or _empty_summary(record.get("limits") or {})
    return MappingView(
        mapping_id=record["_id"],
        status=record["status"],
        generation=record["generation"],
        upstream_services=by_direction["upstream"],
        downstream_services=by_direction["downstream"],
        summary=MappingSummary.model_validate(summary),
        error=record.get("job", {}).get("error") if record["status"] == Status.FAILED else None,
        retrying=retry_notice_of(record["status"], record.get("job", {}).get("retry")),
        created_at=record["created_at"],
        updated_at=record["updated_at"],
    )


def mapping_status(record: dict) -> MappingStatus:
    """The mapping's status: where its generation is, and how many relationships are decided."""
    flags = [
        relation["isAccepted"]
        for dependency in (record.get("result") or {}).get("dependencies", [])
        for relation in dependency["relations"].values()
    ]
    status, job = record["status"], record.get("job", {})
    counts = RelationshipCounts(
        total=len(flags), accepted=flags.count(True), rejected=flags.count(False), pending=flags.count(None)
    )
    return MappingStatus(
        mapping_id=record["_id"],
        entity_id=record["entity_id"],
        user_id=record.get("created_by"),
        status=status,
        generation=record["generation"],
        progress=MappingProgress(overall=_overall(status), relationships=counts),
        retrying=retry_notice_of(status, job.get("retry")),
        error=job.get("error") if status == Status.FAILED else None,
        created_at=record["created_at"],
        updated_at=record["updated_at"],
    )


def _overall(status: str) -> MappingOverall:
    """Queued and running read as generating; done, failed and cancelled as themselves."""
    if status in (Status.QUEUED, Status.RUNNING):
        return MappingOverall.GENERATING
    return MappingOverall(status)


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
