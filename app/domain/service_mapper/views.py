"""Turn one persisted mapping into the minimal public JSON shape."""

from app.core.constants import MappingOverall, Status
from app.models.jobs.views import retry_notice_of
from app.models.service_mapper.contract import (
    DependencyService,
    MappingListItem,
    MappingProgress,
    MappingStatus,
    MappingSummary,
    MappingTimings,
    MappingView,
    RelationshipCounts,
    SelectedService,
)


def pending_relationships(result: dict) -> list[dict[str, str]]:
    """Every relationship of a mapping still without a decision, as {dependency_id, direction}."""
    return [
        {"dependency_id": dependency["dependency_id"], "direction": direction}
        for dependency in result.get("dependencies", [])
        for direction, relation in dependency["relations"].items()
        if relation["isAccepted"] is None
    ]


def approved_relationships(record: dict) -> list[tuple[dict, str]]:
    """The (dependency, direction) pairs an approved dependency graph may use: the mapping's relationships a
    reviewer accepted. Every graph consumer reads through this."""
    return [
        (dependency, direction)
        for dependency in (record.get("result") or {}).get("dependencies", [])
        for direction, relation in dependency["relations"].items()
        if relation["isAccepted"] is True
    ]


def mapping_view(record: dict, max_generations: int) -> MappingView:
    dependencies = (record.get("result") or {}).get("dependencies") or []
    by_direction: dict[str, list[DependencyService]] = {"upstream": [], "downstream": []}
    for dependency in dependencies:
        for direction, relation in dependency["relations"].items():  # one, or both in an older record
            by_direction[direction].append(DependencyService(**_common(dependency), **relation))
    return MappingView(
        mapping_id=record["_id"],
        status=record["status"],
        **_runs(record, max_generations),
        upstream_services=by_direction["upstream"],
        downstream_services=by_direction["downstream"],
        summary=_summary(dependencies, record.get("limits") or {}),
        error=record.get("job", {}).get("error") if record["status"] == Status.FAILED else None,
        retrying=retry_notice_of(record["status"], record.get("job", {}).get("retry")),
        created_at=record["created_at"],
        updated_at=record["updated_at"],
    )


def mapping_status(record: dict, max_generations: int) -> MappingStatus:
    """The mapping's status: where its latest run is, and how many relationships are decided."""
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
        **_runs(record, max_generations),
        progress=MappingProgress(overall=_overall(status), relationships=counts, timings=_timings(job)),
        retrying=retry_notice_of(status, job.get("retry")),
        error=job.get("error") if status == Status.FAILED else None,
        created_at=record["created_at"],
        updated_at=record["updated_at"],
    )


def _timings(job: dict) -> MappingTimings:
    """The latest run's times, kept in its job (every new run starts a new one)."""
    seconds = job.get("timings") or {}
    return MappingTimings(catalog=seconds.get("catalog_s"), services=seconds.get("services_s"))


def _overall(status: str) -> MappingOverall:
    """Queued and running read as generating; done, failed and cancelled as themselves."""
    if status in (Status.QUEUED, Status.RUNNING):
        return MappingOverall.GENERATING
    return MappingOverall(status)


def _runs(record: dict, max_generations: int) -> dict[str, int]:
    """The latest run's number, how many runs finished, and the most a mapping may have (0: no limit)."""
    return {
        "generation": record["job"]["epoch"],
        "generations_done": record.get("generations_done", 0),
        "max_generations": max_generations,
    }


def _summary(dependencies: list[dict], limits: dict) -> MappingSummary:
    """How many services the mapping holds in each direction, and each run's most per direction."""
    directions = [direction for dependency in dependencies for direction in dependency["relations"]]
    return MappingSummary(
        unique_services=len(dependencies),
        upstream_count=directions.count("upstream"),
        downstream_count=directions.count("downstream"),
        max_upstream=limits.get("max_upstream", 0),
        max_downstream=limits.get("max_downstream", 0),
    )


def mapping_list_item(record: dict, max_generations: int) -> MappingListItem:
    return MappingListItem(
        mapping_id=record["_id"],
        status=record["status"],
        **_runs(record, max_generations),
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
    keys = ("dependency_id", "service_id", "service_name", "sector", "subsector", "ai_suggested")
    return {key: dependency[key] for key in keys} | {"generation": dependency.get("generation")}
