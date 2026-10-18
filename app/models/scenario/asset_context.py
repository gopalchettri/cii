"""The asset context of a run: tsg_GetAssetContext's five result sets, and the context frozen from them on the
run, which every later step reads and never changes. Which facts a run has is the procedure's
choice: every column of its asset and supporting-system rows, nothing else."""

from dataclasses import asdict, dataclass, field, fields
from typing import Any

from app.core.constants import ContextProperties

Row = dict[str, Any]


@dataclass(frozen=True)
class AssetContextRows:
    """tsg_GetAssetContext's answer, one field per result set."""

    asset: Row | None  # None: the entity does not own the asset
    services: list[Row]  # the asked service, else every service linked to the asset; each with `linked`
    sector: Row | None  # the asked (sub-)sector with its parent's id and name
    systems: list[Row]  # the asked supporting systems that are linked to the asset and not deleted
    options: list[Row]  # {code, value or id, name}: the dropdown names, keyed as the procedure returns them


@dataclass(frozen=True)
class FrozenContext:
    """What a run knows about its asset, frozen at its start (tsg_sessions.context). Names have runs of spaces
    collapsed; coded columns hold option names, never ids. Each fact is held once: sector, sub_sector,
    critical_service and entity_technology_context are read from `asset_context` (no copies to drift)."""

    asset: dict[str, Any]  # id, name, category_code: what names, cards and the control pool need
    asset_context: dict[str, Any]  # every other column of the asset row: the facts the prompts get
    systems: list[dict[str, Any]]  # aliased SYS1..n in request order: id, alias, name, category_code + facts
    missing_facts: list[str] = field(default_factory=list)  # facts no system records: information only

    def to_record(self) -> dict[str, Any]:
        return asdict(self)

    def own_and_organisation_facts(self) -> tuple[dict[str, Any], dict[str, Any]]:
        """(this asset's own facts, the organisation's): a column named entity_... describes the whole
        organisation, never this asset (G208), so no step reads it as the asset's."""
        prefix = ContextProperties.ORGANISATION_PREFIX
        own = {key: value for key, value in self.asset_context.items() if not key.startswith(prefix)}
        return own, {key: value for key, value in self.asset_context.items() if key.startswith(prefix)}

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "FrozenContext":
        """A stored context; the top-level copies a run frozen before 2026-10-11 still holds are not read."""
        return cls(**{name: record[name] for name in _FIELDS if name in record})


_FIELDS = tuple(f.name for f in fields(FrozenContext))
