"""Reads the threat and control libraries from SQL Server, and proposes a threat to it (stored procedures
only)."""

import json
from collections import defaultdict
from collections.abc import Sequence

import structlog

from app.core.constants import LibraryRowKind, LogEvent, ResolveOutcome, StoredProcedure, StrideCategory
from app.core.database import Row, StoredProcedureClient
from app.models.library import (
    LibraryActor,
    LibraryControl,
    LibraryStamp,
    LibraryThreat,
    LibraryThreatType,
    PendingLibraryRow,
    ProposedThreat,
    RejectedLibraryThreat,
    ThreatLibrary,
    ThreatProposal,
    canonical_asset_type,
    unknown_asset_type,
)

log = structlog.get_logger(__name__)
_STRIDE_ORDER: dict[str, int] = {category.value: index for index, category in enumerate(StrideCategory)}


def _stride_sorted(category_names: set[str]) -> tuple[StrideCategory, ...]:
    """Only real STRIDE categories, in STRIDE order (a custom category never reaches a scenario)."""
    return tuple(
        StrideCategory(name)
        for name in sorted(category_names & _STRIDE_ORDER.keys(), key=lambda name: _STRIDE_ORDER[name])
    )


def _categories_by_threat(links: Sequence[Row], category_name: dict[int, str]) -> defaultdict[int, set[str]]:
    by_threat: defaultdict[int, set[str]] = defaultdict(set)
    for link in links:
        if link["ThreatCategoryID"] in category_name:
            by_threat[link["ThreatCatalogueID"]].add(category_name[link["ThreatCategoryID"]])
    return by_threat


def _actors_by_type(
    links: Sequence[Row], actor_by_id: dict[int, LibraryActor]
) -> defaultdict[int, list[LibraryActor]]:
    by_type: defaultdict[int, list[LibraryActor]] = defaultdict(list)
    for link in links:
        if link["ThreatActorID"] in actor_by_id:
            by_type[link["ThreatTypeID"]].append(actor_by_id[link["ThreatActorID"]])
    return by_type


def _library_types(
    rows: Sequence[Row], category_name: dict[int, str], actors_by_type: defaultdict[int, list[LibraryActor]]
) -> tuple[LibraryThreatType, ...]:
    """Every live type in id order, its category (a STRIDE one only) and its linked actors by name."""
    return tuple(
        LibraryThreatType(
            type_id=row["ThreatTypeID"],
            name=row["ThreatTypeName"],
            category=next(iter(_stride_sorted({category_name.get(row["ThreatCategoryID"], "")})), None),
            linked_actors=tuple(sorted(actors_by_type[row["ThreatTypeID"]], key=lambda actor: actor.name)),
        )
        for row in sorted(rows, key=lambda row: row["ThreatTypeID"])
    )


def _to_library_threat(
    row: Row, threat_type: Row, categories: set[str], actors: list[LibraryActor]
) -> LibraryThreat:
    return LibraryThreat(
        catalogue_id=row["ThreatCatalogueID"],
        name=row["ThreatName"],
        type_id=row["ThreatTypeID"],
        type_name=threat_type["ThreatTypeName"],
        categories=_stride_sorted(categories),
        linked_actors=tuple(sorted(actors, key=lambda actor: actor.name)),
        # None until the procedure returns it: fits everywhere (G211); "IT/OT" kept as IT\OT (G217)
        asset_type=canonical_asset_type(row.get("AssetType")),
    )


def _library_threats(
    rows: Sequence[Row],
    type_by_id: dict[int, Row],
    categories_by_threat: defaultdict[int, set[str]],
    actors_by_type: defaultdict[int, list[LibraryActor]],
) -> tuple[tuple[LibraryThreat, ...], tuple[int, ...]]:
    """(the live threats in id order, the ids left out). Strict (owner, 2026-10-10, G119): a threat with no
    category link of its own is left out and counted (library_data_invalid), never given its type's
    category."""
    ordered = sorted(rows, key=lambda row: row["ThreatCatalogueID"])
    threats = tuple(
        _to_library_threat(
            row,
            type_by_id[row["ThreatTypeID"]],
            categories_by_threat[row["ThreatCatalogueID"]],
            actors_by_type[row["ThreatTypeID"]],
        )
        for row in ordered
        if categories_by_threat[row["ThreatCatalogueID"]]
    )
    left_out = tuple(
        row["ThreatCatalogueID"] for row in ordered if not categories_by_threat[row["ThreatCatalogueID"]]
    )
    return threats, left_out


class LibraryRepository:
    def __init__(self, procedures: StoredProcedureClient) -> None:
        self._procedures = procedures

    def propose_threat(self, proposal: ThreatProposal) -> ProposedThreat:
        """One threat proposed (tsg_ResolveThreat): inserted pending (inactive) unless its name is live or
        pending already, answered as it is. The procedure re-checks under UPDLOCK, HOLDLOCK, so two callers
        proposing one name write it once."""
        (row,) = self._procedures.execute_procedure(
            StoredProcedure.RESOLVE_THREAT,
            CategoryName=proposal.category,
            TypeName=proposal.type_name,
            ThreatName=proposal.threat_name,
            Source=proposal.source,
            CreatedBy=proposal.created_by,
            ActorIDs=json.dumps(list(proposal.actor_ids)),
        )[0]
        return ProposedThreat(
            row["threat_type_id"], row["threat_catalogue_id"], ResolveOutcome(row["outcome"])
        )

    def read_library_stamp(self) -> LibraryStamp:
        rows = self._procedures.execute_procedure(StoredProcedure.GET_LIBRARY_STAMP)[0]
        # Sorted here: the procedure's UNION ALL has no guaranteed row order, and a reordered answer would
        # look like a library change and rebuild every search index.
        return tuple(sorted((row["table_name"], row["fingerprint"]) for row in rows))

    def load_threat_library(self) -> ThreatLibrary:
        # The procedure's eight result sets, in its order (scripts/sql: tsg_GetThreatLibrary).
        categories, types, threats, actors, type_actor_links, threat_category_links, pending, rejected = (
            self._procedures.execute_procedure(StoredProcedure.GET_THREAT_LIBRARY)
        )
        category_name = {row["ThreatCategoryID"]: row["ThreatCategoryName"] for row in categories}
        type_by_id = {row["ThreatTypeID"]: row for row in types}
        actor_by_id = {
            row["ThreatActorID"]: LibraryActor(row["ThreatActorID"], row["ThreatActorName"]) for row in actors
        }
        if threats and "AssetType" not in threats[0]:  # the old procedure: runs on, every threat untyped
            log.warning(LogEvent.LIBRARY_THREAT_ASSET_TYPE_MISSING)
        library_threats, without_category = _library_threats(
            threats,
            type_by_id,
            _categories_by_threat(threat_category_links, category_name),
            _actors_by_type(type_actor_links, actor_by_id),
        )
        actors_in_order = tuple(sorted(actor_by_id.values(), key=lambda actor: actor.actor_id))
        return ThreatLibrary(
            threats=library_threats,
            actors=actors_in_order,
            types=_library_types(types, category_name, _actors_by_type(type_actor_links, actor_by_id)),
            category_ids=tuple(sorted(category_name.items())),
            other_categories=tuple(sorted(set(category_name.values()) - _STRIDE_ORDER.keys())),
            pending=tuple(
                PendingLibraryRow(LibraryRowKind(row["kind"]), row["id"], row["name"], row["type_id"])
                for row in pending
            ),
            curator_rejected=tuple(
                RejectedLibraryThreat(row["ThreatCatalogueID"], row["ThreatName"], row["ThreatTypeID"])
                for row in rejected
            ),
            threats_without_category=without_category,
            threats_unknown_asset_type=tuple(
                threat.catalogue_id for threat in library_threats if unknown_asset_type(threat.asset_type)
            ),
        )

    def load_control_library(self) -> tuple[tuple[LibraryControl, ...], tuple[LibraryControl, ...]]:
        """(the active controls, every other one by code, name and domain): Control_Library only (owner,
        2026-10-09: standards are not used). A retired control is never mapped; a register may still name one
        (owner, 2026-10-11)."""
        active, *later = self._procedures.execute_procedure(StoredProcedure.GET_CONTROL_LIBRARY)
        if (
            not later
        ):  # the procedure from before 2026-10-11: the app still runs while the DBA installs the new one
            log.warning(LogEvent.LIBRARY_RETIRED_CONTROLS_MISSING)
        controls = _controls(active)
        if unknown := [control.code for control in controls if unknown_asset_type(control.asset_type)]:
            # Used for every scenario meanwhile (an unknown type is never a reason to drop a control).
            log.warning(LogEvent.LIBRARY_ASSET_TYPE_UNKNOWN, controls=len(unknown), codes=unknown[:10])
        return controls, _controls(later[0] if later else [])


def _controls(rows: Sequence[Row]) -> tuple[LibraryControl, ...]:
    """In id order; a retired row has no asset type and no description (it is never mapped or searched)."""
    return tuple(
        LibraryControl(
            control_id=row["ControlLibraryID"],
            code=row["ControlCode"],
            asset_type=canonical_asset_type(row.get("AssetType")),
            domain=row["Domain"],
            name=row["ControlName"],
            description=row.get("ControlDescription"),
        )
        for row in sorted(rows, key=lambda control: control["ControlLibraryID"])
    )
