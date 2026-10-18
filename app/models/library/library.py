"""The threat and control libraries as loaded from SQL Server. Frozen, so one snapshot is shared safely by
every thread."""

from dataclasses import dataclass

from app.core.constants import LibraryRowKind, LibrarySource, ResolveOutcome, StrideCategory

#: (table name, SHA-256 of the whole table) per library table; equal stamps = identical library data.
LibraryStamp = tuple[tuple[str, bytes | None], ...]


@dataclass(frozen=True)
class LibraryActor:
    actor_id: int
    name: str


@dataclass(frozen=True)
class LibraryThreatType:
    type_id: int
    name: str
    category: StrideCategory | None = None  # Threat_Type.ThreatCategoryID, when it is a STRIDE category
    linked_actors: tuple[LibraryActor, ...] = ()  # ThreatType_ThreatActor_Map, by name


@dataclass(frozen=True)
class LibraryThreat:
    catalogue_id: int
    name: str
    type_id: int
    type_name: str
    categories: tuple[StrideCategory, ...]
    linked_actors: tuple[LibraryActor, ...]
    asset_type: str | None = None  # Threat_Catalogue.AssetType: IT, OT or IT\OT; None fits everywhere (G211)


@dataclass(frozen=True)
class PendingLibraryRow:
    """A type or threat proposed to the library, waiting for a curator (IsActive 0, not deleted)."""

    kind: LibraryRowKind
    row_id: int
    name: str
    type_id: int | None  # a threat's type; None for a type


@dataclass(frozen=True)
class RejectedLibraryThreat:
    """A threat a curator rejected (IsDeleted 1, IsActive 0): never proposed again."""

    catalogue_id: int
    name: str
    type_id: int


@dataclass(frozen=True)
class ThreatProposal:
    """One threat proposed to the library (tsg_ResolveThreat): written pending unless its name exists."""

    category: (
        str | None
    )  # its primary STRIDE category; None: saved without a category link (owner 2026-09-25)
    type_name: str  # exact, so an existing library type is matched, never duplicated
    threat_name: str
    source: LibrarySource
    created_by: str  # the person's X-User-Id
    actor_ids: tuple[int, ...]  # linked to a NEW type only


@dataclass(frozen=True)
class ProposedThreat:
    type_id: int
    catalogue_id: int
    outcome: ResolveOutcome


@dataclass(frozen=True)
class ThreatLibrary:
    threats: tuple[LibraryThreat, ...]
    actors: tuple[LibraryActor, ...]
    # Every live type, with or without live threats (a hand-written scenario names one by id or name).
    types: tuple[LibraryThreatType, ...] = ()
    category_ids: tuple[tuple[int, str], ...] = ()  # every live category: (id, name), a category named by id
    # For the name checks before a library write (promote, hand-written scenarios): reuse a pending name,
    # never propose a rejected one.
    pending: tuple[PendingLibraryRow, ...] = ()
    curator_rejected: tuple[RejectedLibraryThreat, ...] = ()
    # Live categories that are not STRIDE: never planned under (a scenario is written for STRIDE alone), and
    # each is noted on the plan.
    other_categories: tuple[str, ...] = ()
    # Live threats left out because they have no category link of their own (G119): a curator fixes the data.
    threats_without_category: tuple[int, ...] = ()
    # Live threats whose AssetType is not IT, OT or IT\OT (G211): used everywhere meanwhile, noted for a
    # curator.
    threats_unknown_asset_type: tuple[int, ...] = ()


@dataclass(frozen=True)
class LibraryControl:
    control_id: int
    code: str
    asset_type: str | None  # AssetType: IT, OT or IT\OT (both)
    domain: str | None
    name: str
    description: str | None


@dataclass(frozen=True)
class ResolvedControls:
    """Control references resolved against the library (BLUEPRINT M05 L3): the library rows they name, in the
    order first named, and the register entries no row matches, kept as text (tolerant mode only)."""

    controls: tuple[LibraryControl, ...]
    texts: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()  # entries left out or changed, for the reviewer (never the AI)


@dataclass(frozen=True)
class LoadedLibraries:
    """One consistent snapshot: both libraries and the fingerprint they were loaded at, replaced together."""

    stamp: LibraryStamp
    threat_library: ThreatLibrary
    control_library: tuple[LibraryControl, ...]  # active: the only ones mapped, searched or recommended
    retired_controls: tuple[LibraryControl, ...] = ()  # by code, name and domain: a register may name one
