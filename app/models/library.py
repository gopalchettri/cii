"""The threat and control libraries as loaded from SQL Server. Frozen, so one snapshot is shared safely by
every thread."""

from collections.abc import Collection, Iterable
from dataclasses import dataclass

from app.core.constants import (
    COMPATIBLE_ASSET_TYPES,
    AssetType,
    LibraryRowKind,
    LibrarySource,
    ResolveOutcome,
    StrideCategory,
)

#: (table name, SHA-256 of the whole table) per library table; equal stamps = identical library data.
LibraryStamp = tuple[tuple[str, bytes | None], ...]


def asset_type_label(value: str | None) -> AssetType | None:
    r"""A stored AssetType or category code as one of the values (IT, OT, IT\OT), whatever its case and
    spacing; None when blank or not a value (for example "IT-OT", owner 2026-10-12)."""
    try:
        return AssetType("".join((value or "").split()).upper())
    except ValueError:
        return None


def unknown_asset_type(value: str | None) -> bool:
    """A stored AssetType that is not blank and not a value: a curator fixes it (noted, never silent)."""
    return bool((value or "").strip()) and asset_type_label(value) is None


def compatible_asset_types(
    asset_category: str | None, system_categories: Iterable[str | None]
) -> frozenset[str]:
    """The library AssetType values (Control_Library, Threat_Catalogue) that fit: the union over the asset's
    category code and the given systems' category codes that are recognised (IT, OT, or both). Empty when none
    is recognised: then only untyped rows fit, never every row."""
    known = (
        COMPATIBLE_ASSET_TYPES[label]
        for value in (asset_category, *system_categories)
        if (label := asset_type_label(value))
    )
    return frozenset().union(*known)


def place_asset_types(asset_category: str | None, system_categories: Iterable[str | None]) -> frozenset[str]:
    """The AssetType values that fit one place a threat or a scenario is on (owner 2026-10-12, G211): its
    systems' category codes, each system whose code is not recorded taking the asset's (unknown is not a
    type); the asset's when it is on the asset itself (G211 review: one unrecorded system among recorded ones
    took nothing)."""
    codes = [code if asset_type_label(code) else asset_category for code in system_categories]
    return compatible_asset_types(None, codes) if codes else compatible_asset_types(asset_category, ())


def asset_type_fits(asset_type: str | None, allowed_types: Collection[str]) -> bool:
    r"""Whether a library row with `asset_type` may be used where only `allowed_types` fit. A row with no
    AssetType fits everywhere (spec v4.0 §7.5.2; threats too, owner 2026-10-12), and so does one whose value
    is not IT, OT or IT\OT: it is noted for a curator, never silently dropped."""
    label = asset_type_label(asset_type)
    return label is None or label in allowed_types


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

    def fits(self, allowed_types: Collection[str]) -> bool:
        return asset_type_fits(self.asset_type, allowed_types)


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

    def known_threat_ids(self) -> frozenset[int]:
        """Every threat the library still holds: live (with or without a category link) or waiting for a
        curator. A retired or curator-rejected threat is not among them (accept's library check, Rule S4)."""
        pending = (row.row_id for row in self.pending if row.kind == LibraryRowKind.THREAT)
        return frozenset(
            (*(threat.catalogue_id for threat in self.threats), *self.threats_without_category, *pending)
        )


@dataclass(frozen=True)
class LibraryControl:
    control_id: int
    code: str
    asset_type: str | None  # AssetType: IT, OT or IT\OT (both)
    domain: str | None
    name: str
    description: str | None

    def fits(self, allowed_types: Collection[str]) -> bool:
        """Whether this control may be mapped where only `allowed_types` (upper case) fit: a control with no
        AssetType fits every scenario (spec v4.0 §7.5.2)."""
        return asset_type_fits(self.asset_type, allowed_types)


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
