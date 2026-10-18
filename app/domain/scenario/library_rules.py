"""The library rules a plan uses: which AssetType values fit an asset or a place on it, and which threats the
library still holds."""

from collections.abc import Iterable

from app.core.asset_types import asset_type_label
from app.core.constants import COMPATIBLE_ASSET_TYPES, LibraryRowKind
from app.models.library.library import ThreatLibrary


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


def known_threat_ids(library: ThreatLibrary) -> frozenset[int]:
    """Every threat the library still holds: live (with or without a category link) or waiting for a
    curator. A retired or curator-rejected threat is not among them (accept's library check, Rule S4)."""
    pending = (row.row_id for row in library.pending if row.kind == LibraryRowKind.THREAT)
    return frozenset(
        (*(threat.catalogue_id for threat in library.threats), *library.threats_without_category, *pending)
    )
