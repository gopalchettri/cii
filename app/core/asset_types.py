"""Stored AssetType values (Control_Library, Threat_Catalogue, an asset's category code) read as AssetType,
and whether a library row of one type may be used where only some types fit."""

from collections.abc import Collection

from app.core.constants import AssetType


def asset_type_label(value: str | None) -> AssetType | None:
    r"""A stored AssetType or category code as one of the values (IT, OT, IT\OT), whatever its case and
    spacing; "IT/OT" is IT\OT too (owner 2026-10-13: DevTest5 writes the slash). None when blank or not a
    value (for example "IT-OT", owner 2026-10-12)."""
    try:
        return AssetType("".join((value or "").split()).upper().replace("/", "\\"))
    except ValueError:
        return None


def canonical_asset_type(value: str | None) -> str | None:
    r"""A stored AssetType as the library keeps it: its value when recognised (so "IT/OT" is kept as IT\OT,
    one spelling everywhere), else as stored, so an unknown one is still noted for a curator."""
    label = asset_type_label(value)
    return value if label is None else label.value


def unknown_asset_type(value: str | None) -> bool:
    """A stored AssetType that is not blank and not a value: a curator fixes it (noted, never silent)."""
    return bool((value or "").strip()) and asset_type_label(value) is None


def asset_type_fits(asset_type: str | None, allowed_types: Collection[str]) -> bool:
    r"""Whether a library row with `asset_type` may be used where only `allowed_types` fit. A row with no
    AssetType fits everywhere (spec v4.0 §7.5.2; threats too, owner 2026-10-12), and so does one whose value
    is not IT, OT or IT\OT: it is noted for a curator, never silently dropped."""
    label = asset_type_label(asset_type)
    return label is None or label in allowed_types
