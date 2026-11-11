"""Stored AssetType values (Control_Library, Threat_Catalogue, an asset's category code) read as AssetType,
and whether a library row of one type may be used where only some types fit."""

from collections.abc import Collection, Iterable, Mapping

from app.core.constants import COMPATIBLE_ASSET_TYPES, AssetType


def asset_type_label(value: str | None) -> AssetType | None:
    r"""A stored AssetType or category code as one of the values (IT, OT, IT\OT), whatever its case and
    spacing; "IT/OT" is IT\OT too. None when blank or not a value (for example "IT-OT")."""
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
    AssetType fits everywhere (threats too), and so does one whose value is not IT, OT or IT\OT: it is
    noted for a curator, never silently dropped."""
    label = asset_type_label(asset_type)
    return label is None or label in allowed_types


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
    """The AssetType values that fit one place a threat or a scenario is on: its systems' category codes,
    each system whose code is not recorded taking the asset's (unknown is not a type); the asset's when it
    is on the asset itself."""
    codes = [code if asset_type_label(code) else asset_category for code in system_categories]
    return compatible_asset_types(None, codes) if codes else compatible_asset_types(asset_category, ())


def find_fitting_entry_points(
    asset_type: str | None,
    entry_points: tuple[int, ...],
    asset_category: str | None,
    system_categories: Mapping[int, str | None],
) -> tuple[int, ...] | None:
    """Returns the entry points where a row of `asset_type` fits, () for the asset itself; None: none fits."""
    if not entry_points:
        return () if asset_type_fits(asset_type, place_asset_types(asset_category, ())) else None
    fitting = tuple(
        system
        for system in entry_points
        if asset_type_fits(
            asset_type,
            place_asset_types(asset_category, (system_categories[system],))
            if system in system_categories
            else frozenset(),
        )
    )
    return fitting or None
