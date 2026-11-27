"""Stored AssetType values read as AssetType, and whether a library row of one type fits where some types fit."""

from collections.abc import Collection, Iterable, Mapping

from app.core.constants import COMPATIBLE_ASSET_TYPES, AssetType


def asset_type_label(value: str | None) -> AssetType | None:
    r"""A stored AssetType or category code as IT, OT or IT\OT, whatever its case, spacing, slash or order (OT\IT is
    IT\OT); else None."""
    spelled = "".join((value or "").split()).upper().replace("/", "\\")
    try:
        return AssetType(_BOTH_ORDERS.get(spelled, spelled))
    except ValueError:
        return None


_BOTH_ORDERS = {r"OT\IT": AssetType.IT_OT.value}  # owner 2026-11-25: the data writes both sides either way round


def canonical_asset_type(value: str | None) -> str | None:
    """A stored AssetType as the library keeps it: its value when recognised, else as stored."""
    label = asset_type_label(value)
    return value if label is None else label.value


def unknown_asset_type(value: str | None) -> bool:
    """A stored AssetType that is not blank and not a value: a curator fixes it (noted, never silent)."""
    return bool((value or "").strip()) and asset_type_label(value) is None


def asset_type_fits(asset_type: str | None, allowed_types: Collection[str]) -> bool:
    """Whether a row with `asset_type` fits where only `allowed_types` fit; an untyped or unknown row fits."""
    label = asset_type_label(asset_type)
    return label is None or label in allowed_types


def compatible_asset_types(asset_category: str | None, system_categories: Iterable[str | None]) -> frozenset[str]:
    """The library AssetType values that fit the asset's and systems' recognised category codes (may be empty)."""
    known = (
        COMPATIBLE_ASSET_TYPES[label]
        for value in (asset_category, *system_categories)
        if (label := asset_type_label(value))
    )
    return frozenset().union(*known)


def place_asset_types(asset_category: str | None, system_categories: Iterable[str | None]) -> frozenset[str]:
    """The AssetType values that fit one place: its systems' codes (unrecorded ones take the asset's)."""
    codes = [code if asset_type_label(code) else asset_category for code in system_categories]
    return compatible_asset_types(None, codes) if codes else compatible_asset_types(asset_category, ())


def place_asset_label(asset_category: str | None, system_categories: Iterable[str | None]) -> str | None:
    r"""IT, OT or IT\OT for one place, as the library types its threats: IT\OT when both fit it (IT and OT systems,
    or an IT\OT one), else the one that fits; None when no code is recorded (the threat is saved untyped)."""
    fitting = place_asset_types(asset_category, system_categories)
    if AssetType.IT in fitting and AssetType.OT in fitting:
        return AssetType.IT_OT.value
    for label in (AssetType.OT, AssetType.IT):
        if label in fitting:
            return label.value
    return None


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
