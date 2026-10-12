r"""What code decides about the relevance gate's verdicts once every category was judged, before any gap-fill
(so a category these empty still gets its one AI threat). Code, not the AI's obedience:

* a threat refused for a need under one category is refused under every category (G209);
* a library threat stays only where its AssetType fits (owner 2026-10-12, G211: IT, OT or IT\OT, the last
  meaning both): an OT threat on an OT system or an OT asset, never on an IT system. An untyped threat, or one
  whose value is not a type (noted for a curator), fits everywhere."""

import dataclasses
from collections.abc import Collection, Sequence
from typing import Any

from app.core.constants import CandidateRejection, PlanMessage
from app.models.asset_context import FrozenContext
from app.models.library import LibraryThreat, asset_type_label, compatible_asset_types, place_asset_types
from app.models.threats import CategoryFindings, PlannedThreat, Verdict


def run_asset_types(context: FrozenContext) -> frozenset[str]:
    """The AssetType values a library threat may have to be judged at all: those fitting the asset or a chosen
    supporting system."""
    return compatible_asset_types(
        context.asset.get("category_code"), (system.get("category_code") for system in context.systems)
    )


def threats_that_fit(
    threats: Sequence[LibraryThreat], context: FrozenContext
) -> tuple[list[LibraryThreat], list[str]]:
    """The library threats this run judges (their AssetType fits the asset or a chosen system), and the plan's
    note on how many were left out and of which types: never a silent drop."""
    allowed = run_asset_types(context)
    fitting = [threat for threat in threats if threat.fits(allowed)]
    left_out = {asset_type_label(t.asset_type) for t in threats if not t.fits(allowed)}
    if not left_out:
        return fitting, []
    types = ", ".join(sorted(str(label) for label in left_out))
    takes = ", ".join(sorted(allowed)) or PlanMessage.ASSET_TYPE_NONE_RECORDED
    note = PlanMessage.ASSET_TYPE_LEFT_OUT.format(count=len(threats) - len(fitting), types=types, takes=takes)
    return fitting, [note]


def refuse_unrecorded_needs_everywhere(found: list[CategoryFindings]) -> None:
    """What a threat needs is a fact about the asset, never about a category (G209; live run b0c3908f: the
    helpdesk fraud was refused under one category, its helpdesk unrecorded, and accepted under another, where
    the AI forgot to say so). A threat one category refused for that is refused under every category, each
    record saying so."""
    refused = {
        rejection["library_id"]: rejection
        for result in found
        for rejection in result.audit.rejected
        if rejection["code"] == CandidateRejection.NEEDS_UNRECORDED
    }
    for result in found:
        kept = [(threat, why) for threat, why in result.accepted if threat.catalogue_id not in refused]
        result.audit.rejected.extend(
            refused[threat.catalogue_id] for threat, _ in result.accepted if threat.catalogue_id in refused
        )
        result.accepted[:] = kept
        result.audit.relevant = len(kept)


def place_on_matching_systems(found: list[CategoryFindings], context: FrozenContext) -> None:
    """Each accepted library threat keeps only the systems (or the asset itself) its AssetType fits; judged to
    apply only where its type cannot be, it is refused, its reason on the category's record."""
    asset_fits, system_fits = _place_fits(context)
    places = {system["id"]: _place(system["name"], system.get("category_code")) for system in context.systems}
    on_asset = _place(context.asset["name"], context.asset.get("category_code"))
    for result in found:
        kept = []
        for threat, verdict in result.accepted:
            placed = _placed(threat, verdict, asset_fits, system_fits)
            if placed is not None:
                kept.append((threat, placed))
                continue
            where = ", ".join(places.get(system, str(system)) for system in verdict.systems) or on_asset
            result.audit.rejected.append(_mismatch(threat, where))
        result.accepted[:] = kept
        result.audit.relevant = len(kept)


def keep_on_matching_systems(
    threats: list[PlannedThreat], library: Sequence[LibraryThreat], context: FrozenContext
) -> list[PlannedThreat]:
    """After the folds (G211 review): a fold unites the systems of the threats it joins, so a library threat
    could take a system its type does not fit from one folded into it (an AI threat, or a library twin of
    another type); it keeps only those it fits. Never none: its own systems were placed to fit, and its own
    place on the asset itself (no system) fitted the asset."""
    by_id = {threat.catalogue_id: threat for threat in library}
    _, system_fits = _place_fits(context)
    kept = []
    for threat in threats:
        own = by_id.get(threat.catalogue_id) if threat.catalogue_id is not None else None
        systems = tuple(s for s in threat.systems if own is None or own.fits(system_fits.get(s, frozenset())))
        kept.append(threat if systems == threat.systems else dataclasses.replace(threat, systems=systems))
    return kept


def _place_fits(context: FrozenContext) -> tuple[frozenset[str], dict[int, frozenset[str]]]:
    """The AssetType values the asset itself fits, and those each supporting system fits (its own code, the
    asset's when it is not recorded)."""
    asset_code = context.asset.get("category_code")
    system_fits = {
        system["id"]: place_asset_types(asset_code, (system.get("category_code"),))
        for system in context.systems
    }
    return place_asset_types(asset_code, ()), system_fits


def _placed(
    threat: LibraryThreat,
    verdict: Verdict,
    asset_fits: Collection[str],
    system_fits: dict[int, frozenset[str]],
) -> Verdict | None:
    """The verdict on only the places its threat's type fits; None when it fits none of them."""
    if not verdict.systems:  # the asset itself
        return verdict if threat.fits(asset_fits) else None
    systems = tuple(system for system in verdict.systems if threat.fits(system_fits.get(system, frozenset())))
    if not systems:
        return None
    return verdict if systems == verdict.systems else dataclasses.replace(verdict, systems=systems)


def _place(name: str, category_code: str | None) -> str:
    return f"{name} ({category_code})" if category_code else name


def _mismatch(threat: LibraryThreat, where: str) -> dict[str, Any]:
    return {
        "threat": threat.name,
        "library_id": threat.catalogue_id,
        "code": CandidateRejection.ASSET_TYPE_MISMATCH,
        "reason": PlanMessage.ASSET_TYPE_MISMATCH.format(
            asset_type=asset_type_label(threat.asset_type) or threat.asset_type, places=where
        ),
    }
