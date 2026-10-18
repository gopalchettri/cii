"""A hand-written scenario's threat identity (BLUEPRINT M05 Rule L2; BUILD_PLAN S55): its category, type and
threat resolved against the library in memory, so only a new wording ever reaches SQL Server. Names compare as
the library's other checks do (normalised, library codes left out); an id wins, and an id and a name must name
the same row. Every disagreement is reported at once (422). Pure."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from app.core.constants import (
    ConflictReason,
    LibraryRowKind,
    LibraryStatus,
    RemediationMessage,
    StrideCategory,
)
from app.core.exceptions import Invalid
from app.domain.shared.names import name_match_key, threat_name_without_code
from app.models.library.library import ThreatLibrary
from app.models.remediation.plan import ThreatIdentity
from app.models.remediation.requests import LibraryRef, ManualScenario

#: Where a refusal points: v1's flat fields, e.g. body.manual_scenario.threat_type_id.
_FIELD = "body.manual_scenario.{part}"
Errors = list[dict[str, str]]


@dataclass(frozen=True)
class _Known:
    """One library row a reference may name: a type or a threat, live, pending or curator-rejected."""

    row_id: int
    name: str
    status: LibraryStatus
    type_id: int | None = None  # a threat's type
    categories: tuple[StrideCategory, ...] = ()  # a live threat's, in STRIDE order
    category: StrideCategory | None = None  # a live type's own


def resolve_threat(library: ThreatLibrary, scenario: ManualScenario) -> ThreatIdentity:
    errors: Errors = []
    reason: ConflictReason | None = None  # TYPE_MISMATCH: the library files the threat under another type
    types = _types(library)
    threat_type = _named(types, scenario.threat_type, "threat_type", errors)
    threat = _named(_threats(library), scenario.threat, "threat", errors)
    in_library = threat is not None and threat.status != LibraryStatus.CURATOR_REJECTED
    if threat is not None and in_library:  # threat names are unique across the library: its type decides
        library_type = _first(types, lambda row: row.row_id == threat.type_id)
        if threat_type is None or threat_type.row_id != threat.type_id:
            shown = library_type.name if library_type else str(threat.type_id)
            message = RemediationMessage.TYPE_MISMATCH.format(threat=threat.name, library_type=shown)
            part = "threat_type_id" if scenario.threat_type_id is not None else "threat_type_name"
            errors.append({"field": _FIELD.format(part=part), "message": message})
            reason = ConflictReason.TYPE_MISMATCH
        threat_type = library_type
    category = _category(library, scenario.threat_category, threat, threat_type, errors)
    if errors:
        raise Invalid(RemediationMessage.THREAT_REFS_INVALID, errors=errors, reason=reason)
    return ThreatIdentity(
        category=category,
        type_id=threat_type.row_id if threat_type else None,
        type_name=threat_type.name if threat_type else str(scenario.threat_type.name),
        catalogue_id=threat.row_id if threat is not None and in_library else None,
        threat_name=threat.name if threat is not None else str(scenario.threat.name),
        status=threat.status if threat is not None else None,
        category_id=_category_id(library, category),
    )


def _category_id(library: ThreatLibrary, category: StrideCategory | None) -> int | None:
    if category is None:
        return None
    return next(
        (row_id for row_id, name in library.category_ids if name.casefold() == category.casefold()), None
    )


def _types(library: ThreatLibrary) -> list[_Known]:
    live = [_Known(t.type_id, t.name, LibraryStatus.ACTIVE, category=t.category) for t in library.types]
    pending = [
        _Known(row.row_id, row.name, LibraryStatus.PENDING)
        for row in library.pending
        if row.kind == LibraryRowKind.TYPE
    ]
    return live + pending


def _threats(library: ThreatLibrary) -> list[_Known]:
    """Live, then pending, then curator-rejected: a name found twice is the earlier kind's."""
    live = [
        _Known(t.catalogue_id, t.name, LibraryStatus.ACTIVE, t.type_id, t.categories) for t in library.threats
    ]
    pending = [
        _Known(row.row_id, row.name, LibraryStatus.PENDING, row.type_id)
        for row in library.pending
        if row.kind == LibraryRowKind.THREAT
    ]
    rejected = [
        _Known(row.catalogue_id, row.name, LibraryStatus.CURATOR_REJECTED, row.type_id)
        for row in library.curator_rejected
    ]
    return live + pending + rejected


def _named(rows: Sequence[_Known], ref: LibraryRef, part: str, errors: Errors) -> _Known | None:
    """The row `ref` names; None for a new name. An unknown id, or an id and a name naming two rows, is an
    error."""
    named = _first(rows, lambda row: _key(row.name) == _key(ref.name)) if ref.name else None
    if ref.id is None:
        return named
    by_id = _first(rows, lambda row: row.row_id == ref.id)
    if by_id is None:
        message = RemediationMessage.UNKNOWN_ID.format(id=ref.id)
        errors.append({"field": _FIELD.format(part=f"{part}_id"), "message": message})
        return None
    if ref.name and named is not by_id:
        message = RemediationMessage.ID_NAME_DISAGREE.format(
            id=ref.id, library_name=by_id.name, name=ref.name
        )
        errors.append({"field": _FIELD.format(part=f"{part}_name"), "message": message})
    return by_id


def _category(
    library: ThreatLibrary,
    ref: LibraryRef | None,
    threat: _Known | None,
    threat_type: _Known | None,
    errors: Errors,
) -> StrideCategory | None:
    """The category given (a STRIDE one the library files the threat under), else the threat's first, else the
    type's; None when nothing names one (saved without a category, owner 2026-09-25)."""
    filed = threat.categories if threat is not None else ()
    if ref is None:
        return filed[0] if filed else (threat_type.category if threat_type else None)
    name = dict(library.category_ids).get(ref.id, "") if ref.id is not None else str(ref.name)
    category = next((c for c in StrideCategory if c.value.casefold() == name.casefold()), None)
    field = _FIELD.format(part="threat_category_id" if ref.id is not None else "threat_category_name")
    if ref.id is not None and ref.name and name and ref.name.casefold() != name.casefold():  # both must agree
        message = RemediationMessage.ID_NAME_DISAGREE.format(id=ref.id, library_name=name, name=ref.name)
        errors.append({"field": _FIELD.format(part="threat_category_name"), "message": message})
    elif category is None:
        message = RemediationMessage.CATEGORY_UNKNOWN.format(name=name or ref.id)
        errors.append({"field": field, "message": message})
    elif threat is not None and filed and category not in filed:
        message = RemediationMessage.CATEGORY_NOT_OF_THREAT.format(
            threat=threat.name, categories=", ".join(filed), category=category
        )
        errors.append({"field": field, "message": message})
    return category


def _first(rows: Sequence[_Known], wanted: Callable[[_Known], bool]) -> _Known | None:
    return next((row for row in rows if wanted(row)), None)


def _key(name: str | None) -> str:
    return name_match_key(threat_name_without_code(name or ""))
