"""Control references resolved against the in-memory control library (BLUEPRINT M05 L3; BUILD_PLAN S46): by
id, then code (case-blind), then exact name (case-blind). An id and a code naming two different rows are
always refused. Strict mode (a hand-written scenario's own controls, which become its controls): anything
unknown or named twice is refused, every fault listed at once (422). Tolerant mode (the register's existing
controls, a gap-analysis baseline): an unknown entry is kept as text, a repeat dropped. In memory: no round
trip."""

from collections.abc import Sequence

from app.core.constants import Remediation, RemediationMessage, SnapshotWarning
from app.core.exceptions import Invalid
from app.models.library.library import LibraryControl, ResolvedControls
from app.models.remediation.requests import ControlRef


class _ControlIndex:
    def __init__(self, controls: Sequence[LibraryControl]) -> None:
        self.by_id = {control.control_id: control for control in controls}
        self.by_code = {control.code.casefold(): control for control in controls}
        # IT and OT twins share a name: the lowest id answers, every time (the snapshot counts a twin as the
        # same control when it judges coverage).
        self.by_name: dict[str, LibraryControl] = {}
        for control in sorted(controls, key=lambda row: row.control_id):
            self.by_name.setdefault(control.name.casefold(), control)

    def row_named_by(self, ref: ControlRef) -> LibraryControl | None:
        """The row `ref` names, strongest key first; ValueError when its id and code name two rows. An id is
        decisive: an id no active row has is unknown, even when the code beside it names a live row."""
        by_code = self.by_code.get(ref.control_code.casefold()) if ref.control_code else None
        if ref.control_id is not None:
            by_id = self.by_id.get(ref.control_id)
            if by_id is not None and by_code is not None and by_id is not by_code:
                raise ValueError(
                    RemediationMessage.CONTROL_ID_CODE_DISAGREE.format(
                        control_id=ref.control_id, control_code=ref.control_code
                    )
                )
            return by_id
        return by_code or self.by_name.get((ref.control_name or "").casefold())


def resolve_controls(
    refs: Sequence[ControlRef],
    controls: Sequence[LibraryControl],
    field: str,
    strict: bool,
    stored: bool = False,
    retired: Sequence[LibraryControl] = (),
) -> ResolvedControls:
    """`refs` resolved against `controls` (the active library). `field` names the request field in a 422.
    `stored`: references a request already passed (a regenerate rebuilds from them): a library change since is
    noted, never refused, as the caller cannot fix what it did not send now. `retired`: the library's other
    controls; tolerant mode sends one a register names by its name and domain (owner, 2026-10-11)."""
    index, retired_index = _ControlIndex(controls), _ControlIndex(retired)
    kept: dict[int, LibraryControl] = {}
    texts: dict[str, str] = {}  # case-blind, the first spelling kept
    notes: list[str] = []
    errors: list[dict[str, str]] = []
    for position, ref in enumerate(refs):
        where = f"body.{field}[{position}]"
        try:
            row = _row_or_change(index, ref, stored, notes)
        except ValueError as exc:
            errors.append({"field": where, "message": str(exc)})
            continue
        if row is None and strict:
            message = RemediationMessage.CONTROL_UNKNOWN.format(reference=_named(ref))
            errors.append({"field": where, "message": message})
        elif row is None:
            _keep_unknown(ref, retired_index, texts, notes)
        elif row.control_id in kept and strict:
            message = RemediationMessage.CONTROL_REPEATED.format(reference=_named(ref))
            errors.append({"field": where, "message": message})
        else:
            kept.setdefault(row.control_id, row)
    if errors:
        raise Invalid(RemediationMessage.REFERENCES_INVALID, errors=errors)
    return ResolvedControls(tuple(kept.values()), tuple(texts.values()), tuple(notes))


def _row_or_change(
    index: _ControlIndex, ref: ControlRef, stored: bool, notes: list[str]
) -> LibraryControl | None:
    """The row `ref` names; ValueError when its id and code name two rows, unless the reference is stored:
    then the library changed since, which is noted and the entry read as unknown."""
    try:
        return index.row_named_by(ref)
    except ValueError:
        if not stored:
            raise
        notes.append(SnapshotWarning.REGISTER_REF_CHANGED.format(reference=_named(ref)))
        return None


def _keep_unknown(ref: ControlRef, retired: _ControlIndex, texts: dict[str, str], notes: list[str]) -> None:
    """Tolerant mode, an entry no active row has: a retired row (by id, else code) goes to the AI by code,
    name and domain; an id alone that no row has is a note only (a database id never reaches the AI);
    anything else stays as the person wrote it."""
    if ref.control_id is not None:
        row = retired.by_id.get(ref.control_id)
    else:
        row = retired.by_code.get((ref.control_code or "").casefold())
    if row is not None:
        domain = f" ({row.domain})" if row.domain else ""
        text = f"{row.code} — {row.name}{domain}{Remediation.RETIRED_MARK}"
        notes.append(SnapshotWarning.REGISTER_CONTROL_RETIRED.format(code=row.code))
    elif not (ref.control_code or ref.control_name):
        notes.append(SnapshotWarning.REGISTER_ID_UNKNOWN.format(control_id=ref.control_id))
        return
    else:
        text = _named(ref)
    texts.setdefault(text.casefold(), text)


def _named(ref: ControlRef) -> str:
    """How an entry reads in a 422 or in the register's baseline: "code — name" when both say something, else
    the one given; an id alone reads "control_id 1483", so a reviewer can still look it up."""
    code, name = ref.control_code or "", ref.control_name or ""
    if code and name and code != name:
        return f"{code} — {name}"
    if code or name:
        return name or code
    return f"control_id {ref.control_id}"
