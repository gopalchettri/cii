"""The register half of a plan version's frozen input (BLUEPRINT M11 R4; BUILD_PLAN S48; v1
treatment_input.py): the register's controls resolved against the library (tolerant), its numbers, the
mitigation window, the echo-only fields (never sent to the AI) and the three consistency advisories. A
regenerate rebuilds it from the stored register data, so what code derives (library matches, advisories) is
always current. Pure, no IO."""

from collections.abc import Sequence
from datetime import date
from decimal import MAX_PREC, ROUND_HALF_UP, Decimal, localcontext
from typing import Any

from app.core.constants import Remediation, SnapshotWarning
from app.core.redaction import redact
from app.engine.remediation.references import resolve_controls
from app.models.library import LibraryControl
from app.models.remediation_requests import RegisterData


def clip(text: str | None) -> str | None:
    """THE ONE DOOR for free text entering a snapshot: redacted, then cut at Remediation.TEXT_MAX_CHARS and
    marked, so a cut is never silent and never crowds the register's own facts out of the prompt."""
    if text is None:
        return None
    cleaned = redact(text)
    if len(cleaned) <= Remediation.TEXT_MAX_CHARS:
        return cleaned
    return cleaned[: Remediation.TEXT_MAX_CHARS] + Remediation.TRUNCATED_MARK


def register_half(
    register: RegisterData,
    controls: Sequence[LibraryControl],
    today: date,
    stored: bool = False,
    retired: Sequence[LibraryControl] = (),
) -> dict[str, Any]:
    """{register_controls, applied_to_all_subsystems, applied_to_all_subsystems_justification,
    risk_assessment, register, warnings}: everything the plan's input takes from the register. `stored`: the
    register a regenerate rebuilds from (a library change since is a warning, never a 422)."""
    refs = register.existing_controls or []
    resolved = resolve_controls(
        refs, controls, "existing_controls", strict=False, stored=stored, retired=retired
    )
    applied = register.existing_controls_all_subsystems
    return {
        "register_controls": [
            {
                "control_id": control.control_id,
                "control_code": control.code,
                "control_name": control.name,
                "domain": control.domain,
                "control_description": clip(control.description),
            }
            for control in resolved.controls
        ]
        + [clip(text) for text in resolved.texts],
        "applied_to_all_subsystems": applied,
        # A justification of a Yes/No nobody gave justifies nothing: left out rather than orphaned.
        "applied_to_all_subsystems_justification": (
            clip(register.existing_controls_all_subsystems_justification) if applied is not None else None
        ),
        "risk_assessment": _assessment(register),
        "register": _echo(register),
        "warnings": _advisories(register, today) + list(resolved.notes),
    }


def _assessment(register: RegisterData) -> dict[str, Any]:
    """The register's numbers and level as the AI reads them; free text through the one door."""
    return {
        "likelihood_rating": _number(register.likelihood_rating),
        "impact_rating": _number(register.impact_rating),
        "final_risk_rating": _number(register.final_risk_rating),
        "risk_level": clip(register.risk_level),
        "impacted_business_division": clip(register.impacted_business_division),
        "assessment_window": _window(register),
    }


def _echo(register: RegisterData) -> dict[str, Any]:
    """Echo-only facts: copied into the plan by code, never shown to the AI (the risk owner is a person)."""
    identified = register.risk_identification_date
    return {
        "risk_identification_date": identified.isoformat() if identified is not None else None,
        "risk_owner": clip(register.risk_owner),
        "impacted_business_division": clip(register.impacted_business_division),
    }


def _window(register: RegisterData) -> dict[str, Any] | None:
    """The window the whole plan must fit, with its length in days (inclusive: 1 Oct to 31 Dec is 92), so
    the AI and the scheduler reason over one number."""
    start, end = register.mitigation_start_date, register.mitigation_end_date
    if start is None or end is None:
        return None
    return {
        "timeline_start_date": start.isoformat(),
        "timeline_end_date": end.isoformat(),
        "total_days": (end - start).days + 1,
    }


def _number(value: Decimal | None) -> int | float | None:
    """A rating as a JSON number, an int when whole: the prompt cites final_risk_rating verbatim, so 20 must
    never become 20.0. Exact: the request allows at most 15 significant digits."""
    if value is None:
        return None
    return int(value) if value == value.to_integral_value() else float(value)


def _advisories(register: RegisterData, today: date) -> list[str]:
    """Flags, never blocks: the register owns its numbers, but a contradiction the AI will cite must reach
    the reviewer. The product is compared at the final rating's own scale (two 4-place scores multiply to 8
    places, which the register cannot write), exactly (MAX_PREC: no rounding of the product)."""
    warnings = []
    likelihood, impact, final = (
        _canonical(register.likelihood_rating),
        _canonical(register.impact_rating),
        _canonical(register.final_risk_rating),
    )
    if likelihood is not None and impact is not None and final is not None:
        with localcontext(prec=MAX_PREC):
            product = likelihood * impact
            mismatch = final != product.quantize(final, rounding=ROUND_HALF_UP)
        if mismatch:
            warnings.append(
                SnapshotWarning.RATING_MISMATCH.format(
                    final=final, likelihood=likelihood, impact=impact, product=product
                )
            )
    if final is None and not register.risk_level:
        warnings.append(SnapshotWarning.NOT_CALIBRATED)
    end = register.mitigation_end_date
    if end is not None and end < today:
        warnings.append(SnapshotWarning.WINDOW_OVER.format(end=end.isoformat()))
    return warnings


def _canonical(value: Decimal | None) -> Decimal | None:
    """The value's own scale, never the way it was spelt: "20.00" compares as 20 (scale 0), so a correctly
    rounded register is not flagged."""
    if value is None:
        return None
    return value.quantize(Decimal(1)) if value == value.to_integral_value() else value.normalize()
