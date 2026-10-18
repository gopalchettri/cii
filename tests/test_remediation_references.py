"""Control references resolved against the library (BLUEPRINT M05 L3, BUILD_PLAN S46): strict for a
hand-written scenario's controls, tolerant for the register's existing controls. In memory."""

from typing import Any

import pytest

from app.core.constants import SnapshotWarning
from app.core.exceptions import Invalid
from app.domain.remediation.references import resolve_controls
from app.models.library import LibraryControl
from app.models.remediation_requests import ControlRef

LIBRARY = (
    LibraryControl(1, "CII-CID-1", "OT", "Integrity", "Firmware integrity verification", "Signed firmware."),
    LibraryControl(2, "CII-CID-2", "IT", "Email", "Phishing protection", "Filters phishing."),
    LibraryControl(3, "CII-CID-3", None, "Access", "Vendor remote-access approval", "Approves sessions."),
)


def _refs(*entries: Any) -> list[ControlRef]:
    return [ControlRef.model_validate(entry) for entry in entries]


def test_id_then_code_then_name_each_case_blind() -> None:
    resolved = resolve_controls(
        _refs({"control_id": 1}, "cii-cid-2", {"control_name": "VENDOR remote-access approval"}),
        LIBRARY,
        "manual_scenario.mapped_controls",
        strict=True,
    )
    assert [control.control_id for control in resolved.controls] == [1, 2, 3] and resolved.texts == ()


def test_strict_refuses_every_unknown_or_repeated_entry_at_once() -> None:
    """A hand-written scenario's controls become its controls: an unknown code, an id no active row has (even
    beside a live code), and a second name for one control are all listed in one 422."""
    with pytest.raises(Invalid) as refused:
        resolve_controls(
            _refs(
                "CII-CID-99", {"control_id": 99, "control_code": "CII-CID-1"}, "CII-CID-2", {"control_id": 2}
            ),
            LIBRARY,
            "manual_scenario.mapped_controls",
            strict=True,
        )
    assert refused.value.errors is not None
    assert [error["field"] for error in refused.value.errors] == [
        "body.manual_scenario.mapped_controls[0]",
        "body.manual_scenario.mapped_controls[1]",
        "body.manual_scenario.mapped_controls[3]",
    ]


def test_an_id_and_a_code_naming_two_rows_are_refused_in_both_modes() -> None:
    for strict in (True, False):
        with pytest.raises(Invalid):
            resolve_controls(
                _refs({"control_id": 1, "control_code": "CII-CID-2"}), LIBRARY, "f", strict=strict
            )


def test_tolerant_keeps_the_unknown_as_text_and_drops_a_repeat() -> None:
    """The register's baseline: free text and retired rows stay as readable text; one control named twice,
    by id and by code, counts once. An id alone that no row has is a note for the reviewer, never text: a
    database id never reaches the AI (review S56)."""
    resolved = resolve_controls(
        _refs(
            {"control_id": 1},
            "CII-CID-1",
            "Quarterly phishing simulation",
            "quarterly PHISHING simulation",
            {"control_id": 99},
            {"control_code": "X-1", "control_name": "Old control"},
        ),
        LIBRARY,
        "existing_controls",
        strict=False,
    )
    assert [control.control_id for control in resolved.controls] == [1]
    assert resolved.texts == ("Quarterly phishing simulation", "X-1 — Old control")
    assert resolved.notes == (SnapshotWarning.REGISTER_ID_UNKNOWN.format(control_id=99),)


def test_a_stored_register_notes_a_library_change_and_never_refuses() -> None:
    """A regenerate rebuilds from references a request already passed (review S56): an id and a code that name
    two rows only since then are kept as text with a note, as the caller cannot fix what it did not send."""
    refs = _refs({"control_id": 1, "control_code": "CII-CID-2"})
    with pytest.raises(Invalid):
        resolve_controls(refs, LIBRARY, "existing_controls", strict=False)
    resolved = resolve_controls(refs, LIBRARY, "existing_controls", strict=False, stored=True)
    assert (resolved.controls, resolved.texts) == ((), ("CII-CID-2",))
    assert resolved.notes == (SnapshotWarning.REGISTER_REF_CHANGED.format(reference="CII-CID-2"),)


def test_a_name_shared_by_it_and_ot_twins_always_resolves_to_the_lowest_id() -> None:
    """S46 review: twins share a name; the answer never depends on the library's row order."""
    twins = (
        LibraryControl(9, "CII-CID-9", "OT", "D", "Backup policy", "Keeps backups."),
        LibraryControl(4, "CII-CID-4", "IT", "D", "Backup policy", "Keeps backups."),
    )
    for library in (twins, twins[::-1]):
        resolved = resolve_controls(_refs({"control_name": "Backup policy"}), library, "f", strict=True)
        assert [control.control_id for control in resolved.controls] == [4]


RETIRED = (
    LibraryControl(77, "CII-CID-077", None, "Integrity", "Firmware integrity review", None),
    LibraryControl(78, "CII-CID-078", None, None, "Old badge audit", None),
)


def test_a_retired_register_control_reaches_the_ai_by_name_and_domain() -> None:
    """Owner, 2026-10-11: the organisation still has a control the library retired; the AI gets its code,
    name and domain (the domain only when the library has one), never a bare number. A number no control
    has, current or retired, stays a note. A hand-written scenario's own controls still refuse it: a plan
    never recommends a retired control."""
    refs = _refs({"control_id": 77}, "cii-cid-078", {"control_id": 4040})
    resolved = resolve_controls(refs, LIBRARY, "existing_controls", strict=False, retired=RETIRED)
    assert resolved.texts == (
        "CII-CID-077 — Firmware integrity review (Integrity), retired in the library",
        "CII-CID-078 — Old badge audit, retired in the library",
    )
    assert resolved.notes == (
        SnapshotWarning.REGISTER_CONTROL_RETIRED.format(code="CII-CID-077"),
        SnapshotWarning.REGISTER_CONTROL_RETIRED.format(code="CII-CID-078"),
        SnapshotWarning.REGISTER_ID_UNKNOWN.format(control_id=4040),
    )
    with pytest.raises(Invalid):
        resolve_controls(_refs({"control_id": 77}), LIBRARY, "f", strict=True, retired=RETIRED)
