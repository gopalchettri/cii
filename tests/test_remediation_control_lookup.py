"""A plan job reads the control library once: the register's controls are looked up in one pass for its
identified controls and its alternatives, and the controls matched are what they were."""

from collections import Counter
from typing import Any

import pytest

from app.core.constants import ImplementationStatus, PlanWarning
from app.domain.remediation import plan
from app.domain.remediation.plan import (
    assess_alternatives,
    assess_controls,
    list_affected_systems,
    resolve_control_refs,
)
from app.models.library.library import LibraryControl
from tests.planner_samples import CONTEXT
from tests.test_remediation_plan import LIBRARY, _item, _refs, _register

PARTIAL = ImplementationStatus.PARTIALLY_IMPLEMENTED
#: In no register, mapped item or alternative: only a library scan reads it.
UNNAMED = LibraryControl(99, "CII-CID-99", "OT", "Physical", "Badge access logging", "Logs badge use.")
#: By code, by twin name, by a "CODE · Name" label, by id, unknown, and a name two controls share.
EXISTING = [
    "CII-CID-1",
    {"control_name": "vendor remote access approval"},
    "CII-CID-3 · Email filtering",
    {"control_id": 4},
    "Quarterly phishing simulation",
    {"control_name": "Access review"},
]
SAME_NAME = (
    LibraryControl(41, "C-41", "IT", None, "Access review", "Quarterly review of user access"),
    LibraryControl(42, "C-42", "IT", None, "Access review", "Review of firewall access rules"),
)


def _library() -> tuple[LibraryControl, ...]:
    """A new library tuple each call, as a new library version is."""
    return (*LIBRARY, *SAME_NAME, UNNAMED)


def _job(controls: tuple[LibraryControl, ...]) -> tuple[Any, Any, Any]:
    """What a plan job assesses: the identified controls, then the alternatives found, on one library."""
    stored = _register(existing_controls=EXISTING, supporting_systems_applicable_to_existing_controls=[321])
    affected = list_affected_systems(CONTEXT, stored)
    categories = CONTEXT.system_categories()
    items = [_item(1), _item(5), _item(6)]
    identified, warnings = assess_controls(items, stored, controls, affected, categories)
    found = [(controls[2], 61.0), (controls[3], 55.0), (controls[4], 50.0)]
    alternatives = assess_alternatives(found, stored, controls, affected, categories)
    return identified, warnings, alternatives


@pytest.fixture
def described(monkeypatch: pytest.MonkeyPatch) -> Counter[int]:
    """How many times each library row's text is read."""
    seen: Counter[int] = Counter()
    real = plan.describe_control

    def counting(control: LibraryControl) -> str:
        seen[control.control_id] += 1
        return real(control)

    monkeypatch.setattr(plan, "describe_control", counting)
    return seen


def test_a_plan_job_scans_the_library_once(described: Counter[int]) -> None:
    """Six register controls, two passes: the unnamed row is read as often as by one lookup, not twelve."""
    resolve_control_refs([], _library())
    one_scan = described[UNNAMED.control_id]
    described.clear()
    _job(_library())
    assert one_scan > 0 and described[UNNAMED.control_id] == one_scan


def test_the_controls_matched_are_unchanged() -> None:
    """Code, twin name, label and id match (the twins as one), on the SCADA server of two systems; the
    unknown and the shared name warn, in the register's order."""
    identified, warnings, alternatives = _job(_library())
    assert [(r["control_code"], r["implementation_status"]) for r in identified] == [
        ("CII-CID-1", PARTIAL),
        ("CII-CID-5", PARTIAL),
        ("CII-CID-6", ImplementationStatus.NOT_IMPLEMENTED),
    ]
    assert warnings == [
        PlanWarning.CONTROL_UNMATCHED.format(reference="Quarterly phishing simulation"),
        PlanWarning.CONTROL_UNMATCHED.format(reference="Access review"),
    ]
    assert [(r["control_code"], r["implementation_status"]) for r in alternatives] == [
        ("CII-CID-3", PARTIAL),
        ("CII-CID-4", PARTIAL),
        ("CII-CID-5", PARTIAL),
    ]
    rows, unresolved = resolve_control_refs(_refs(*EXISTING), _library())
    assert [row.control_id for row in rows] == [1, 2, 3, 4]
    assert [position for position, _ in unresolved] == [4, 5]
