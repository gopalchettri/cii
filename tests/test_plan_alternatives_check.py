"""The plan alternatives check's own logic (scripts/plan_alternatives_check.py) on hand-made controls: the
register's controls the search missed, each once. The test names the mutation it catches."""

import importlib
import sys
from pathlib import Path

from app.models.library.library import LibraryControl

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
try:
    check = importlib.import_module("plan_alternatives_check")
finally:
    sys.path.remove(str(REPO / "scripts"))

MFA = LibraryControl(
    242, "CID-0242", "OT", "Identification & Authentication", "Multi-Factor Authentication", "MFA."
)
MFA_TWIN = LibraryControl(
    1242, "CID-1242", "IT", "Identification & Authentication", "Multi-Factor Authentication", "MFA."
)
MALWARE = LibraryControl(195, "CID-0195", "OT", "Endpoint Security", "Anti-Malware", "Malware.")


def test_the_registers_missed_controls_are_offered_once_never_a_taken_one_or_its_twin() -> None:
    """Mutation caught: comparing ids alone offers CID-1242, the IT twin of the identified MFA."""
    register = {
        "existing_controls": [
            {"control_code": "CID-0242"},  # identified
            {"control_code": "CID-1242"},  # its twin
            {"control_name": "Anti-Malware"},
            {"control_code": "CID-0195"},  # the same control again
            {"control_code": "CID-9999"},  # not in the library: assess_controls warns
        ]
    }
    library = [MFA, MFA_TWIN, MALWARE]
    assert check.register_controls_not_found(register, library, [242]) == [(MALWARE, None)]
