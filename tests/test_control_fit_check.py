"""The control fit check's own logic (scripts/control_fit_check.py) on hand-made controls and marks: the AI's
codes read even with their names, each line's best control kept once, and the fit counted. Each test names the
mutation it catches."""

import importlib
import sys
from pathlib import Path

from app.models.library.library import LibraryControl

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
try:
    check = importlib.import_module("control_fit_check")
finally:
    sys.path.remove(str(REPO / "scripts"))

MFA = LibraryControl(
    242, "CID-0242", "OT", "Identification & Authentication", "Multi-Factor Authentication", "MFA."
)
MFA_TWIN = LibraryControl(
    1242, "CID-1242", "IT", "Identification & Authentication", "Multi-Factor Authentication", "MFA."
)
LOCKOUT = LibraryControl(255, "CID-0255", "OT", "Identification & Authentication", "Account Lockout", "Lock.")
MALWARE = LibraryControl(195, "CID-0195", "OT", "Endpoint Security", "Anti-Malware", "Malware.")


def test_the_ais_codes_are_read_with_their_names_once_each_and_capped() -> None:
    """Mutation caught: matching the whole answer ("CODE Name") instead of its code drops every pick."""
    answers = [
        "CID-0242 Multi-Factor Authentication",
        "cid-0255",
        "CID-0242",
        "CID-9999 Made Up",
        "",
        "CID-0195",
    ]
    assert check.chosen_codes(answers, [MFA, LOCKOUT, MALWARE], most=2) == [MFA, LOCKOUT]


def test_each_line_keeps_its_best_control_never_one_or_its_twin_twice() -> None:
    """Mutation caught: keeping a line's best even when it or its twin is already kept (MFA twice)."""

    def score(line: str, texts: list[str]) -> list[float]:
        return [90.0 if line.split()[0].lower() in text.lower() else 1.0 for text in texts]

    pool = [MFA, MFA_TWIN, LOCKOUT, MALWARE]
    kept = check.best_per_line(
        ["multi-factor log-ins", "multi-factor again", "lock accounts"], pool, score, most=5
    )
    assert kept[0] in (MFA, MFA_TWIN) and LOCKOUT in kept and len(kept) == 3
    texts = [check.name_match_key(check.describe_control(control)) for control in kept]
    assert len(set(texts)) == len(texts)  # no control, nor its IT/OT twin, twice


def test_the_fit_counts_partly_as_half_over_the_marked_controls() -> None:
    """Mutation caught: counting an unmarked control as "no" (the fit would fall to 50%)."""
    rows = [
        {"lists": {"today": [MFA, LOCKOUT, MALWARE]}, "marks": {"CID-0242": "fits", "CID-0255": "partly"}}
    ]
    fit = check.fit_of(rows, "today")
    assert (fit["fits"], fit["partly"], fit["fit"], fit["count"]) == (0.5, 0.5, 0.75, 3)
