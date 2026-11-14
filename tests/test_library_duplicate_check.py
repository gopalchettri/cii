"""scripts/library_duplicate_check.py: only pairs of one threat type and asset type at or above the floor,
closest first."""

import sys

import numpy as np

from app.models.library.library import LibraryThreat
from tests.checkout import REPO

sys.path.insert(0, str(REPO / "scripts"))

from library_duplicate_check import find_look_alikes  # noqa: E402


def test_only_pairs_of_one_type_and_asset_type_at_or_above_the_floor_are_listed_closest_first() -> None:
    """The laptop library's closest pair (0.81) is one attack's OT and IT variants: not listed."""
    ot = LibraryThreat(1, "Shared, default or stale OT account abuse", 7, "Credential Abuse", (), (), "OT")
    stale = LibraryThreat(2, "Shared, stale or orphaned account misuse", 7, "Credential Abuse", (), (), "IT")
    phishing = LibraryThreat(
        3, "Credential phishing and MFA session theft", 7, "Credential Abuse", (), (), "IT"
    )
    # close words, another type
    flood = LibraryThreat(4, "Shared account flood", 9, "Service Disruption", (), (), "IT")
    vectors = np.array([[1.0, 0.0], [0.81, 0.586], [0.6, 0.8], [0.99, 0.141]])
    pairs = find_look_alikes([ot, stale, phishing, flood], vectors, 0.75)
    assert [(round(cosine, 2), a.catalogue_id, b.catalogue_id) for cosine, a, b in pairs] == [(0.95, 2, 3)]
