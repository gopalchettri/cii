"""External intelligence: the numbers of the refresh's safety rules (what a feed may retire, how long old
versions are kept)."""

from typing import Final


class IntelOperationsLimits:
    #: A complete fetch must still hold at least this share of the source's current records before the
    #: ones it lacks are retired. A feed cut short (5 entries instead of 1500) is a failed fetch, never a
    #: mass removal; a real shrink of up to half passes. Remedy for a legitimate bigger removal: revoke the
    #: source and approve it again (POST /v1/tsg/intel/sources/{source}/revoke, then .../approve).
    MIN_RETIRE_RATIO: Final = 0.5
    RETIRED_VERSION_DAYS: Final = 90  # a version no longer current is deleted this long after it stopped
