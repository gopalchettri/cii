"""Before an evidence story is written (G229, owner 2026-10-13: with external intelligence on, "the final
output contains zero scenarios without qualifying evidence. Missing evidence must result in an explicit
failure ... never a silent omission or fabricated evidence"; no AI call is spent to find that out): a path
whose threat's search (and its alternative searches) settled with no usable entry fails for good, its reason
recorded, before any write call; one whose search could not be made is an outage, retried like any, never
written without evidence. Pure."""

from typing import Any

from app.core.constants import ErrorCode, ErrorMessage, EvidenceSearchFailure
from app.core.exceptions import Unavailable
from app.models.writing import PathFailure


def evidence_problem(threat: dict[str, Any]) -> PathFailure | Unavailable | None:
    """Why this threat's story cannot be written yet (None: its evidence is there). `threat`: the plan's,
    after EvidenceAtWrite.attach."""
    search = threat.get("intel_search")
    if search is None or search.get("failure") is not None or search.get("snapshot_id") is None:
        failure = (search or {}).get("failure") or EvidenceSearchFailure.NO_SNAPSHOT
        return Unavailable(ErrorMessage.EVIDENCE_SEARCH_UNAVAILABLE.format(reason=failure))
    if not threat.get("evidence"):
        searches = 1 + len(search.get("attempts") or ())
        message = ErrorMessage.EVIDENCE_NOT_FOUND.format(searches=searches)
        return PathFailure(ErrorCode.EVIDENCE_NOT_FOUND, message, final=True)
    return None
