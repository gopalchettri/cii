"""The library's curation rules: which accepted scenario's threat may be proposed, what the library's answer
means, and the key that makes a curator's decisions idempotent."""

import hashlib
import json
from typing import Any

from app.core.constants import ConflictReason, Decision, PromotionOutcome, ResolveOutcome, ReviewMessage
from app.core.exceptions import Conflict

#: tsg_ResolveThreat's answer as a promotion outcome; any other answer: the library has it already.
_PROMOTION_OUTCOME: dict[str, PromotionOutcome] = {
    ResolveOutcome.CREATED_PENDING: PromotionOutcome.INSERTED,
    ResolveOutcome.CURATOR_REJECTED: PromotionOutcome.CURATOR_REJECTED,
}


def decision_operation_key(approve: list[int], reject: list[int], decided_by: str) -> str:
    """The operation key of one set of curator decisions: the same decisions sent again share it."""
    payload = {"approve": approve, "reject": reject, "decided_by": decided_by}
    return f"decide:{hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()}"


def accepted_ai_threat_key(scenario: dict[str, Any], scenario_id: str) -> str | None:
    """The plan key of an accepted scenario's AI-written threat, None for a library threat; 409 when the
    scenario is not accepted."""
    if scenario.get("decision") != Decision.ACCEPTED:
        message = ReviewMessage.SCENARIO_NOT_ACCEPTED.format(scenario_id=scenario_id)
        raise Conflict(message, reason=ConflictReason.SCENARIO_NOT_ACCEPTED)
    reference = (scenario.get("content") or {}).get("threat") or {}
    return reference["key"] if reference.get("ai_generated") and reference.get("key") else None


def threat_to_promote(threat: dict[str, Any] | None, scenario_id: str) -> dict[str, Any]:
    """The threat to propose; 409 nothing_to_promote when the scenario has none."""
    if threat is None:
        message = ReviewMessage.NOTHING_TO_PROMOTE.format(scenario_id=scenario_id)
        raise Conflict(message, reason=ConflictReason.NOTHING_TO_PROMOTE)
    return threat


def scenario_actor_ids(scenario: dict[str, Any]) -> tuple[int, ...]:
    """The library ids of the scenario's actors, proposed with its threat."""
    actors = (scenario.get("content") or {}).get("actors") or []
    return tuple(actor["id"] for actor in actors if actor.get("id"))


def promotion_outcome(resolved: ResolveOutcome | str) -> PromotionOutcome:
    """The library's answer to a proposal as the promotion outcome."""
    return _PROMOTION_OUTCOME.get(resolved, PromotionOutcome.EXISTING)
