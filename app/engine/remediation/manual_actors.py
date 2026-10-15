"""A hand-written scenario's threat as attacker ranking reads it (FR-THR-07), built from the scenario as
saved: "<type>: <threat>. <the person's scenario>", as a generated threat's, the person's words redacted (they
go to the embedding model). Read by its plan job (G262: a request makes no AI call). Pure."""

from typing import Any

from app.core.constants import LibraryStatus, StrideCategory
from app.core.redaction import redact
from app.models.threats import PlannedThreat


def manual_planned_threat(content: dict[str, Any]) -> PlannedThreat:
    """A new type links no actor yet (type id 0): the closest acts, flagged."""
    threat = content.get("threat") or {}
    category = content.get("category")
    active = threat.get("library_status") == LibraryStatus.ACTIVE
    return PlannedThreat(
        key="manual",
        catalogue_id=threat.get("library_id") if active else None,
        type_id=threat.get("type_id") or 0,
        type_name=redact(threat.get("type") or ""),
        name=redact(threat.get("name") or ""),
        categories=(StrideCategory(category),) if category else (),
        systems=(),
        impact=0,
        confidence=0.0,
        reason=redact(content.get("statement") or ""),
    )
