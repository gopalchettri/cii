"""A hand-written scenario's acting attacker (FR-THR-07), ranked by the scenario as saved: "<type>:
<threat>. <the person's scenario>", as a generated threat's, the person's words redacted (they go to the
embedding model). Read by its plan job, since a request makes no AI call."""

from typing import Any

from app.core.constants import ActorRole, LibraryStatus
from app.core.redaction import redact
from app.models.scenario.plan import PlannedActor
from app.search.snapshot import LibrarySnapshot, linked_actors_by_type


def manual_attacker(
    snapshot: LibrarySnapshot, content: dict[str, Any]
) -> tuple[tuple[PlannedActor, ...], bool]:
    """(the acting attacker, whether it is only the closest match), ranked with one embedding call: the top of
    its threat's linked actors, else its type's, else the whole library's (closest)."""
    threat, library = content.get("threat") or {}, snapshot.library.threat_library
    by_threat = {row.catalogue_id: row.linked_actors for row in library.threats}
    active = threat.get("library_status") == LibraryStatus.ACTIVE
    own = by_threat.get(threat.get("library_id") or 0, ()) if active else ()
    linked = own or linked_actors_by_type(library).get(threat.get("type_id") or 0, ())  # 0: a new type
    candidates = linked or library.actors
    if not candidates:
        return (), False
    type_name, name = redact(threat.get("type") or ""), redact(threat.get("name") or "")
    query = f"{type_name}: {name}. {redact(content.get('statement') or '')}".strip()
    allowed = {actor.actor_id for actor in candidates}
    (found,) = snapshot.find_actors([query], top_k=len(library.actors), allowed_ids=[allowed])
    acting = found[0][0] if found else candidates[0]
    return (PlannedActor(acting.actor_id, acting.name, ActorRole.ACTING),), not linked
