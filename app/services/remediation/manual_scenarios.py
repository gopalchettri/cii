"""A hand-written scenario made and saved: the asset checked
and its facts frozen as a run start does; the threat resolved in memory and a new wording
proposed to the library, pending a curator; the acting attacker and its alternates ranked among
the type's linked attackers (none linked: the closest, flagged; no AI fit check, the person described the
attack); the person's controls resolved strictly ; the run and its scenario saved under
key-derived ids. Anything refused saves nothing."""

import dataclasses
from datetime import UTC, datetime
from typing import Any

from app.ai import RerankModel
from app.core.constants import (
    AuditAction,
    AuditTarget,
    ConflictReason,
    ErrorCode,
    LibrarySource,
    LibraryStatus,
    PlanMessage,
    ResolveOutcome,
    SessionMessage,
)
from app.core.exceptions import Conflict, Unavailable
from app.core.redaction import redact
from app.core.tracing import traced
from app.data_access.asset_context import AssetContextRepository
from app.data_access.library import LibraryRepository
from app.data_access.manual_scenarios import ManualRecords
from app.data_access.run_counts import RunCounts
from app.engine.remediation.manual_records import (
    given_controls,
    manual_ids,
    manual_run_record,
    manual_scenario_record,
)
from app.engine.remediation.references import resolve_controls
from app.engine.remediation.threat_identity import resolve_threat
from app.engine.scenarios.threat_list.attacker_assignment import AttackerAssigner
from app.models.api_clients import Principal
from app.models.library import ThreatProposal
from app.models.remediation import ThreatIdentity
from app.models.remediation_requests import ManualScenario, PlanRequest
from app.models.threats import PlannedActor, PlannedThreat
from app.search.library_cache import LibraryService
from app.search.service import LibrarySearch
from app.services.audit import audit_target, caller_actor, record_audit
from app.services.scenarios.context import freeze_context

#: (the acting actor then its alternates, whether the acting one is only the closest)
Actors = tuple[tuple[PlannedActor, ...], bool]


class ManualScenarios:
    def __init__(  # noqa: PLR0913 — the stores and libraries a hand-written scenario touches
        self,
        asset_contexts: AssetContextRepository,
        library: LibraryService,
        threat_writes: LibraryRepository,
        search: LibrarySearch,
        records: ManualRecords,
        counts: RunCounts,
        rerank: RerankModel,  # the attacker threshold's scores (ACTOR_SIMILARITY_THRESHOLD)
    ) -> None:
        self._asset_contexts, self._library, self._threat_writes = asset_contexts, library, threat_writes
        self._search, self._records, self._counts, self._rerank = search, records, counts, rerank

    @traced("remediation.manual_scenario")
    def save(self, principal: Principal, body: PlanRequest, key: str, request_hash: str) -> dict[str, Any]:
        """The scenario as saved (accepted by its writer), its run beside it. Everything a 422 could refuse is
        checked before the first write (the library proposal, then the run and the scenario)."""
        manual = body.manual_scenario
        assert manual is not None
        rows = self._asset_contexts.read(
            principal.entity_id,
            manual.asset_id,
            manual.supporting_system_ids,
            manual.service_id,
            manual.sector_id,
            manual.subsector_id,
        )
        context = freeze_context(manual, rows)
        self._library.check_library_once()  # a row a curator added in the last minute is seen
        loaded = self._library.get_loaded_libraries()
        identity = resolve_threat(loaded.threat_library, manual)
        # The register too: a refused one (an id and a code naming two rows) must save nothing, or a corrected
        # retry under the same key would meet its orphaned scenario (409).
        resolve_controls(
            body.existing_controls or [], loaded.control_library, "existing_controls", strict=False
        )
        refs = manual.mapped_controls or []
        controls = resolve_controls(
            refs, loaded.control_library, "manual_scenario.mapped_controls", strict=True
        )
        actors = self._actors(identity, manual)
        if identity.status is None:
            identity = self._propose(principal, identity, actors)
        now, ids = datetime.now(UTC), manual_ids(principal.entity_id, key)
        run = manual_run_record(principal, manual, ids[0], key, request_hash, context, now)
        saved = given_controls(controls.controls, now)
        scenario = manual_scenario_record(principal, manual, ids, identity, actors, context, saved, now)
        if self._records.save(run, scenario) is not None:  # another request took the key meanwhile
            message = SessionMessage.IDEMPOTENCY_KEY_CONFLICT
            raise Conflict(message, reason=ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
        self._counts.refresh(ids[0])
        return scenario

    def _actors(self, identity: ThreatIdentity, manual: ManualScenario) -> Actors:
        """Ranked against "<type>: <threat>. <the person's scenario>" (FR-THR-07), as a generated threat's."""
        snapshot = self._search.snapshot()
        if not snapshot.library.threat_library.actors:
            raise Unavailable(PlanMessage.ACTOR_LIBRARY_EMPTY, reason=ErrorCode.ACTOR_LIBRARY_EMPTY)
        planned = PlannedThreat(
            key="manual",
            catalogue_id=identity.catalogue_id if identity.status == LibraryStatus.ACTIVE else None,
            type_id=identity.type_id or 0,  # a new type links no actor yet: the closest acts
            type_name=redact(identity.type_name),  # the person's words go to the embedding model: redacted
            name=redact(identity.threat_name),
            categories=(identity.category,) if identity.category else (),
            systems=(),
            impact=0,
            confidence=0.0,
            reason=redact(manual.threat_scenario),
        )
        (assigned,) = AttackerAssigner(snapshot, self._rerank).assign_attackers([planned], sector="")
        return assigned.actors, assigned.closest_attacker

    def _propose(self, principal: Principal, identity: ThreatIdentity, actors: Actors) -> ThreatIdentity:
        """A new wording proposed pending a curator; a new type is linked to the attackers chosen
        for it. Audited: the library changed even if saving the scenario then fails."""
        actor_ids = tuple(actor.actor_id for actor in actors[0]) if identity.type_id is None else ()
        proposal = ThreatProposal(
            identity.category,
            identity.type_name,
            identity.threat_name,
            LibrarySource.MANUAL,
            principal.user_id,
            actor_ids,
        )
        proposed = self._threat_writes.propose_threat(proposal)
        active = proposed.outcome == ResolveOutcome.EXISTING_ACTIVE
        target = audit_target(AuditTarget.LIBRARY_THREAT, str(proposed.catalogue_id))
        after = {"threat": identity.threat_name, "type": identity.type_name, "outcome": proposed.outcome}
        record_audit(AuditAction.LIBRARY_PROPOSED, caller_actor(principal), target, after=after)
        return dataclasses.replace(
            identity,
            type_id=proposed.type_id,
            catalogue_id=proposed.catalogue_id,
            status=LibraryStatus.ACTIVE if active else LibraryStatus.PENDING,
        )
