"""A hand-written scenario made and saved, with no AI call (G262, owner 2026-10-15: with many users at once an
AI step inside the request answered 503): the asset checked and its facts frozen as a run start does; the
threat resolved in memory; the person's controls resolved strictly; the run and its scenario saved under
key-derived ids. Its attackers (and the library proposal of a new wording, which links a new type to them)
are found by its plan job (app/worker/plan_inputs.py), where a busy AI only means waiting. Anything refused
saves nothing."""

from datetime import UTC, datetime
from typing import Any

from app.core.constants import ConflictReason, ErrorCode, PlanMessage, SessionMessage
from app.core.exceptions import Conflict, Unavailable
from app.core.tracing import traced
from app.data_access.asset_context import AssetContextRepository
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
from app.models.api_clients import Principal
from app.models.remediation_requests import PlanRequest
from app.search.library_cache import LibraryService
from app.services.audit import caller_actor
from app.services.scenarios.context import freeze_context


class ManualScenarios:
    def __init__(
        self,
        asset_contexts: AssetContextRepository,
        library: LibraryService,
        records: ManualRecords,
        counts: RunCounts,
    ) -> None:
        self._asset_contexts, self._library = asset_contexts, library
        self._records, self._counts = records, counts

    @traced("remediation.manual_scenario")
    def save(self, principal: Principal, body: PlanRequest, key: str, request_hash: str) -> dict[str, Any]:
        """The scenario as saved (accepted by its writer), its run beside it. Everything a 422 could refuse is
        checked before the first write; no AI is called."""
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
        if not loaded.threat_library.actors:  # in memory: its plan job could never name an attacker
            raise Unavailable(PlanMessage.ACTOR_LIBRARY_EMPTY, reason=ErrorCode.ACTOR_LIBRARY_EMPTY)
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
        now, ids = datetime.now(UTC), manual_ids(principal.entity_id, key)
        run = manual_run_record(principal, manual, ids[0], key, request_hash, context, now)
        saved = given_controls(controls.controls, now)
        scenario = manual_scenario_record(
            principal, manual, ids, identity, context, saved, caller_actor(principal), now
        )
        if self._records.save(run, scenario) is not None:  # another request took the key meanwhile
            message = SessionMessage.IDEMPOTENCY_KEY_CONFLICT
            raise Conflict(message, reason=ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
        self._counts.refresh(ids[0])
        return scenario
