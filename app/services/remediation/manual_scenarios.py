"""A hand-written scenario made and saved, with no AI call (G262, owner 2026-10-15: with many users at once an
AI step inside the request answered 503): the asset checked and its facts frozen as a run start does; the
threat resolved in memory; the person's controls resolved strictly; the run and its scenario saved under
key-derived ids. Its attackers (and the library proposal of a new wording, which links a new type to them)
are found by its plan job (app/worker/plan_inputs.py), where a busy AI only means waiting. Anything refused
saves nothing."""

from datetime import UTC, datetime
from typing import Any

from app.core.constants import ConflictReason, SessionMessage
from app.core.exceptions import Conflict, DuplicateRecord
from app.data_access.library.repository import SqlServerRepository
from app.data_access.scenario.repository import scenario_sessions, scenarios
from app.domain.remediation.manual_records import (
    check_actor_library,
    given_controls,
    manual_ids,
    manual_run_record,
    manual_scenario_record,
)
from app.domain.remediation.references import resolve_controls
from app.domain.remediation.threat_identity import resolve_threat
from app.domain.scenario.plan import freeze_context
from app.models.api_clients import Principal
from app.models.remediation_requests import PlanRequest
from app.search.library_cache import LibraryService
from app.services.audit import caller_actor


class ManualScenarios:
    def __init__(
        self,
        asset_contexts: SqlServerRepository,
        library: LibraryService,
    ) -> None:
        self._asset_contexts, self._library = asset_contexts, library

    def save(self, principal: Principal, body: PlanRequest, key: str, request_hash: str) -> dict[str, Any]:
        """The scenario as saved (accepted by its writer), its run beside it. Everything a 422 could refuse is
        checked before the first write; no AI is called."""
        manual = body.manual_scenario
        assert manual is not None
        rows = self._asset_contexts.get_asset_context(principal.entity_id, manual)
        context = freeze_context(manual, rows)
        self._library.check_library_once()  # a row a curator added in the last minute is seen
        loaded = self._library.get_loaded_libraries()
        check_actor_library(loaded.threat_library.actors)  # in memory
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
        if scenario_sessions.create_manual_scenario_session(run) is not None:  # the key was taken meanwhile
            message = SessionMessage.IDEMPOTENCY_KEY_CONFLICT
            raise Conflict(message, reason=ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
        try:  # inserted once: a retry after a crash finds it stored and changes nothing
            scenarios.create(scenario)
        except DuplicateRecord as clash:
            if clash.index_name != "_id_":
                raise
        scenarios.update_scenario_session_counts(ids[0])
        return scenario
