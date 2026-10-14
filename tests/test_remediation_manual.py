"""A plan for a hand-written scenario (#11 with `manual_scenario`; BLUEPRINT M11 R2; BUILD_PLAN S55): saved
and planned, replayed, key conflicts, a new wording proposed pending (a new type linked to its closest
attacker), a curator-rejected wording, strict control references, the top-up. The asset from the SQL test
database; the library, the search, the proposal and the top-up faked."""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from app.core.config import get_settings
from app.core.constants import (
    AuditAction,
    Collection,
    ConflictReason,
    Header,
    LibraryStatus,
    ResolveOutcome,
    RunKind,
    StrideCategory,
    TaskName,
)
from app.core.database import StoredProcedureClient, get_mongodb
from app.data_access.asset_context import AssetContextRepository
from app.data_access.manual_scenarios import ManualRecords
from app.data_access.remediations import RemediationRepository
from app.data_access.run_counts import RunCounts
from app.data_access.sessions import SessionRepository
from app.models.library import LoadedLibraries, ProposedThreat, ThreatProposal
from app.models.remediation_requests import PlanRequest
from app.services.remediation.manual import ManualPlans, _fingerprint, get_manual_plans
from app.services.remediation.manual_scenarios import ManualScenarios
from tests.fakes import FakeRerankModel
from tests.test_remediation_requests import (  # noqa: F401 — api_key and world are fixtures
    _service,
    api_key,
    world,
)
from tests.test_remediation_snapshot import LIBRARY as CONTROLS
from tests.test_threat_identity import LIBRARY as THREATS

IDENTITY = {Header.USER_ID: "u1", Header.ENTITY_ID: "86", Header.TENANT_ID: "DESC"}
BODY = {
    "manual_scenario": {
        "asset_id": 103,
        "supporting_system_id": [321, 322],
        "subsector_id": 11,
        "threat_type": {"name": "Malware"},
        "threat": {"name": "Firmware tampering"},
        "threat_scenario": "A cybercriminal could push unsigned firmware to the RTU during maintenance.",
        "risk_statement": "Loss of trusted control could interrupt electricity transmission.",
        "mapped_controls": ["CII-CID-1"],
    },
    "risk_level": "High",
}


class _Search:
    """LibrarySearch's surface: the actors a query may rank, in library order; every query kept."""

    def __init__(self) -> None:
        self.queries: list[str] = []

    def snapshot(self) -> Any:
        def find_actors(queries: list[str], top_k: int, allowed_ids: list[Any]) -> list[Any]:
            self.queries += queries
            actors = THREATS.actors
            return [[(a, 1.0) for a in actors if ids is None or a.actor_id in ids] for ids in allowed_ids]

        return SimpleNamespace(library=SimpleNamespace(threat_library=THREATS), find_actors=find_actors)


@pytest.fixture
def manual(
    client: TestClient,
    world: dict[str, Any],  # noqa: F811
    sql_test_engine: Engine,
) -> Iterator[dict[str, Any]]:
    """ManualPlans on the SQL test database's asset 103 (entity 86) and the fakes; what it proposed."""
    db, proposals, search = get_mongodb(), [], _Search()

    def propose(proposal: ThreatProposal) -> ProposedThreat:
        proposals.append(proposal)
        type_id = 1 if proposal.type_name == "Malware" else 900
        return ProposedThreat(type_id, 901, ResolveOutcome.CREATED_PENDING)

    library = SimpleNamespace(
        check_library_once=lambda: None,
        get_loaded_libraries=lambda: LoadedLibraries((), THREATS, tuple(CONTROLS.values())),
    )
    scenarios = ManualScenarios(
        AssetContextRepository(StoredProcedureClient(sql_test_engine)),
        library,  # type: ignore[arg-type]
        SimpleNamespace(propose_threat=propose),  # type: ignore[arg-type]
        search,  # type: ignore[arg-type]
        ManualRecords(db),
        RunCounts(db),
        FakeRerankModel(),  # the attacker threshold's scores (off by default)
    )
    built = ManualPlans(
        SessionRepository(db), RemediationRepository(db), scenarios, _service(world["top_up"])
    )
    client.app.dependency_overrides[get_manual_plans] = lambda: built  # type: ignore[attr-defined]
    yield world | {"proposals": proposals, "search": search}
    client.app.dependency_overrides.pop(get_manual_plans, None)  # type: ignore[attr-defined]


def _post(client: TestClient, key: str, body: dict[str, Any], idempotency_key: str | None) -> Any:
    headers = IDENTITY | {Header.API_KEY: key}
    if idempotency_key:
        headers[Header.IDEMPOTENCY_KEY] = idempotency_key
    return client.post("/v1/remediation", json=body, headers=headers)


def _with(**changes: Any) -> dict[str, Any]:
    return BODY | {"manual_scenario": BODY["manual_scenario"] | changes}


def _scenario(scenario_id: str) -> dict[str, Any]:
    return get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id})


def test_a_hand_written_scenario_is_saved_planned_and_replayed(
    client: TestClient,
    api_key: str,  # noqa: F811
    manual: dict[str, Any],
) -> None:
    key = uuid.uuid4().hex
    first = _post(client, api_key, BODY, key)
    assert first.status_code == 202, first.text
    planned = first.json()
    scenario = _scenario(planned["scenario_id"])
    run = get_mongodb()[Collection.SESSIONS].find_one({"_id": planned["session_id"]})
    assert (run["kind"], run["active"], run["counts"]["accepted"]) == (RunKind.MANUAL, False, 1)
    content = scenario["content"]
    # Two systems: any link between them is one the platform does not record.
    found = (scenario["source"], scenario["decision"], content["route"]["status"])
    assert found == (RunKind.MANUAL, "accepted", "unknown")
    threat = content["threat"]
    found = (threat["library_id"], threat["library_status"], content["category"])
    assert found == (10, LibraryStatus.ACTIVE, StrideCategory.TAMPERING) and content["category_id"] == 2
    actors = [(a["name"], a["role"], a["closest"]) for a in content["actors"]]
    assert actors == [("Organised crime group", "acting", False)]
    item = scenario["controls"]["items"][0]
    assert (scenario["controls"]["status"], item["code"], item["match"]) == ("done", "CII-CID-1", "given")
    assert item["description"] == next(c.description for c in CONTROLS.values() if c.code == "CII-CID-1")
    record = get_mongodb()[Collection.REMEDIATIONS].find_one({"_id": planned["remediation_id"]})
    shown = record["versions"][0]["snapshot"]["existing_controls"]["library_mapped"][0]
    assert (shown["match"], shown["mapping_relevance"]) == ("exact", None)  # the prompt knows exact, nearest
    assert manual["sent"] == [(TaskName.WRITE_PLAN, planned["remediation_id"], 1)]
    assert manual["top_up"].asked == []
    again = _post(client, api_key, BODY, key)
    assert (again.status_code, again.json()) == (200, planned)
    assert len(manual["sent"]) == 1 and manual["proposals"] == []
    listed = client.get("/v1/entities/86/scenarios", headers=IDENTITY | {Header.API_KEY: api_key})
    assert planned["scenario_id"] in [row["scenario_id"] for row in listed.json()["scenarios"]]
    # The writer has no plan path for it: regenerating it is refused by name, never a 500 (no write job).
    url = f"/v1/sessions/{planned['session_id']}/regenerate/scenarios"
    regenerate = client.post(
        url, json={"scenario_ids": [planned["scenario_id"]]}, headers=IDENTITY | {Header.API_KEY: api_key}
    )
    assert (regenerate.status_code, regenerate.json()["errors"][0]["reason"]) == (409, "hand_written")
    next_set = client.post(
        f"/v1/sessions/{planned['session_id']}/scenarios/next-set",
        headers=IDENTITY | {Header.API_KEY: api_key},
    )
    assert next_set.status_code == 409


def test_a_required_property_not_recorded_saves_nothing(
    client: TestClient,
    api_key: str,  # noqa: F811
    manual: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """G197 (owner 2026-10-11): a hand-written scenario is held to the same required properties as a run;
    the refusal names the field where the request put it, and nothing is proposed or saved."""
    monkeypatch.setattr(get_settings(), "system_properties_required", "description")
    key = uuid.uuid4().hex
    refused = _post(client, api_key, BODY, key)
    assert (refused.status_code, refused.json()["reason"]) == (422, "required_facts_missing")
    assert refused.json()["errors"][0]["field"] == "body.manual_scenario.supporting_system_id.1"
    assert get_mongodb()[Collection.SESSIONS].count_documents({"idempotency_key": key}) == 0
    assert manual["proposals"] == []


def test_the_key_is_required_and_names_one_request(
    client: TestClient,
    api_key: str,  # noqa: F811
    manual: dict[str, Any],
) -> None:
    assert _post(client, api_key, BODY, None).status_code == 422
    key = uuid.uuid4().hex
    assert _post(client, api_key, BODY, key).status_code == 202
    other = _post(client, api_key, _with(threat_scenario="Another attack, written differently."), key)
    assert (other.status_code, other.json()["reason"]) == (409, ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
    # A generated run's key, even with this very body's fingerprint: refused before any library write.
    generated, new_wording = uuid.uuid4().hex, _with(threat={"name": "Logic bomb"})
    get_mongodb()[Collection.SESSIONS].insert_one(
        {"_id": uuid.uuid4().hex, "entity_id": 86, "asset_id": 103, "kind": RunKind.GENERATED,
         "idempotency_key": generated, "status": "done", "updated_at": datetime.now(UTC),
         "request_hash": _fingerprint(PlanRequest.model_validate(new_wording))}
    )  # fmt: skip
    taken = _post(client, api_key, new_wording, generated)
    assert (taken.status_code, taken.json()["reason"]) == (409, ConflictReason.IDEMPOTENCY_KEY_CONFLICT)
    assert manual["proposals"] == []


def test_new_wordings_are_proposed_pending_and_a_rejected_one_is_not(
    client: TestClient,
    api_key: str,  # noqa: F811
    manual: dict[str, Any],
) -> None:
    """A new threat of a live type: proposed with no actor links. A new type: linked to the closest attacker
    it was given (flagged). A curator-rejected wording: never proposed, saved without a library id."""
    new_threat = _post(client, api_key, _with(threat={"name": "Logic bomb"}), uuid.uuid4().hex).json()
    threat = _scenario(new_threat["scenario_id"])["content"]["threat"]
    assert (threat["library_id"], threat["library_status"]) == (901, LibraryStatus.PENDING)
    proposal = manual["proposals"][0]
    found = (proposal.category, proposal.type_name, proposal.actor_ids, proposal.source)
    assert found == (StrideCategory.TAMPERING, "Malware", (), "manual")
    audit = {"action": AuditAction.LIBRARY_PROPOSED, "target.id": "901"}
    assert get_mongodb()[Collection.AUDIT].count_documents(audit) >= 1
    body = _with(threat_type={"name": "Insider sabotage"}, threat={"name": "Logic bomb"})
    new_type = _post(client, api_key, body, uuid.uuid4().hex).json()
    actors = _scenario(new_type["scenario_id"])["content"]["actors"]
    assert [(a["name"], a["closest"]) for a in actors] == [("Organised crime group", True)]
    assert (manual["proposals"][1].actor_ids, manual["proposals"][1].category) == ((3,), None)
    rejected = _post(client, api_key, _with(threat={"name": "Rogue USB"}), uuid.uuid4().hex).json()
    threat = _scenario(rejected["scenario_id"])["content"]["threat"]
    found = (threat["library_id"], threat["library_status"], len(manual["proposals"]))
    assert found == (None, LibraryStatus.CURATOR_REJECTED, 2)


def test_controls_named_strictly_else_the_top_up(
    client: TestClient,
    api_key: str,  # noqa: F811
    manual: dict[str, Any],
) -> None:
    key = uuid.uuid4().hex
    unknown = _post(client, api_key, _with(mapped_controls=["CII-CID-1", "CII-CID-77"]), key)
    assert unknown.status_code == 422
    assert unknown.json()["errors"][0]["field"] == "body.manual_scenario.mapped_controls[1]"
    assert get_mongodb()[Collection.SESSIONS].count_documents({"idempotency_key": key}) == 0  # nothing saved
    topped = _post(client, api_key, _with(mapped_controls=None), uuid.uuid4().hex).json()
    assert manual["top_up"].asked == [topped["scenario_id"]]


def test_a_refused_register_saves_nothing_and_the_persons_words_are_redacted(
    client: TestClient,
    api_key: str,  # noqa: F811
    manual: dict[str, Any],
) -> None:
    """Review S56: the register is checked before the library proposal, the run and the scenario, so a
    corrected retry under the same key is a first request, never a 409 against an orphan; the person's text
    goes to the embedding model redacted."""
    key = uuid.uuid4().hex
    wording = _with(threat={"name": "Logic bomb"}, threat_scenario="Mail ops@example.com a bad image.")
    refused = wording | {"existing_controls": [{"control_id": 1, "control_code": "CII-CID-2"}]}
    assert _post(client, api_key, refused, key).status_code == 422
    assert get_mongodb()[Collection.SESSIONS].count_documents({"idempotency_key": key}) == 0
    assert manual["proposals"] == []
    assert _post(client, api_key, wording, key).status_code == 202
    assert manual["search"].queries[-1] == "Malware: Logic bomb. Mail [REDACTED] a bad image."
