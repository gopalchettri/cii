"""The endpoints of external intelligence: no key on any of them, validation, the switch, a refresh
queued one at a time, and the health report with the evidence settings. The switch and the intelligence
stores are fakes with their documented signatures; the job queue is faked too."""

from datetime import UTC, datetime
from types import ModuleType
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings, get_settings
from app.core.constants import Collection, FeedStatus, IntelSource, TaskName
from app.core.database import get_mongodb
from app.crud.admin_jobs import get_admin_job_repository
from app.schemas.intel_records import SourceHealth, SwitchState
from tests.conftest import ADMIN
from tests.external_intelligence.evidence_fakes import MemoryKeeper
from tests.external_intelligence.fakes import intelligence_service

URL = "/v1/tsg/intel"
KEEP = "a" * 40


class MemorySwitch:
    def __init__(self) -> None:
        self.env, self.runtime = True, True

    def state(self) -> SwitchState:
        return SwitchState(self.env, self.runtime)

    def is_on(self, sure: bool = False) -> bool:
        return self.env and self.runtime

    def save(self, enabled: bool, changed_by: str) -> SwitchState:
        self.runtime = enabled
        return SwitchState(self.env, enabled, None, changed_by)


class Feeds:
    """One fresh source in the health report."""

    def __init__(self) -> None:
        self.reads = 0

    def list(self, fields: Any = None, **where: Any) -> list[dict[str, Any]]:
        self.reads += 1
        now = datetime.now(UTC)
        fresh = SourceHealth(IntelSource.ATTACK_ENTERPRISE, FeedStatus.OK, "c", "v", 5, now, now).as_doc()
        return [fresh | {"_id": IntelSource.ATTACK_ENTERPRISE}]


class Snapshots:
    def get(self, fields: Any = None, **where: Any) -> dict[str, Any]:
        return {"snapshot_id": "snap-1"}


class Api:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.switch, self.sent = MemorySwitch(), []
        self.feeds = Feeds()
        self._monkeypatch = monkeypatch
        self.service = self.build(get_settings())

    def build(self, settings: Settings) -> ModuleType:
        """The admin module over these fakes, the real admin jobs and audit, with `settings`."""
        return intelligence_service(
            self._monkeypatch,
            settings=settings,
            switch=self.switch,
            feeds=self.feeds,
            snapshots=Snapshots(),
            index_keeper=MemoryKeeper(),
            send_admin_job=self.send,
        )

    def send(self, task: str, job_id: str) -> bool:
        self.sent.append((task, job_id))
        return True


@pytest.fixture
def api(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> Api:
    get_mongodb()[Collection.ADMIN_JOBS].delete_many({})
    built = Api(monkeypatch)
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", True)
    return built


def _audit(action: str) -> list[dict[str, Any]]:
    return list(get_mongodb()[Collection.AUDIT].find({"action": action}))


def test_the_switch_needs_no_key(client: TestClient, api: Api) -> None:
    # Owner, 2026-10-15: no admin key and no API key on any external intelligence endpoint.
    assert client.get(f"{URL}/switch").status_code == 200
    assert client.put(f"{URL}/switch", json={"enabled": True}).status_code == 200
    assert _audit("external_intelligence.switched")[-1]["actor"]["user_id"] == "admin"


@pytest.mark.parametrize("action", ["revoke", "approve"])
def test_a_source_is_neither_withdrawn_nor_approved_by_any_route(client: TestClient, action: str) -> None:
    """Owner, 2026-11-17: only MITRE ATT&CK is imported, so no source needs withdrawing."""
    path = f"{URL}/sources/{{source}}/{action}"
    assert client.post(path.format(source="mitre_attack_ics")).status_code == 404
    assert path not in client.app.openapi()["paths"]


def test_health_and_a_refresh_need_no_key(client: TestClient, api: Api) -> None:
    # Owner, 2026-10-15: run by hand in UAT and prod with no admin key and no API key.
    assert client.get(f"{URL}/health").status_code == 200
    started = client.post(f"{URL}/refresh")
    assert started.status_code == 202
    job = client.get(f"{URL}/refresh/{started.json()['job_id']}")
    assert job.status_code == 200 and job.json()["requested_by"] == "admin"  # no X-User-Id: Audit.ADMIN_USER


def test_the_switch_is_read_and_changed_and_the_change_is_audited(client: TestClient, api: Api) -> None:
    assert client.get(f"{URL}/switch", headers=ADMIN).json()["effective"] is True
    off = client.put(f"{URL}/switch", json={"enabled": False}, headers=ADMIN | {"X-User-Id": "op-1"})
    assert off.status_code == 200 and off.json()["runtime_enabled"] is False and off.json()["effective"] is False
    assert api.sent == []  # turning it off queues nothing (its audit row: test_switch_admin.py)


@pytest.mark.parametrize("body", [{}, {"enabled": "yes"}, {"enabled": 1}, {"enabled": True, "extra": 1}])
def test_the_switch_body_is_validated(client: TestClient, api: Api, body: dict[str, Any]) -> None:
    assert client.put(f"{URL}/switch", json=body, headers=ADMIN).status_code == 422


def test_turning_it_on_queues_a_refresh(client: TestClient, api: Api) -> None:
    api.switch.runtime = False
    on = client.put(f"{URL}/switch", json={"enabled": True}, headers=ADMIN)
    assert on.status_code == 200 and on.json()["effective"] is True
    assert [task for task, _ in api.sent] == [TaskName.REFRESH_EXTERNAL_INTELLIGENCE]
    again = client.put(f"{URL}/switch", json={"enabled": True}, headers=ADMIN)  # one is already queued
    assert again.status_code == 200 and len(api.sent) == 1


def test_with_the_master_switch_off_the_switch_is_not_written_and_nothing_is_queued(
    client: TestClient, api: Api, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", False)
    api.switch.runtime = False
    assert client.put(f"{URL}/switch", json={"enabled": True}, headers=ADMIN).status_code == 409
    assert api.switch.runtime is False and api.sent == []


def test_a_refresh_is_queued_once_at_a_time_and_read_back(client: TestClient, api: Api) -> None:
    started = client.post(f"{URL}/refresh", headers=ADMIN | {"X-User-Id": "op-2"})
    assert started.status_code == 202 and started.json()["status"] == "queued"
    job_id = started.json()["job_id"]
    again = client.post(f"{URL}/refresh", json={"source": "mitre_attack_enterprise"}, headers=ADMIN)
    assert again.status_code == 409
    assert (again.json()["reason"], again.json()["details"]) == ("job_in_progress", {"job_id": job_id})
    job = client.get(f"{URL}/refresh/{job_id}", headers=ADMIN).json()
    assert (job["kind"], job["status"], job["requested_by"]) == ("intel_refresh", "queued", "op-2")
    assert _audit("admin.job_started")[-1]["after"]["kind"] == "intel_refresh"


def test_a_refresh_names_a_known_source_only(client: TestClient, api: Api) -> None:
    assert client.post(f"{URL}/refresh", json={"source": "not_a_source"}, headers=ADMIN).status_code == 422
    ok = client.post(f"{URL}/refresh", json={"source": "mitre_attack_enterprise"}, headers=ADMIN)
    assert ok.status_code == 202
    stored = get_mongodb()[Collection.ADMIN_JOBS].find_one({"_id": ok.json()["job_id"]})
    assert stored["source"] == "mitre_attack_enterprise"


def test_a_refresh_is_queued_while_the_master_switch_is_off(
    client: TestClient, api: Api, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-010: the MITRE ATT&CK import runs whatever the switch says (the MITRE run reads it)."""
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", False)
    api.switch.env = False  # this fake reads no settings
    assert client.post(f"{URL}/refresh", headers=ADMIN).status_code == 202
    assert len(api.sent) == 1 and get_mongodb()[Collection.ADMIN_JOBS].count_documents({}) == 1


def test_a_refresh_is_queued_while_the_runtime_switch_is_off(client: TestClient, api: Api) -> None:
    api.switch.runtime = False
    assert client.post(f"{URL}/refresh").status_code == 202
    assert len(api.sent) == 1 and get_mongodb()[Collection.ADMIN_JOBS].count_documents({}) == 1


def test_a_job_of_another_kind_is_not_found_here(client: TestClient, api: Api) -> None:
    get_admin_job_repository().create(
        {
            "active": True,
            "_id": "emb-1",
            "kind": "embeddings_build",
            "status": "queued",
            "requested_by": "x",
            "created_at": 0,
        }
    )
    assert client.get(f"{URL}/refresh/emb-1", headers=ADMIN).status_code == 404


def test_health_shows_the_evidence_settings_and_whether_they_were_calibrated(
    client: TestClient, api: Api, monkeypatch: pytest.MonkeyPatch
) -> None:
    bge = {"rerank_model": "C:/models/bge-reranker-v2-m3", "evidence_similarity_threshold": 30.0}
    api.service = api.build(get_settings().model_copy(update=bge))
    health = client.get(f"{URL}/health", headers=ADMIN).json()
    assert health["snapshot_id"] == "snap-1" and health["evidence"]["threshold"] == 30.0
    assert health["evidence"]["rerank_model"] == "bge-reranker-v2-m3"  # the name only, never the folder
    assert health["evidence"]["threshold_calibrated"] is True
    assert health["pending_sources"] == [] and health["no_data"] is False and "stale" not in health
    uat = get_settings().model_copy(update={"rerank_model": "litellm_proxy/qwen3-reranker-8b"})
    other_threshold = get_settings().model_copy(update=bge | {"evidence_similarity_threshold": 5.0})
    for settings, model in ((uat, "qwen3-reranker-8b"), (other_threshold, "bge-reranker-v2-m3")):
        api.service = api.build(settings)
        shown = client.get(f"{URL}/health", headers=ADMIN).json()["evidence"]
        assert (shown["rerank_model"], shown["threshold_calibrated"]) == (model, False)
        assert shown["threshold_calibrated_on"] is None


def test_health_with_the_master_switch_off_shows_the_import_but_no_evidence(
    client: TestClient, api: Api, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-010: the MITRE import runs with the switch off, and NO_MITRE_DATA tells the caller to wait here."""
    off = get_settings().model_copy(update={"external_intelligence_enabled": False})
    api.switch.env = False
    api.service = api.build(off)
    health = client.get(f"{URL}/health", headers=ADMIN).json()
    assert [source["source"] for source in health["sources"]] == ["mitre_attack_enterprise"]
    assert health["pending_sources"] == [] and health["no_data"] is False and health["snapshot_id"] is None
    assert health["switch"]["effective"] is False
