"""The endpoints of external intelligence: no key on any of them, validation, the switch, a refresh
queued one at a time, and the health report with the evidence settings. The switch, the health reporter
and the feed store are group B's and A's: fakes with their documented signatures stand in; the job queue
is faked too."""

from collections.abc import Iterator
from datetime import datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.api.routers import external_intelligence as router_module
from app.core.config import get_settings
from app.core.constants import Collection, IntelSource, TaskName
from app.core.database import get_mongodb
from app.data_access.admin_jobs import AdminJobRecords
from app.models.external_intelligence.source_health import HealthReport
from app.models.external_intelligence.switch_state import SwitchState
from app.services.external_intelligence import intel_refreshes
from app.services.external_intelligence.intel_admin import IntelAdmin
from app.services.external_intelligence.intel_refreshes import IntelRefreshes
from tests.conftest import ADMIN

URL = "/v1/tsg/intel"
KEEP = "a" * 40


class MemorySwitch:
    def __init__(self) -> None:
        self.env, self.runtime = True, True

    def state(self) -> SwitchState:
        return SwitchState(self.env, self.runtime)

    def is_enabled(self) -> bool:
        return self.env and self.runtime

    def change_runtime_flag(self, enabled: bool, changed_by: str) -> SwitchState:
        self.runtime = enabled
        return SwitchState(self.env, enabled, None, changed_by)


class Reporter:
    def __init__(self, switch: MemorySwitch) -> None:
        self.switch, self.reads = switch, 0

    def describe_health(self, now: datetime) -> HealthReport:
        self.reads += 1
        return HealthReport(self.switch.state(), "snap-1", (), False)


class Feeds:
    def __init__(self) -> None:
        self.approved: list[IntelSource] = []

    def is_source_approved(self, source: IntelSource) -> bool:
        return source != IntelSource.NIST_NVD or source in self.approved  # NVD is revoked in these tests

    def approve_source(self, source: IntelSource) -> None:
        self.approved.append(source)


class Purger:
    def __init__(self) -> None:
        self.revoked: list[IntelSource] = []

    def revoke_and_purge(self, source: IntelSource) -> int:
        self.revoked.append(source)
        return 7

    def purge_existing_only(self, source: IntelSource) -> int:  # the master switch is off
        self.revoked.append(source)
        return 7


class Api:
    def __init__(self) -> None:
        self.switch, self.sent = MemorySwitch(), []
        self.reporter, self.purger = Reporter(self.switch), Purger()
        self.feeds = Feeds()
        self.refreshes = IntelRefreshes(AdminJobRecords(get_mongodb()), self.feeds, self.switch)  # type: ignore[arg-type]
        self.admin = IntelAdmin(  # type: ignore[arg-type]
            self.switch, self.reporter, self.refreshes, get_settings(), self.purger, self.feeds
        )


@pytest.fixture
def api(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> Iterator[Api]:
    get_mongodb()[Collection.ADMIN_JOBS].delete_many({})
    built = Api()

    def send(task: str, job_id: str) -> bool:
        built.sent.append((task, job_id))
        return True

    monkeypatch.setattr(intel_refreshes, "send_admin_job", send)
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", True)
    client.app.dependency_overrides[router_module.get_intel_admin] = lambda: built.admin
    client.app.dependency_overrides[router_module.get_intel_refreshes] = lambda: built.refreshes
    yield built
    client.app.dependency_overrides.clear()


def _audit(action: str) -> list[dict[str, Any]]:
    return list(get_mongodb()[Collection.AUDIT].find({"action": action}))


def test_the_switch_revoke_and_approve_need_no_key(client: TestClient, api: Api) -> None:
    # Owner, 2026-10-15: no admin key and no API key on any external intelligence endpoint.
    assert client.get(f"{URL}/switch").status_code == 200
    assert client.put(f"{URL}/switch", json={"enabled": True}).status_code == 200
    assert client.post(f"{URL}/sources/nist_nvd/revoke").status_code == 200
    assert client.post(f"{URL}/sources/nist_nvd/approve").status_code == 200
    assert _audit("external_intelligence.source_revoked")[-1]["actor"]["user_id"] == "admin"


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
    assert (
        off.status_code == 200 and off.json()["runtime_enabled"] is False and off.json()["effective"] is False
    )
    assert (
        api.sent == []
    )  # turning it off queues nothing (the audit row is the switch's: test_switch_admin.py)


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
    again = client.post(f"{URL}/refresh", json={"source": "cisa_kev"}, headers=ADMIN)
    assert again.status_code == 409
    assert (again.json()["reason"], again.json()["details"]) == ("job_in_progress", {"job_id": job_id})
    job = client.get(f"{URL}/refresh/{job_id}", headers=ADMIN).json()
    assert (job["kind"], job["status"], job["requested_by"]) == ("intel_refresh", "queued", "op-2")
    assert _audit("admin.job_started")[-1]["after"]["kind"] == "intel_refresh"


def test_a_refresh_names_an_approved_known_source_only(client: TestClient, api: Api) -> None:
    assert client.post(f"{URL}/refresh", json={"source": "nist_nvd"}, headers=ADMIN).status_code == 422
    assert client.post(f"{URL}/refresh", json={"source": "not_a_source"}, headers=ADMIN).status_code == 422
    ok = client.post(f"{URL}/refresh", json={"source": "cisa_kev"}, headers=ADMIN)
    assert ok.status_code == 202
    stored = get_mongodb()[Collection.ADMIN_JOBS].find_one({"_id": ok.json()["job_id"]})
    assert stored["source"] == "cisa_kev"


def test_a_refresh_is_refused_while_the_master_switch_is_off(
    client: TestClient, api: Api, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", False)
    api.switch.env = False  # the real switch reads the env master once, at start-up
    assert client.post(f"{URL}/refresh", headers=ADMIN).status_code == 409
    assert api.sent == [] and get_mongodb()[Collection.ADMIN_JOBS].count_documents({}) == 0


def test_a_refresh_is_refused_while_the_runtime_switch_is_off(client: TestClient, api: Api) -> None:
    # Queued then, the worker could only fail it: refused at once instead (owner, 2026-10-15).
    api.switch.runtime = False
    refused = client.post(f"{URL}/refresh")
    assert (
        refused.status_code == 409
        and refused.json()["detail"] == "External intelligence is off: nothing was refreshed."
    )
    assert api.sent == [] and get_mongodb()[Collection.ADMIN_JOBS].count_documents({}) == 0


def test_an_approval_with_the_runtime_switch_off_queues_nothing(client: TestClient, api: Api) -> None:
    api.switch.runtime = False
    done = client.post(f"{URL}/sources/nist_nvd/approve")
    assert done.status_code == 200 and done.json()["refresh_job_id"] is None
    assert api.feeds.approved == [IntelSource.NIST_NVD] and api.sent == []


def test_a_job_of_another_kind_is_not_found_here(client: TestClient, api: Api) -> None:
    AdminJobRecords(get_mongodb()).insert_active(
        {"_id": "emb-1", "kind": "embeddings_build", "status": "queued", "requested_by": "x", "created_at": 0}
    )
    assert client.get(f"{URL}/refresh/emb-1", headers=ADMIN).status_code == 404


def test_health_shows_the_evidence_settings_and_whether_they_were_calibrated(
    client: TestClient, api: Api, monkeypatch: pytest.MonkeyPatch
) -> None:
    health = client.get(f"{URL}/health", headers=ADMIN).json()
    assert (
        health["snapshot_id"] == "snap-1"
        and health["evidence"]["threshold"] == get_settings().evidence_similarity_threshold
    )
    assert health["evidence"]["rerank_model"] == "bge-reranker-v2-m3"  # the name only, never the folder
    assert health["evidence"]["threshold_calibrated"] is True
    assert health["pending_sources"] == [] and health["no_data"] is False and health["stale"] is False
    uat = get_settings().model_copy(update={"rerank_model": "litellm_proxy/qwen3-reranker-8b-mig"})
    api.admin = IntelAdmin(api.switch, api.reporter, api.refreshes, uat, api.purger, api.feeds)  # type: ignore[arg-type]
    shown = client.get(f"{URL}/health", headers=ADMIN).json()["evidence"]
    assert (shown["rerank_model"], shown["threshold_calibrated"]) == ("qwen3-reranker-8b-mig", False)
    assert shown["threshold_calibrated_on"] is None


def test_health_with_the_master_switch_off_reads_no_store(
    client: TestClient, api: Api, monkeypatch: pytest.MonkeyPatch
) -> None:
    off = get_settings().model_copy(update={"external_intelligence_enabled": False})
    api.switch.env = False
    api.admin = IntelAdmin(api.switch, api.reporter, api.refreshes, off, api.purger, api.feeds)  # type: ignore[arg-type]
    health = client.get(f"{URL}/health", headers=ADMIN).json()
    assert health["sources"] == [] and health["snapshot_id"] is None and api.reporter.reads == 0
    assert health["switch"]["effective"] is False


def test_a_source_is_revoked_purged_and_audited_whatever_the_switch_says(
    client: TestClient, api: Api, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", False)
    revoked = client.post(f"{URL}/sources/nist_nvd/revoke", headers=ADMIN | {"X-User-Id": "op-3"})
    assert revoked.status_code == 200 and revoked.json() == {"source": "nist_nvd", "records_purged": 7}
    assert api.purger.revoked == [IntelSource.NIST_NVD]
    row = _audit("external_intelligence.source_revoked")[-1]
    assert row["actor"]["user_id"] == "op-3" and row["target"]["id"] == "nist_nvd"
    assert client.post(f"{URL}/sources/not_a_source/revoke", headers=ADMIN).status_code == 422


def test_a_revoked_source_is_approved_again_audited_and_refreshed(client: TestClient, api: Api) -> None:
    done = client.post(f"{URL}/sources/nist_nvd/approve", headers=ADMIN | {"X-User-Id": "op-4"})
    assert done.status_code == 200 and done.json()["source"] == "nist_nvd" and done.json()["refresh_job_id"]
    assert api.feeds.approved == [IntelSource.NIST_NVD]
    assert [task for task, _ in api.sent] == [TaskName.REFRESH_EXTERNAL_INTELLIGENCE]
    job = get_mongodb()[Collection.ADMIN_JOBS].find_one({"_id": done.json()["refresh_job_id"]})
    assert job["source"] == "nist_nvd" and job["requested_by"] == "op-4"
    row = _audit("external_intelligence.source_approved")[-1]
    assert row["actor"]["user_id"] == "op-4" and row["target"]["id"] == "nist_nvd"
    again = client.post(f"{URL}/sources/cisa_kev/approve", headers=ADMIN)  # a refresh is already queued
    assert again.status_code == 200 and again.json()["refresh_job_id"] is None


def test_the_approval_needs_a_known_source_and_the_master_switch(
    client: TestClient, api: Api, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert client.post(f"{URL}/sources/not_a_source/approve", headers=ADMIN).status_code == 422
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", False)
    assert client.post(f"{URL}/sources/cisa_kev/approve", headers=ADMIN).status_code == 409
    assert api.feeds.approved == [] and api.sent == []
