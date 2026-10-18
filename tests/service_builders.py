"""Services built as the app builds them, with some dependencies swapped for a test's own."""

from typing import Any

from app import container
from app.realtime.publisher import publish_session_status
from app.services.scenario.threat_scenario_service import ThreatScenarioService
from app.worker.celery_app import send_job


def threat_scenario_service(**changed: Any) -> ThreatScenarioService:
    """The scenario service on the app's own repositories and side effects, `changed` ones swapped in."""
    dependencies: dict[str, Any] = {
        "sessions": container.get_threat_scenario_session_repository(),
        "scenarios": container.get_threat_scenario_repository(),
        "assets": container.get_asset_repository(),
        "work_control": container.get_work_control_repository(),
        "threats": container.get_threat_repository(),
        "threat_library": container.get_library_cache().get_threat_library,
        "switch": container.get_intelligence_switch(),
        "intel_snapshots": container.get_intel_snapshot_repository(),
        "audit": container.get_audit_repository(),
        "send_job": send_job,
        "publish_session_status": publish_session_status,
    }
    return ThreatScenarioService(**(dependencies | changed))
