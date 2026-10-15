"""The stub's canned answers: the mapping, entity services and events of the HOW_IT_WORKS doc."""

from datetime import UTC, datetime

from app.core.constants import (
    MapperConfidence,
    MapperDirection,
    MapperRecommendationStatus,
    MapperSample,
    Status,
)
from app.models.service_map import (
    DecisionInfo,
    EntityServices,
    MappingView,
    Recommendation,
    ServiceRef,
    StatusEvent,
)

_DECIDED_AT = datetime(2026, 10, 15, 10, 42, 11, tzinfo=UTC)
_REJECTED_AT = datetime(2026, 10, 15, 10, 44, 2, tzinfo=UTC)


def selected_service() -> ServiceRef:
    return ServiceRef(
        service_id=MapperSample.SERVICE_ID,
        name=MapperSample.SERVICE_NAME,
        sector=MapperSample.SECTOR,
        sub_sector=MapperSample.SUB_SECTOR,
    )


def _accepted_upstream() -> Recommendation:
    """A service of another sector that the selected one needs, accepted."""
    return Recommendation(
        recommendation_id=MapperSample.ACCEPTED_ID,
        generation=1,
        direction=MapperDirection.UPSTREAM,
        related_service_id=58,
        name="Identity Service",
        sector="Technology",
        sub_sector="Identity",
        cross_sector=True,
        ai_generated=False,
        reason="Payment needs identity to verify the payer.",
        confidence=MapperConfidence.HIGH,
        status=MapperRecommendationStatus.ACCEPTED,
        decision=DecisionInfo(by="user-123", at=_DECIDED_AT, comment="Relationship verified."),
    )


def _rejected_ai_downstream() -> Recommendation:
    """A service the AI named (not in the inventory), rejected."""
    return Recommendation(
        recommendation_id=MapperSample.REJECTED_ID,
        generation=1,
        direction=MapperDirection.DOWNSTREAM,
        related_service_id=None,
        name="Merchant Portal",
        sector=None,
        sub_sector=None,
        cross_sector=None,
        ai_generated=True,
        reason="Merchants may rely on payment.",
        confidence=MapperConfidence.LOW,
        status=MapperRecommendationStatus.REJECTED,
        decision=DecisionInfo(by="user-123", at=_REJECTED_AT, comment="Not used here."),
    )


def _proposed_downstream() -> Recommendation:
    """A cross-sector service that relies on the selected one, from the latest round, not yet decided."""
    return Recommendation(
        recommendation_id=MapperSample.PROPOSED_ID,
        generation=2,
        direction=MapperDirection.DOWNSTREAM,
        related_service_id=77,
        name="Utility Bill Collection",
        sector="Energy",
        sub_sector="Electricity",
        cross_sector=True,
        ai_generated=False,
        reason="Bill collection relies on payment to take customer payments.",
        confidence=MapperConfidence.MEDIUM,
        status=MapperRecommendationStatus.PROPOSED,
        decision=None,
    )


def sample_mapping(entity_id: int, mapping_id: str) -> MappingView:
    return MappingView(
        mapping_id=mapping_id,
        entity_id=entity_id,
        status=Status.DONE,
        generation=2,
        error=None,
        service=selected_service(),
        recommendations=[_accepted_upstream(), _rejected_ai_downstream(), _proposed_downstream()],
    )


def sample_entity_services(entity_id: int) -> EntityServices:
    return EntityServices(
        entity_id=entity_id,
        services=[
            selected_service(),
            ServiceRef(service_id=58, name="Identity Service", sector="Technology", sub_sector="Identity"),
        ],
    )


def sample_events(mapping_id: str) -> list[StatusEvent]:
    """A round as the live stream shows it: queued, running, done."""
    return [
        StatusEvent(mapping_id=mapping_id, status=status, generation=2)
        for status in (Status.QUEUED, Status.RUNNING, Status.DONE)
    ]
