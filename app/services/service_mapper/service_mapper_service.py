"""The Service Mapper stub: the real service's methods, answered with canned data. Nothing is stored, so a
decision is not kept and an Idempotency-Key is not remembered. The fixed ids in MapperSample pick an error
(404 or 409), so a UI developer can see every error response. Replace this class with the real service
(same methods) and the router, the models and the tests stay."""

from datetime import UTC, datetime

from app.core.constants import (
    MapperAction,
    MapperConfidence,
    MapperConflict,
    MapperDirection,
    MapperMessage,
    MapperRecommendationStatus,
    MapperSample,
    Status,
)
from app.core.exceptions import Conflict, Forbidden, NotFound
from app.models.admin.api_clients import Principal
from app.models.service_mapper.service_map import (
    CreateMappingRequest,
    DecisionInfo,
    DecisionRequest,
    DecisionResult,
    EntityServices,
    MappingAccepted,
    MappingView,
    Recommendation,
    ServiceRef,
    StatusEvent,
)

_ACTION_STATUS = {
    MapperAction.ACCEPT: MapperRecommendationStatus.ACCEPTED,
    MapperAction.REJECT: MapperRecommendationStatus.REJECTED,
}
_DECIDED_AT = datetime(2026, 10, 15, 10, 42, 11, tzinfo=UTC)
_REJECTED_AT = datetime(2026, 10, 15, 10, 44, 2, tzinfo=UTC)


class ServiceMapperService:
    def create_service_mapping(
        self, principal: Principal, body: CreateMappingRequest, idempotency_key: str | None
    ) -> MappingAccepted:
        """Start a mapping: queued at once (a replay of the same Idempotency-Key is not simulated)."""
        self._own_entity(principal, body.entity_id)
        return MappingAccepted(mapping_id=MapperSample.MAPPING_ID, status=Status.QUEUED, generation=1)

    def get_service_mapping(self, principal: Principal, mapping_id: str) -> MappingView:
        self._known_mapping(mapping_id)
        return sample_mapping(principal.entity_id, mapping_id)

    def list_entity_services(self, principal: Principal, listed_entity_id: int) -> EntityServices:
        self._own_entity(principal, listed_entity_id)
        return sample_entity_services(listed_entity_id)

    def regenerate_service_mapping(
        self, principal: Principal, mapping_id: str, idempotency_key: str | None
    ) -> MappingAccepted:
        self._known_mapping(mapping_id)
        if mapping_id == MapperSample.BUSY_MAPPING_ID:
            raise Conflict(MapperMessage.ROUND_RUNNING, reason=MapperConflict.GENERATION_IN_PROGRESS)
        return MappingAccepted(mapping_id=mapping_id, status=Status.QUEUED, generation=2)

    def decide_service_mapping_recommendation(
        self, principal: Principal, recommendation_id: str, body: DecisionRequest
    ) -> DecisionResult:
        if recommendation_id == MapperSample.DECIDED_RECOMMENDATION_ID:
            raise Conflict(MapperMessage.DECISION_FINAL, reason=MapperConflict.DECISION_FINAL)
        if recommendation_id == MapperSample.STALE_RECOMMENDATION_ID:
            raise Conflict(MapperMessage.RECOMMENDATION_SUPERSEDED, reason=MapperConflict.SUPERSEDED)
        return DecisionResult(
            recommendation_id=recommendation_id,
            status=_ACTION_STATUS[body.action],
            decision=DecisionInfo(by=principal.user_id, at=datetime.now(UTC), comment=body.reviewer_comment),
        )

    def list_service_mapping_events(self, principal: Principal, mapping_id: str) -> list[StatusEvent]:
        """The live-status events of a round, in order (the router streams them)."""
        self._known_mapping(mapping_id)
        return sample_events(mapping_id)

    @staticmethod
    def _own_entity(principal: Principal, entity_id: int) -> None:
        if entity_id != principal.entity_id:
            raise Forbidden(MapperMessage.NOT_YOUR_ENTITY)

    @staticmethod
    def _known_mapping(mapping_id: str) -> None:
        if mapping_id == MapperSample.UNKNOWN_MAPPING_ID:
            raise NotFound(MapperMessage.MAPPING_NOT_FOUND)


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
