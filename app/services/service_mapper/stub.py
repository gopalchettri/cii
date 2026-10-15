"""The Service Mapper stub: the real service's methods, answered with canned data. Nothing is stored, so a
decision is not kept and an Idempotency-Key is not remembered. The fixed ids in MapperSample pick an error
(404 or 409), so a UI developer can see every error response. Replace this class with the real service
(same methods) and the router, the models and the tests stay."""

from datetime import UTC, datetime

from app.core.constants import (
    MapperAction,
    MapperConflict,
    MapperMessage,
    MapperRecommendationStatus,
    MapperSample,
    Status,
)
from app.core.exceptions import Conflict, Forbidden, NotFound
from app.core.singletons import singleton
from app.models.api_clients import Principal
from app.models.service_map import (
    CreateMappingRequest,
    DecisionInfo,
    DecisionRequest,
    DecisionResult,
    EntityServices,
    MappingAccepted,
    MappingView,
    StatusEvent,
)
from app.services.service_mapper.samples import sample_entity_services, sample_events, sample_mapping

_ACTION_STATUS = {
    MapperAction.ACCEPT: MapperRecommendationStatus.ACCEPTED,
    MapperAction.REJECT: MapperRecommendationStatus.REJECTED,
}


class ServiceMapperStub:
    def create(
        self, principal: Principal, body: CreateMappingRequest, idempotency_key: str | None
    ) -> MappingAccepted:
        """Start a mapping: queued at once (a replay of the same Idempotency-Key is not simulated)."""
        self._own_entity(principal, body.entity_id)
        return MappingAccepted(mapping_id=MapperSample.MAPPING_ID, status=Status.QUEUED, generation=1)

    def get(self, principal: Principal, mapping_id: str) -> MappingView:
        self._known_mapping(mapping_id)
        return sample_mapping(principal.entity_id, mapping_id)

    def entity_services(self, principal: Principal, listed_entity_id: int) -> EntityServices:
        self._own_entity(principal, listed_entity_id)
        return sample_entity_services(listed_entity_id)

    def regenerate(
        self, principal: Principal, mapping_id: str, idempotency_key: str | None
    ) -> MappingAccepted:
        self._known_mapping(mapping_id)
        if mapping_id == MapperSample.BUSY_MAPPING_ID:
            raise Conflict(MapperMessage.ROUND_RUNNING, reason=MapperConflict.GENERATION_IN_PROGRESS)
        return MappingAccepted(mapping_id=mapping_id, status=Status.QUEUED, generation=2)

    def decide(self, principal: Principal, recommendation_id: str, body: DecisionRequest) -> DecisionResult:
        if recommendation_id == MapperSample.DECIDED_RECOMMENDATION_ID:
            raise Conflict(MapperMessage.DECISION_FINAL, reason=MapperConflict.DECISION_FINAL)
        if recommendation_id == MapperSample.STALE_RECOMMENDATION_ID:
            raise Conflict(MapperMessage.RECOMMENDATION_SUPERSEDED, reason=MapperConflict.SUPERSEDED)
        return DecisionResult(
            recommendation_id=recommendation_id,
            status=_ACTION_STATUS[body.action],
            decision=DecisionInfo(by=principal.user_id, at=datetime.now(UTC), comment=body.reviewer_comment),
        )

    def events(self, principal: Principal, mapping_id: str) -> list[StatusEvent]:
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


@singleton
def get_service_mapper() -> ServiceMapperStub:
    return ServiceMapperStub()
