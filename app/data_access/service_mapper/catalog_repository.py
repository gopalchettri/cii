"""Read the verified onboarding catalog through the shared stored-procedure client."""

from app.core.constants import MapperMessage, StoredProcedure
from app.core.database import StoredProcedureClient
from app.core.exceptions import SetupError
from app.models.service_mapper.catalog import CatalogRows


class ServiceCatalogRepository:
    def __init__(self, procedures: StoredProcedureClient) -> None:
        self._procedures = procedures

    def load(self) -> CatalogRows:
        services = self._procedures.execute_procedure(StoredProcedure.GET_SERVICES_WITH_SECTOR_DETAILS)
        associations = self._procedures.execute_procedure(StoredProcedure.GET_SERVICE_MAPPER_ASSOCIATIONS)
        if len(services) != 1 or len(associations) != 3:
            raise SetupError(MapperMessage.CATALOG_RESULT_SETS)
        return CatalogRows(*services, *associations)
