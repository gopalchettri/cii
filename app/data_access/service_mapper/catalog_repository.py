"""Read the verified onboarding catalog through the shared stored-procedure client."""

from app.core.constants import MapperMessage, StoredProcedure
from app.core.database import StoredProcedureClient
from app.core.exceptions import SetupError
from app.models.service_mapper.catalog import CatalogRows


class ServiceCatalogRepository:
    def __init__(self, procedures: StoredProcedureClient) -> None:
        self._procedures = procedures

    def load(self) -> CatalogRows:
        summary = self._one(StoredProcedure.GET_SECTORS_AND_SUBSECTORS)
        mappings = self._one(StoredProcedure.GET_SECTOR_SERVICE_MAPPINGS)
        services = self._one(StoredProcedure.GET_SERVICES_WITH_SECTOR_DETAILS)
        associations = self._procedures.execute_procedure(StoredProcedure.GET_SERVICE_MAPPER_ASSOCIATIONS)
        if len(associations) != 3:
            raise SetupError(MapperMessage.CATALOG_RESULT_SETS)
        return CatalogRows(summary, mappings, services, *associations)

    def _one(self, procedure: StoredProcedure) -> list[dict]:
        result = self._procedures.execute_procedure(procedure)
        if len(result) != 1:
            raise SetupError(MapperMessage.CATALOG_RESULT_SETS)
        return result[0]
