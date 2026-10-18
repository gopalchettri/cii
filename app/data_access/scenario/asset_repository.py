"""SQL Server's asset context, through its one stored procedure."""

import json

from app.core.constants import StoredProcedure
from app.core.database import StoredProcedureClient
from app.models.scenario.asset_context import AssetContextRows
from app.models.scenario.views import StartRunRequest


class AssetRepository:
    """The asset facts a run is built from (tsg_GetAssetContext)."""

    def __init__(self, procedures: StoredProcedureClient) -> None:
        self._procedures = procedures

    def get_asset_context(self, entity_id: int, request: StartRunRequest) -> AssetContextRows:
        """One tsg_GetAssetContext call: proves the entity owns the asset and reads every fact a run uses (the
        sub-sector when sent, else the sector, with its parent)."""
        asset, services, sector, systems, options = self._procedures.execute_procedure(
            StoredProcedure.GET_ASSET_CONTEXT,
            EntityID=entity_id,
            AssetID=request.asset_id,
            SystemIDs=json.dumps(request.supporting_system_ids),
            ServiceID=request.service_id,
            SectorID=request.sector_id,
            SubsectorID=request.subsector_id,
        )
        return AssetContextRows(
            asset=asset[0] if asset else None,
            services=services,
            sector=sector[0] if sector else None,
            systems=systems,
            options=options,
        )
