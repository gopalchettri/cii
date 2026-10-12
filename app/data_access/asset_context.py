"""The asset context of a run: one tsg_GetAssetContext call proves the entity owns the asset and reads every
fact the run is built from (StoredProcedure.GET_ASSET_CONTEXT): the procedure's columns are the facts."""

import json

from app.core.constants import StoredProcedure
from app.core.database import StoredProcedureClient
from app.models.asset_context import AssetContextRows


class AssetContextRepository:
    def __init__(self, procedures: StoredProcedureClient) -> None:
        self._procedures = procedures

    def read(  # noqa: PLR0913 — the procedure's own parameters, one each
        self,
        entity_id: int,
        asset_id: int,
        system_ids: list[int],
        service_id: int | None,
        sector_id: int | None,
        subsector_id: int | None,
    ) -> AssetContextRows:
        """`sector_id` and `subsector_id` as the caller sent them: the procedure reads the sub-sector when
        sent, else the sector, with its parent."""
        asset, services, sector, systems, options = self._procedures.execute_procedure(
            StoredProcedure.GET_ASSET_CONTEXT,
            EntityID=entity_id,
            AssetID=asset_id,
            SystemIDs=json.dumps(system_ids),
            ServiceID=service_id,
            SectorID=sector_id,
            SubsectorID=subsector_id,
        )
        return AssetContextRows(
            asset=asset[0] if asset else None,
            services=services,
            sector=sector[0] if sector else None,
            systems=systems,
            options=options,
        )
