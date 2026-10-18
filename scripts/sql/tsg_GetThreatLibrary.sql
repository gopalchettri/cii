-- The threat library. Read-only. Called by app/data_access/sql.py (StoredProcedure.GET_THREAT_LIBRARY).
-- Result sets, in order:
--   1-6. the live library (active and not deleted): categories, types, threats, actors, type->actor links,
--        threat->category links
--   7.   pending types and threats (proposed, waiting for a curator: IsActive = 0 AND IsDeleted = 0)
--   8.   curator-rejected threats (IsDeleted = 1 AND IsActive = 0; a live row later retired keeps IsActive = 1)
-- Sets 7 and 8 serve the in-memory name checks before a write (promote, hand-written scenarios): a name already
-- pending is reused, a rejected one is never proposed again.
-- Threat_Catalogue.AssetType (owner 2026-10-12, G211): IT, OT or IT\OT (both); NULL fits every asset and system. The
-- column must exist before this procedure is installed.
CREATE OR ALTER PROCEDURE dbo.tsg_GetThreatLibrary
AS
BEGIN
    SET NOCOUNT ON;

    SELECT ThreatCategoryID, ThreatCategoryName
    FROM dbo.Threat_Category
    WHERE IsActive = 1 AND IsDeleted = 0;

    SELECT ThreatTypeID, ThreatTypeName, ThreatCategoryID
    FROM dbo.Threat_Type
    WHERE IsActive = 1 AND IsDeleted = 0;

    SELECT c.ThreatCatalogueID, c.ThreatName, c.ThreatTypeID, c.AssetType
    FROM dbo.Threat_Catalogue AS c
    JOIN dbo.Threat_Type AS t ON t.ThreatTypeID = c.ThreatTypeID AND t.IsActive = 1 AND t.IsDeleted = 0
    WHERE c.IsActive = 1 AND c.IsDeleted = 0;

    SELECT ThreatActorID, ThreatActorName
    FROM dbo.Threat_Actor
    WHERE IsActive = 1 AND IsDeleted = 0;

    SELECT ThreatTypeID, ThreatActorID
    FROM dbo.ThreatType_ThreatActor_Map;

    SELECT ThreatCatalogueID, ThreatCategoryID
    FROM dbo.Threat_Catalogue_Category_Map;

    SELECT N'type' AS kind, t.ThreatTypeID AS id, t.ThreatTypeName AS name, CAST(NULL AS INT) AS type_id
    FROM dbo.Threat_Type AS t
    WHERE t.IsActive = 0 AND t.IsDeleted = 0
    UNION ALL
    SELECT N'threat', c.ThreatCatalogueID, c.ThreatName, c.ThreatTypeID
    FROM dbo.Threat_Catalogue AS c
    WHERE c.IsActive = 0 AND c.IsDeleted = 0;

    SELECT c.ThreatCatalogueID, c.ThreatName, c.ThreatTypeID
    FROM dbo.Threat_Catalogue AS c
    WHERE c.IsDeleted = 1 AND c.IsActive = 0;
END
GO
