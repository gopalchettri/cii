-- Threats waiting for a curator (pending: IsActive = 0 AND IsDeleted = 0), oldest first.
-- Read-only. Called by app/data_access/sql.py (StoredProcedure.LIST_PENDING_THREATS).
-- Result sets, in order:
--   1. one page: catalogue_id, threat, threat_type, type_pending (the type is pending too), categories (a JSON array
--      of names), source ('manual' | 'ai'), created_by, created_at
--   2. total: every pending threat, for paging
CREATE OR ALTER PROCEDURE dbo.tsg_ListPendingThreats
    @Offset INT = 0,
    @Limit  INT = 50
AS
BEGIN
    SET NOCOUNT ON;

    SELECT c.ThreatCatalogueID AS catalogue_id, c.ThreatName AS threat, t.ThreatTypeName AS threat_type,
           CAST(CASE WHEN t.IsActive = 0 THEN 1 ELSE 0 END AS BIT) AS type_pending,
           ISNULL((SELECT cat.ThreatCategoryName AS [name]
                   FROM dbo.Threat_Catalogue_Category_Map AS m
                   JOIN dbo.Threat_Category AS cat ON cat.ThreatCategoryID = m.ThreatCategoryID
                   WHERE m.ThreatCatalogueID = c.ThreatCatalogueID
                   ORDER BY cat.ThreatCategoryName
                   FOR JSON PATH), N'[]') AS categories,
           c.Source AS source, c.CreatedBy AS created_by, c.CreatedAt AS created_at
    FROM dbo.Threat_Catalogue AS c
    JOIN dbo.Threat_Type AS t ON t.ThreatTypeID = c.ThreatTypeID
    WHERE c.IsActive = 0 AND c.IsDeleted = 0
    ORDER BY c.CreatedAt, c.ThreatCatalogueID
    OFFSET @Offset ROWS FETCH NEXT @Limit ROWS ONLY;

    SELECT COUNT(*) AS total
    FROM dbo.Threat_Catalogue
    WHERE IsActive = 0 AND IsDeleted = 0;
END
GO
