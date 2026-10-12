-- A curator's decisions on pending threats, in one transaction.
-- Called by app/data_access/pending_threats.py (StoredProcedure.DECIDE_PENDING_THREATS). The API checks the lists
-- first: 1-100 ids in total, no id in both.
--   Approve: IsActive = 1, its pending parent type first (a type goes live with its first approved threat).
--   Reject:  IsDeleted = 1 on a PENDING row only (curator-rejected = IsDeleted 1, IsActive 0), and on its pending type
--            when that type has no other threat left that is not deleted.
-- One result row per id: catalogue_id, outcome
--   approved | already_approved | rejected | already_rejected | is_approved (asked to reject a live row: nothing
--   changed) | not_found
CREATE OR ALTER PROCEDURE dbo.tsg_DecidePendingThreats
    @ApproveIDs NVARCHAR(MAX),     -- JSON array of catalogue ids, e.g. N'[512]'; N'[]' for none
    @RejectIDs  NVARCHAR(MAX),
    @DecidedBy  NVARCHAR(200)
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @Requests TABLE (catalogue_id INT PRIMARY KEY, decision NCHAR(1));   -- A approve, R reject
    INSERT @Requests (catalogue_id, decision)
    SELECT DISTINCT CAST([value] AS INT), N'A' FROM OPENJSON(@ApproveIDs);
    INSERT @Requests (catalogue_id, decision)
    SELECT DISTINCT CAST(j.[value] AS INT), N'R' FROM OPENJSON(@RejectIDs) AS j
    WHERE CAST(j.[value] AS INT) NOT IN (SELECT catalogue_id FROM @Requests);

    DECLARE @Results TABLE (catalogue_id INT PRIMARY KEY, type_id INT NULL, outcome NVARCHAR(20));
    DECLARE @Now DATETIME2 = SYSUTCDATETIME();

    BEGIN TRANSACTION;
    -- Each outcome from the row as it is now, locked until the commit.
    INSERT @Results (catalogue_id, type_id, outcome)
    SELECT r.catalogue_id, c.ThreatTypeID,
           CASE WHEN c.ThreatCatalogueID IS NULL THEN N'not_found'
                WHEN c.IsDeleted = 1 THEN N'already_rejected'
                WHEN r.decision = N'A' AND c.IsActive = 1 THEN N'already_approved'
                WHEN r.decision = N'A' THEN N'approved'
                WHEN c.IsActive = 1 THEN N'is_approved'
                ELSE N'rejected' END
    FROM @Requests AS r
    LEFT JOIN dbo.Threat_Catalogue AS c WITH (UPDLOCK, HOLDLOCK) ON c.ThreatCatalogueID = r.catalogue_id;

    UPDATE t SET IsActive = 1, UpdatedAt = @Now, UpdatedBy = @DecidedBy
    FROM dbo.Threat_Type AS t
    WHERE t.IsActive = 0 AND t.IsDeleted = 0
      AND t.ThreatTypeID IN (SELECT type_id FROM @Results WHERE outcome = N'approved');

    UPDATE c SET IsActive = 1, UpdatedAt = @Now, UpdatedBy = @DecidedBy
    FROM dbo.Threat_Catalogue AS c
    JOIN @Results AS r ON r.catalogue_id = c.ThreatCatalogueID AND r.outcome = N'approved';

    UPDATE c SET IsDeleted = 1, UpdatedAt = @Now, UpdatedBy = @DecidedBy
    FROM dbo.Threat_Catalogue AS c
    JOIN @Results AS r ON r.catalogue_id = c.ThreatCatalogueID AND r.outcome = N'rejected';

    UPDATE t SET IsDeleted = 1, UpdatedAt = @Now, UpdatedBy = @DecidedBy
    FROM dbo.Threat_Type AS t
    WHERE t.IsActive = 0 AND t.IsDeleted = 0
      AND t.ThreatTypeID IN (SELECT type_id FROM @Results WHERE outcome = N'rejected')
      AND NOT EXISTS (SELECT 1 FROM dbo.Threat_Catalogue AS c
                      WHERE c.ThreatTypeID = t.ThreatTypeID AND c.IsDeleted = 0);
    COMMIT TRANSACTION;

    SELECT catalogue_id, outcome FROM @Results ORDER BY catalogue_id;
END
GO
