-- Propose a threat to the library: the only write of AI-proposed and hand-written threats (BLUEPRINT M05 L4).
-- Called by app/data_access/library.py (StoredProcedure.RESOLVE_THREAT) when the in-memory check found the threat
-- missing: promote-to-library (#27, Source 'ai') and hand-written scenarios (Source 'manual').
-- New rows are PENDING (IsActive = 0): a curator activates them (tsg_DecidePendingThreats). Accepting a scenario
-- never writes here.
-- One result row: threat_type_id, threat_catalogue_id, outcome
--   existing_active   the threat name is live already: nothing written
--   existing_pending  the threat name is already waiting for a curator: nothing written
--   created_pending   the threat (and its type, when new) was inserted as pending
-- Names are unique among non-deleted rows (UX_ThreatType_NaturalKey, UX_ThreatCatalogue_NaturalKey), compared
-- case-insensitively by SQL Server. The re-checks run under UPDLOCK, HOLDLOCK, so two callers proposing the same
-- name wait for each other; a duplicate-key race that still slips through returns the row that won.
CREATE OR ALTER PROCEDURE dbo.tsg_ResolveThreat
    @CategoryName NVARCHAR(200),          -- a live STRIDE category, or NULL: saved without a category link
    @TypeName     NVARCHAR(300),
    @ThreatName   NVARCHAR(500),
    @Source       NVARCHAR(50),           -- 'manual' | 'ai'
    @CreatedBy    NVARCHAR(200),
    @ActorIDs     NVARCHAR(MAX) = NULL    -- JSON array of live actor ids, linked to a NEW type only, e.g. N'[3,5]'
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    IF @Source NOT IN (N'manual', N'ai')
        THROW 50001, N'tsg_ResolveThreat: @Source must be manual or ai.', 1;

    DECLARE @CategoryID INT = (SELECT ThreatCategoryID FROM dbo.Threat_Category
                               WHERE ThreatCategoryName = @CategoryName AND IsActive = 1 AND IsDeleted = 0);
    DECLARE @TypeID INT, @ThreatID INT, @ThreatActive BIT, @Created BIT = 0, @TypeCreated BIT = 0;

    BEGIN TRY
        BEGIN TRANSACTION;
        -- An existing threat is answered as it is, under its own type: a live row is never changed from here.
        SELECT @ThreatID = ThreatCatalogueID, @TypeID = ThreatTypeID, @ThreatActive = IsActive
        FROM dbo.Threat_Catalogue WITH (UPDLOCK, HOLDLOCK)
        WHERE ThreatName = @ThreatName AND IsDeleted = 0;

        IF @ThreatID IS NULL
        BEGIN
            SELECT @TypeID = ThreatTypeID
            FROM dbo.Threat_Type WITH (UPDLOCK, HOLDLOCK)
            WHERE ThreatTypeName = @TypeName AND IsDeleted = 0;
            IF @TypeID IS NULL
            BEGIN
                INSERT dbo.Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source, CreatedBy, CreatedAt)
                VALUES (@TypeName, @CategoryID, 0, 0, @Source, @CreatedBy, SYSUTCDATETIME());
                SELECT @TypeID = SCOPE_IDENTITY(), @TypeCreated = 1;
            END

            INSERT dbo.Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source, CreatedBy, CreatedAt)
            VALUES (@TypeID, @ThreatName, 0, 0, @Source, @CreatedBy, SYSUTCDATETIME());
            SELECT @ThreatID = SCOPE_IDENTITY(), @ThreatActive = 0, @Created = 1;

            IF @CategoryID IS NOT NULL
                INSERT dbo.Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID, CreatedAt)
                VALUES (@ThreatID, @CategoryID, SYSUTCDATETIME());

            IF @TypeCreated = 1 AND @ActorIDs IS NOT NULL
                INSERT dbo.ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID, CreatedAt)
                SELECT @TypeID, a.ThreatActorID, SYSUTCDATETIME()
                FROM dbo.Threat_Actor AS a
                WHERE a.IsActive = 1 AND a.IsDeleted = 0
                  AND a.ThreatActorID IN (SELECT DISTINCT CAST([value] AS INT) FROM OPENJSON(@ActorIDs));
        END
        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        IF ERROR_NUMBER() NOT IN (2601, 2627) THROW;   -- only a duplicate-key race is answered, below
        SELECT @ThreatID = NULL, @TypeID = NULL, @Created = 0;
        SELECT @ThreatID = ThreatCatalogueID, @TypeID = ThreatTypeID, @ThreatActive = IsActive
        FROM dbo.Threat_Catalogue
        WHERE ThreatName = @ThreatName AND IsDeleted = 0;
        IF @ThreatID IS NULL THROW;   -- the clash was on the type alone: let the caller retry
    END CATCH

    SELECT @TypeID AS threat_type_id, @ThreatID AS threat_catalogue_id,
           CASE WHEN @Created = 1 THEN N'created_pending'
                WHEN @ThreatActive = 1 THEN N'existing_active'
                ELSE N'existing_pending' END AS outcome;
END
GO
