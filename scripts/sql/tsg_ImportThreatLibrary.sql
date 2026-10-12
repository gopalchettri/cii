-- Import a library source (pytm, emb3d, atlas, misp_actors) in one transaction.
-- Called by app/data_access/library_imports.py (StoredProcedure.IMPORT_THREAT_LIBRARY).
-- Inserts only what is missing ("first writer wins"): an existing type, threat or actor is counted as existing and
-- keeps its own IsActive and links. A threat row is skipped when a name is blank, its category is not a live
-- category, or a curator rejected that threat. A dry run computes the same counts and rolls everything back.
-- @Rows: a JSON array of {"kind": "threat", "category": ..., "type": ..., "threat": ...}
--                    and {"kind": "actor", "actor_name": ...}
-- One result row per kind (actor, threat, type): kind, inserted, existing, skipped
CREATE OR ALTER PROCEDURE dbo.tsg_ImportThreatLibrary
    @Source    NVARCHAR(100),
    @Rows      NVARCHAR(MAX),
    @Activate  BIT = 1,            -- 0: new rows are pending, for a curator to approve
    @DryRun    BIT = 0,
    @CreatedBy NVARCHAR(200)
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @Now DATETIME2 = SYSUTCDATETIME();

    DECLARE @Threats TABLE (category NVARCHAR(200), type_name NVARCHAR(300), threat NVARCHAR(500));
    INSERT @Threats (category, type_name, threat)
    SELECT LTRIM(RTRIM(ISNULL(category, N''))), LTRIM(RTRIM(ISNULL(type_name, N''))), LTRIM(RTRIM(ISNULL(threat, N'')))
    FROM OPENJSON(@Rows) WITH (kind NVARCHAR(10) '$.kind', category NVARCHAR(200) '$.category',
                               type_name NVARCHAR(300) '$.type', threat NVARCHAR(500) '$.threat')
    WHERE kind = N'threat';

    DECLARE @Actors TABLE (actor_name NVARCHAR(200));
    INSERT @Actors (actor_name)
    SELECT LTRIM(RTRIM(ISNULL(actor_name, N'')))
    FROM OPENJSON(@Rows) WITH (kind NVARCHAR(10) '$.kind', actor_name NVARCHAR(200) '$.actor_name')
    WHERE kind = N'actor';

    DECLARE @Usable TABLE (threat NVARCHAR(500), type_name NVARCHAR(300), category_id INT);
    DECLARE @TypeIDs TABLE (type_name NVARCHAR(300) PRIMARY KEY, type_id INT, created BIT);
    DECLARE @ThreatIDs TABLE (threat NVARCHAR(500) PRIMARY KEY, catalogue_id INT, created BIT);
    DECLARE @ActorNames TABLE (actor_name NVARCHAR(200) PRIMARY KEY, created BIT);

    BEGIN TRANSACTION;
    INSERT @Usable (threat, type_name, category_id)
    SELECT r.threat, r.type_name, cat.ThreatCategoryID
    FROM @Threats AS r
    JOIN dbo.Threat_Category AS cat
      ON cat.ThreatCategoryName = r.category AND cat.IsActive = 1 AND cat.IsDeleted = 0
    WHERE r.type_name <> N'' AND r.threat <> N''
      AND NOT EXISTS (SELECT 1 FROM dbo.Threat_Catalogue AS c
                      WHERE c.ThreatName = r.threat AND c.IsDeleted = 1 AND c.IsActive = 0);

    -- Types: the existing ones (locked), then the missing ones.
    INSERT @TypeIDs (type_name, type_id, created)
    SELECT u.type_name, t.ThreatTypeID, 0
    FROM (SELECT DISTINCT type_name FROM @Usable) AS u
    JOIN dbo.Threat_Type AS t WITH (UPDLOCK, HOLDLOCK) ON t.ThreatTypeName = u.type_name AND t.IsDeleted = 0;
    INSERT dbo.Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source, CreatedBy, CreatedAt)
    OUTPUT inserted.ThreatTypeName, inserted.ThreatTypeID, 1 INTO @TypeIDs (type_name, type_id, created)
    SELECT u.type_name, MIN(u.category_id), @Activate, 0, @Source, @CreatedBy, @Now
    FROM @Usable AS u
    WHERE u.type_name NOT IN (SELECT type_name FROM @TypeIDs)
    GROUP BY u.type_name;

    -- Threats: the same, each under its row's type; a new threat gets its rows' category links.
    INSERT @ThreatIDs (threat, catalogue_id, created)
    SELECT u.threat, c.ThreatCatalogueID, 0
    FROM (SELECT DISTINCT threat FROM @Usable) AS u
    JOIN dbo.Threat_Catalogue AS c WITH (UPDLOCK, HOLDLOCK) ON c.ThreatName = u.threat AND c.IsDeleted = 0;
    INSERT dbo.Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source, CreatedBy, CreatedAt)
    OUTPUT inserted.ThreatName, inserted.ThreatCatalogueID, 1 INTO @ThreatIDs (threat, catalogue_id, created)
    SELECT MIN(ty.type_id), u.threat, @Activate, 0, @Source, @CreatedBy, @Now
    FROM @Usable AS u
    JOIN @TypeIDs AS ty ON ty.type_name = u.type_name
    WHERE u.threat NOT IN (SELECT threat FROM @ThreatIDs)
    GROUP BY u.threat;
    INSERT dbo.Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID, CreatedAt)
    SELECT DISTINCT th.catalogue_id, u.category_id, @Now
    FROM @Usable AS u
    JOIN @ThreatIDs AS th ON th.threat = u.threat AND th.created = 1;

    -- Actors.
    INSERT @ActorNames (actor_name, created)
    SELECT DISTINCT a.actor_name, 0
    FROM @Actors AS a
    WHERE a.actor_name <> N''
      AND EXISTS (SELECT 1 FROM dbo.Threat_Actor AS x WITH (UPDLOCK, HOLDLOCK)
                  WHERE x.ThreatActorName = a.actor_name AND x.IsDeleted = 0);
    INSERT dbo.Threat_Actor (ThreatActorName, IsCapable, IsActive, IsDeleted, Source, CreatedBy, CreatedAt)
    OUTPUT inserted.ThreatActorName, 1 INTO @ActorNames (actor_name, created)
    SELECT DISTINCT a.actor_name, 1, @Activate, 0, @Source, @CreatedBy, @Now
    FROM @Actors AS a
    WHERE a.actor_name <> N'' AND a.actor_name NOT IN (SELECT actor_name FROM @ActorNames);

    IF @DryRun = 1 ROLLBACK TRANSACTION ELSE COMMIT TRANSACTION;   -- table variables keep their rows either way

    SELECT N'actor' AS kind,
           (SELECT COUNT(*) FROM @ActorNames WHERE created = 1) AS inserted,
           (SELECT COUNT(*) FROM @ActorNames WHERE created = 0) AS existing,
           (SELECT COUNT(*) FROM @Actors WHERE actor_name = N'') AS skipped
    UNION ALL
    SELECT N'threat',
           (SELECT COUNT(*) FROM @ThreatIDs WHERE created = 1),
           (SELECT COUNT(*) FROM @ThreatIDs WHERE created = 0),
           (SELECT COUNT(DISTINCT threat) FROM @Threats) - (SELECT COUNT(DISTINCT threat) FROM @Usable)
    UNION ALL
    SELECT N'type',
           (SELECT COUNT(*) FROM @TypeIDs WHERE created = 1),
           (SELECT COUNT(*) FROM @TypeIDs WHERE created = 0),
           0;
END
GO
