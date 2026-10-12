-- One exact fingerprint per library table: when any value in any row changes, the app reloads its in-memory library.
-- Read-only. Called by app/data_access/library.py once a minute per process (StoredProcedure.GET_LIBRARY_STAMP), ~100 ms CPU.
--
-- Fingerprint = SHA-256 of the whole table as JSON, rows in primary-key order (so the same data = the same text).
-- SELECT * covers every column, including any column added later, and every type; NULL shows as a missing key.
-- Why not CHECKSUM_AGG(BINARY_CHECKSUM(*)) (the first version): measured on DevTest5, BINARY_CHECKSUM reads only the
-- first 255 characters of an nvarchar(max) value, so an edit at the end of a long ControlDescription was invisible,
-- and CHECKSUM_AGG combines rows like XOR, so two identical edits cancelled out.
-- Why one JSON per table, not a hash per row: per-row FOR JSON cost ~800 ms CPU per call; this costs ~100 ms.
CREATE OR ALTER PROCEDURE dbo.tsg_GetLibraryStamp
AS
BEGIN
    SET NOCOUNT ON;

    SELECT N'Threat_Category' AS table_name,
           HASHBYTES('SHA2_256', (SELECT * FROM dbo.Threat_Category ORDER BY ThreatCategoryID FOR JSON PATH)) AS fingerprint
    UNION ALL SELECT N'Threat_Type',
           HASHBYTES('SHA2_256', (SELECT * FROM dbo.Threat_Type ORDER BY ThreatTypeID FOR JSON PATH))
    UNION ALL SELECT N'Threat_Catalogue',
           HASHBYTES('SHA2_256', (SELECT * FROM dbo.Threat_Catalogue ORDER BY ThreatCatalogueID FOR JSON PATH))
    UNION ALL SELECT N'Threat_Actor',
           HASHBYTES('SHA2_256', (SELECT * FROM dbo.Threat_Actor ORDER BY ThreatActorID FOR JSON PATH))
    UNION ALL SELECT N'Threat_Catalogue_Category_Map',
           HASHBYTES('SHA2_256', (SELECT * FROM dbo.Threat_Catalogue_Category_Map
                                  ORDER BY ThreatCategoryID, ThreatCatalogueID FOR JSON PATH))
    UNION ALL SELECT N'ThreatType_ThreatActor_Map',
           HASHBYTES('SHA2_256', (SELECT * FROM dbo.ThreatType_ThreatActor_Map
                                  ORDER BY ThreatTypeID, ThreatActorID FOR JSON PATH))
    UNION ALL SELECT N'Control_Library',
           HASHBYTES('SHA2_256', (SELECT * FROM dbo.Control_Library ORDER BY ControlLibraryID FOR JSON PATH));
    -- Control_Standard and Control_Library_Standard_Map are not read by the app.
END
GO
