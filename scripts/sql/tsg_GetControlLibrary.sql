-- Live control library. Read-only. Called by app/data_access/sql.py (StoredProcedure.GET_CONTROL_LIBRARY).
-- Two result sets: (1) the active controls; (2) every other control (retired or deleted), by code, name and
-- domain only: a plan request's register may still name one the organisation has, and the AI then gets its
-- name and domain instead of a bare number. Control_Library only:
-- Control_Standard and Control_Library_Standard_Map are not used. AssetType (was ITOT) is IT, OT or IT\OT (both;
-- owner 2026-10-12, G211).
CREATE OR ALTER PROCEDURE dbo.tsg_GetControlLibrary
AS
BEGIN
    SET NOCOUNT ON;

    SELECT ControlLibraryID, ControlCode, AssetType, Domain, ControlName, ControlDescription
    FROM dbo.Control_Library
    WHERE IsActive = 1 AND IsDeleted = 0;

    SELECT ControlLibraryID, ControlCode, Domain, ControlName
    FROM dbo.Control_Library
    WHERE NOT (IsActive = 1 AND IsDeleted = 0);
END
GO
