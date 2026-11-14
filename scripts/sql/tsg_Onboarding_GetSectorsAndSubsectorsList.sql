-- Every live top-level sector with its live sub-sectors as one comma-separated list, one row per sector name.
-- Read-only. TSG's own copy of the onboarding platform's Onboarding_GetSectorsAndSubsectorsList. Shipped and
-- granted (StoredProcedure.GET_SECTORS_AND_SUBSECTORS); since 14 Nov 2026 the Service Mapper no longer reads it.
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE OR ALTER PROCEDURE dbo.tsg_Onboarding_GetSectorsAndSubsectorsList
AS
BEGIN
    SET NOCOUNT ON;

    SELECT 
        parent.name AS SectorName,
        -- Aggregates all active child subsectors into a comma-separated list
        STRING_AGG(sub.name, ', ') WITHIN GROUP (ORDER BY sub.name) AS SubsectorList
    FROM 
        dbo.onboarding_sectors parent
    LEFT JOIN 
        dbo.onboarding_sectors sub 
            ON sub.parent_id = parent.id 
            AND sub.is_deleted = 0 -- Ensures only active sub-sectors are included
    WHERE 
        parent.parent_id IS NULL -- Ensures we only get top-level sectors as the base
        AND parent.is_deleted = 0 -- Ensures only active top-level sectors are included
    GROUP BY 
        parent.name
    ORDER BY 
        parent.name;

END;
GO
