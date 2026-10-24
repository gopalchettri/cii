-- Reference copy of dbo.Onboarding_GetSectorsAndSubsectorsList (Sectors and sub-sectors), the onboarding platform's own procedure.
-- The onboarding platform team owns and installs it; TSG only calls it (scripts\sql\grants.sql grants it).
-- Never install it from here: the DBA's step installs scripts\sql\tsg_*.sql only, and this file is not one.


/****** Object:  StoredProcedure [dbo].[Onboarding_GetSectorsAndSubsectorsList]    Script Date: 24-10-2026 23:51:53 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE OR ALTER PROCEDURE [dbo].[Onboarding_GetSectorsAndSubsectorsList]
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