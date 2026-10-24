-- Reference copy of dbo.Onboarding_GetServicesWithSectorDetails (Services with their sector details), the onboarding platform's own procedure.
-- The onboarding platform team owns and installs it; TSG only calls it (scripts\sql\grants.sql grants it).
-- Never install it from here: the DBA's step installs scripts\sql\tsg_*.sql only, and this file is not one.



/****** Object:  StoredProcedure [dbo].[Onboarding_GetServicesWithSectorDetails]    Script Date: 24-10-2026 23:59:32 ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO


/* =====================================================
   Onboarding_GetServicesWithSectorDetails

   Returns every (non-deleted) onboarding service together with the
   details needed to describe it:

   - service_id, service_name, service_description
   - sectors      : comma separated list of the top-level sectors for the
     service. For every sector/sub-sector linked via
     onboarding_sector_services the top-level sector is
     resolved through the onboarding_sectors.parent_id
     relationship (a sub-sector resolves to its parent).
   - subsectors   : comma separated list of the sub-sectors
     (onboarding_sectors.parent_id IS NOT NULL) the
     service is linked to via onboarding_sector_services
   - entities     : comma separated list of the entities ([group])
     linked to the service via onboarding_service_entity
   - upstream_dependencies   : semicolon separated list of the names of the
     upstream dependency targets from onboarding_dependencies
   - downstream_dependencies : semicolon separated list of the names of the
     downstream dependency targets from onboarding_dependencies

   Optional filters:
   - @sector_id    : when supplied, only services linked to that sector
      (either directly, or through one of its sub-sectors)
      are returned.
   - @subsector_id : when supplied, only services linked to that
      sub-sector are returned.

   Both filters may be combined; when both are supplied the service must
   satisfy both conditions. Passing NULL for a filter disables it.
   ===================================================== */
CREATE OR ALTER PROCEDURE [dbo].[Onboarding_GetServicesWithSectorDetails]
 @sector_id INT = NULL,
 @subsector_id INT = NULL
AS
BEGIN
 SET NOCOUNT ON;

 SELECT
  s.id AS service_id,
  s.name AS service_name,
  s.description AS service_description,

  /* Top-level sectors for the service. Every linked sector/sub-sector
     is resolved to its top-level sector through parent_id
     (COALESCE(parent_id, id) -> a sub-sector maps to its parent,
     a top-level sector maps to itself). */
  (
   SELECT STRING_AGG(x.name, ', ') WITHIN GROUP (ORDER BY x.name)
   FROM
   (
    SELECT DISTINCT parent_sec.id, parent_sec.name
    FROM dbo.onboarding_sector_services ss
    INNER JOIN dbo.onboarding_sectors linked
     ON linked.id = ss.sector_id
       AND linked.is_deleted = 0
    INNER JOIN dbo.onboarding_sectors parent_sec
     ON parent_sec.id = COALESCE(linked.parent_id, linked.id)
       AND parent_sec.is_deleted = 0
    WHERE ss.service_id = s.id
   ) x
  ) AS sectors,

  /* Sub-sectors linked to the service */
  (
   SELECT STRING_AGG(x.name, ', ') WITHIN GROUP (ORDER BY x.name)
   FROM
   (
    SELECT DISTINCT sub.id, sub.name
    FROM dbo.onboarding_sector_services ss
    INNER JOIN dbo.onboarding_sectors sub
     ON sub.id = ss.sector_id
    WHERE ss.service_id = s.id
      AND sub.parent_id IS NOT NULL
      AND sub.is_deleted = 0
   ) x
  ) AS subsectors,

  /* Entities (groups) linked to the service */
  (
   SELECT STRING_AGG(x.name, ', ') WITHIN GROUP (ORDER BY x.name)
   FROM
   (
    SELECT DISTINCT g.id, g.name
    FROM dbo.onboarding_service_entity ose
    INNER JOIN dbo.[group] g
     ON g.id = ose.group_id
    WHERE ose.service_id = s.id
   ) x
  ) AS entities,

  /* Upstream dependency targets (names aggregated with ';') */
  (
   SELECT STRING_AGG(x.target_name, '; ') WITHIN GROUP (ORDER BY x.target_name)
   FROM
   (
    SELECT DISTINCT
     CASE d.target_type
      WHEN 'Entity'           THEN dep_group.name
      WHEN 'Organization'     THEN dep_group.name
      WHEN 'Service'          THEN dep_service.name
      WHEN 'Sector'           THEN dep_sector.name
      WHEN 'SupportingSystem' THEN dep_support.name
      WHEN 'Asset'            THEN dep_asset.name
     END AS target_name
    FROM dbo.onboarding_dependencies d
    INNER JOIN dbo.option_value dep_type
     ON dep_type.id = d.dependency_type_id
    LEFT JOIN dbo.[group] dep_group
     ON dep_group.id = d.target_id
       AND d.target_type IN ('Entity', 'Organization')
       AND dep_group.is_deleted = 0
    LEFT JOIN dbo.onboarding_services dep_service
     ON dep_service.id = d.target_id
       AND d.target_type = 'Service'
       AND dep_service.is_deleted = 0
    LEFT JOIN dbo.onboarding_sectors dep_sector
     ON dep_sector.id = d.target_id
       AND d.target_type = 'Sector'
       AND dep_sector.is_deleted = 0
    LEFT JOIN dbo.onboarding_supporting_systems dep_support
     ON dep_support.id = d.target_id
       AND d.target_type = 'SupportingSystem'
       AND dep_support.is_deleted = 0
    LEFT JOIN dbo.ctm_scan_entity dep_asset
     ON dep_asset.id = d.target_id
       AND d.target_type = 'Asset'
       AND dep_asset.is_deleted = 0
    WHERE d.source_type = 'Service'
      AND d.source_id = s.id
      AND dep_type.name = 'Upstream'
   ) x
   WHERE x.target_name IS NOT NULL
  ) AS upstream_dependencies,

  /* Downstream dependency targets (names aggregated with ';') */
  (
   SELECT STRING_AGG(x.target_name, '; ') WITHIN GROUP (ORDER BY x.target_name)
   FROM
   (
    SELECT DISTINCT
     CASE d.target_type
      WHEN 'Entity'           THEN dep_group.name
      WHEN 'Organization'     THEN dep_group.name
      WHEN 'Service'          THEN dep_service.name
      WHEN 'Sector'           THEN dep_sector.name
      WHEN 'SupportingSystem' THEN dep_support.name
      WHEN 'Asset'            THEN dep_asset.name
     END AS target_name
    FROM dbo.onboarding_dependencies d
    INNER JOIN dbo.option_value dep_type
     ON dep_type.id = d.dependency_type_id
    LEFT JOIN dbo.[group] dep_group
     ON dep_group.id = d.target_id
       AND d.target_type IN ('Entity', 'Organization')
       AND dep_group.is_deleted = 0
    LEFT JOIN dbo.onboarding_services dep_service
     ON dep_service.id = d.target_id
       AND d.target_type = 'Service'
       AND dep_service.is_deleted = 0
    LEFT JOIN dbo.onboarding_sectors dep_sector
     ON dep_sector.id = d.target_id
       AND d.target_type = 'Sector'
       AND dep_sector.is_deleted = 0
    LEFT JOIN dbo.onboarding_supporting_systems dep_support
     ON dep_support.id = d.target_id
       AND d.target_type = 'SupportingSystem'
       AND dep_support.is_deleted = 0
    LEFT JOIN dbo.ctm_scan_entity dep_asset
     ON dep_asset.id = d.target_id
       AND d.target_type = 'Asset'
       AND dep_asset.is_deleted = 0
    WHERE d.source_type = 'Service'
      AND d.source_id = s.id
      AND dep_type.name = 'Downstream'
   ) x
   WHERE x.target_name IS NOT NULL
  ) AS downstream_dependencies

 FROM dbo.onboarding_services s
 WHERE s.is_deleted = 0

   /* Optional sector filter: direct link or via one of its sub-sectors */
   AND (
   @sector_id IS NULL
   OR EXISTS
   (
    SELECT 1
    FROM dbo.onboarding_sector_services ss
    INNER JOIN dbo.onboarding_sectors sec
     ON sec.id = ss.sector_id
    WHERE ss.service_id = s.id
      AND (sec.id = @sector_id OR sec.parent_id = @sector_id)
   )
    )

   /* Optional sub-sector filter */
   AND (
   @subsector_id IS NULL
   OR EXISTS
   (
    SELECT 1
    FROM dbo.onboarding_sector_services ss
    WHERE ss.service_id = s.id
      AND ss.sector_id = @subsector_id
   )
    )

 ORDER BY s.name;
END;
 
GO


