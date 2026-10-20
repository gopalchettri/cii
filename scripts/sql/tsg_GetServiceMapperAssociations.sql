-- Read-only, normalized associations for the Service Mapper. The three onboarding procedures provide
-- the catalog and descriptive context; their comma-separated fields cannot preserve exact relationships.
-- Keep this procedure separate so existing onboarding result contracts remain unchanged.
CREATE OR ALTER PROCEDURE dbo.tsg_GetServiceMapperAssociations
AS
BEGIN
    SET NOCOUNT ON;

    -- Result 1: every live sector and its parent. Names are never parsed to infer the hierarchy.
    SELECT sector.id AS sector_id, sector.name AS sector_name,
           parent.id AS parent_sector_id, parent.name AS parent_sector_name
    FROM dbo.onboarding_sectors AS sector
    LEFT JOIN dbo.onboarding_sectors AS parent
        ON parent.id = sector.parent_id AND parent.is_deleted = 0
    WHERE sector.is_deleted = 0
      AND (sector.parent_id IS NULL OR parent.id IS NOT NULL)
    ORDER BY sector.id;

    -- Result 2: exact service-to-sector links. Include the service's own sector_id even when
    -- the junction has not yet been populated; UNION removes duplicate links.
    SELECT service.id AS service_id, link.sector_id AS sector_id
    FROM dbo.onboarding_services AS service
    JOIN dbo.onboarding_sector_services AS link ON link.service_id = service.id
    JOIN dbo.onboarding_sectors AS sector ON sector.id = link.sector_id AND sector.is_deleted = 0
    WHERE service.is_deleted = 0
    UNION
    SELECT service.id, service.sector_id
    FROM dbo.onboarding_services AS service
    JOIN dbo.onboarding_sectors AS sector ON sector.id = service.sector_id AND sector.is_deleted = 0
    WHERE service.is_deleted = 0
    ORDER BY service_id, sector_id;

    -- Result 3: verified entity associations, scoped to the sector link recorded by onboarding.
    SELECT DISTINCT association.service_id, association.sector_id,
           entity.id AS entity_id, entity.name AS entity_name
    FROM dbo.onboarding_service_entity AS association
    JOIN dbo.onboarding_services AS service
        ON service.id = association.service_id AND service.is_deleted = 0
    JOIN dbo.onboarding_sectors AS sector
        ON sector.id = association.sector_id AND sector.is_deleted = 0
    JOIN dbo.[group] AS entity
        ON entity.id = association.group_id AND entity.is_deleted = 0
    ORDER BY association.service_id, association.sector_id, entity.id;
END
GO
