-- =====================================================================================================================
-- dbo.tsg_GetAssetContext: what TSG knows about one asset and its supporting systems when a run starts.
-- Read-only. Called by the app (app/data_access/asset_context.py) once per run.
-- =====================================================================================================================
--
-- HOW TO USE THIS FILE (owner 2026-10-11)
-- ---------------------------------------
-- Every column of PART 1 (the asset) and PART 4 (each supporting system) is a FACT that every step uses: threat
-- finding, scenario writing, control mapping and remediation. Nothing else reaches the AI.
--
--   * To HIDE a fact:   put -- at the start of its line.            Example:   --, e.location
--   * To SHOW it again: remove the -- you added.                     Example:     , e.location
--   * To ADD a fact:    add a new line in PART 1 or PART 4.          Example:     , ss.recovery_notes
--   * Then install this file (nothing else to change, no restart; runs already started keep what they had):
--       sqlcmd -S localhost\SQLEXPRESS -d DevTest5 -E -I -b -i scripts\sql\tsg_GetAssetContext.sql
--
-- WHAT THE APP SENDS (an example run)
--   The caller sends:   { "asset_id": 1206, "supporting_system_id": [1567,1568,1569], "entity_id": "127",
--                         "sector_id": 183, "subsector_id": 199, "service_id": 1624 }
--   The app calls:      EXEC dbo.tsg_GetAssetContext @EntityID = 127, @AssetID = 1206,
--                            @SystemIDs = N'[1567,1568,1569]', @ServiceID = 1624, @SectorID = 183, @SubsectorID = 199
--   Result:             sector = Transport (183), sub_sector = Aviation (199), critical_service = service 1624's name
--
-- WHERE TO EDIT
--   PART 0  LOOKUPS                   DO NOT EDIT     works out the service, sector and organisation values PART 1 uses
--   PART 1  ASSET FACTS               SHOW / HIDE HERE   one line per asset fact
--   PART 2  SERVICES                  DO NOT EDIT     checks the service sent in the request (404 when unknown/deleted)
--   PART 3  SECTOR                    DO NOT EDIT     checks the sector sent in the request (404 / 422)
--   PART 4  SUPPORTING SYSTEM FACTS   SHOW / HIDE HERE   one line per system fact
--   PART 5  DROPDOWN NAMES            DO NOT EDIT     lets the app turn saved dropdown values into their names
--
-- RULES
--   * Never hide id, name or category_code (marked ALWAYS NEEDED): without them every run stops with
--     "dbo.tsg_GetAssetContext must return id, name, category_code ...".
--   * The name after AS is the name the AI sees, and the name ASSET_/SYSTEM_PROPERTIES_REQUIRED use in .env. Before
--     .env requires a fact, make sure its line is shown here.
--   * A NEW dropdown column must return the option's NAME, never its saved number. The platform saves the option's
--     VALUE (1, 2, 3 ...), so match on value AND the option code (values repeat across dropdowns), e.g.
--         , (SELECT v.name FROM dbo.option_value AS v JOIN dbo.[option] AS o ON o.id = v.option_id WHERE o.code = N'backup-frequency' AND v.value = ss.backup_frequency) AS backup_frequency
--     The dropdown columns already here (marked "dropdown") return the saved number on purpose: the app turns them
--     into names with PART 5.
--   * Keep entity_technology_context the LAST asset line: when the asset's text is too long, it is cut from the end.
--   * Never name a fact alias, criticality, category_id, type_id, catalogue_id, actor_id or control_id: those names
--     are never shown to the AI, so a run stops with "reserved names" (rename it: e.g. AS asset_criticality).
--   * The asset and every supporting system need a name: a run on one without a name is refused (422).
--   * Whoever edits this file decides what reaches the AI: a sensitive column added here is sent to it.
--   * Each fact sits on its own line and starts with a comma, so -- in front hides exactly that one fact.
-- =====================================================================================================================
CREATE OR ALTER PROCEDURE dbo.tsg_GetAssetContext
    @EntityID  INT,                  -- the organisation asking (it must own the asset)
    @AssetID   INT,                  -- the asset
    @SystemIDs NVARCHAR(MAX),        -- JSON list of the supporting systems sent, e.g. N'[321,322]'
    @ServiceID   INT = NULL,         -- service_id sent, if any, e.g. 1624
    @SectorID    INT = NULL,         -- sector_id sent, if any, e.g. 183 (Transport)
    @SubsectorID INT = NULL          -- subsector_id sent, if any, e.g. 199 (Aviation)
AS
BEGIN 
    SET NOCOUNT ON;

    -- -----------------------------------------------------------------------------------------------------------------
    -- PART 0: LOOKUPS                                                                         >>> DO NOT EDIT <<<
    -- Values PART 1 shows as one-line facts.
    -- -----------------------------------------------------------------------------------------------------------------
    -- The critical service: the one sent in the request; if none was sent, every service this organisation links
    -- to the asset, joined with "; " (e.g. "Billing; Electricity transmission"). Blank and deleted services are skipped.
    DECLARE @critical_service NVARCHAR(MAX) = STUFF((
        SELECT N'; ' + sv.name
        FROM dbo.onboarding_services AS sv
        WHERE LTRIM(RTRIM(sv.name)) <> N''
          AND sv.is_deleted = 0
          AND ((@ServiceID IS NOT NULL AND sv.id = @ServiceID)
               OR (@ServiceID IS NULL AND sv.id IN (SELECT bu.service_id FROM dbo.ctm_scan_entity_bu AS bu
                                                    WHERE bu.ctm_scan_entity_id = @AssetID
                                                      AND bu.group_id = @EntityID)))
        ORDER BY sv.name
        FOR XML PATH(''), TYPE).value('.', 'NVARCHAR(MAX)'), 1, 2, N'');
    -- Which sector row to read: the sub-sector when one was sent (199), else the sector (183). The sector is then
    -- the sub-sector's parent, so both names come from one row. (The app checks that a sector_id sent with a
    -- subsector_id is really its parent: 422 if not.) A deleted sector reads as unknown.
    DECLARE @sector_row INT = COALESCE(@SubsectorID, @SectorID);
    -- The sector: the parent of the sub-sector (e.g. "Transport"), or the sector itself when no sub-sector was sent.
    DECLARE @sector NVARCHAR(MAX) = (
        SELECT COALESCE(p.name, s.name)
        FROM dbo.onboarding_sectors AS s
        LEFT JOIN dbo.onboarding_sectors AS p ON p.id = s.parent_id
        WHERE s.id = @sector_row AND s.is_deleted = 0);
    -- The sub-sector: the one sent (e.g. "Aviation"); empty when only a sector was sent.
    DECLARE @sub_sector NVARCHAR(MAX) = (
        SELECT s.name
        FROM dbo.onboarding_sectors AS s
        WHERE s.id = @sector_row AND s.parent_id IS NOT NULL AND s.is_deleted = 0);
    -- The organisation's own description of its technology.
    DECLARE @entity_technology NVARCHAR(MAX) = (
        SELECT g.technology_context
        FROM dbo.[group] AS g
        WHERE g.id = @EntityID);

    -- -----------------------------------------------------------------------------------------------------------------
    -- PART 1: ASSET FACTS                                                                 >>> SHOW / HIDE HERE <<<
    -- One row, and only when the organisation owns the asset (no row = the run is refused: 403).
    -- Hide a fact: put -- at the start of its line.
    -- -----------------------------------------------------------------------------------------------------------------
    SELECT
          e.id                                              -- ALWAYS NEEDED: the asset's id (never sent to the AI)
        , e.name                                            -- ALWAYS NEEDED: the asset's name
        , cat.code AS category_code                         -- ALWAYS NEEDED: IT or OT; picks which controls fit
        -- ---- facts: put -- at the start of a line to hide it -------------------------------------------------------
        , CAST(e.description AS NVARCHAR(MAX)) AS cii_asset_description  -- what the asset is and what it does
        , @critical_service AS critical_service             -- the critical service(s) it supports (PART 0)
        , @sector AS sector                                 -- its sector, e.g. Energy (PART 0)
        , @sub_sector AS sub_sector                         -- its sub-sector, e.g. Electricity (PART 0)
        --, e.data_handled                                    -- the data it handles
        , e.type AS asset_type                                 -- how many hours of data it may lose at most
        --, e.priority AS asset_priority                      -- its priority (dropdown: the option's id, the app shows the name)
        --, e.can_service_continue_without_asset              -- 1, 0 (Yes/No)
        --, e.has_disaster_recovery_setup                     -- 1, 0 (Yes/No)
        --, e.criticality as  asset_criticality                              -- cia score
        --, @entity_technology AS entity_technology_context   -- the organisation's technology (PART 0). KEEP LAST
    FROM dbo.ctm_scan_entity AS e
    LEFT JOIN dbo.ctm_scan_category AS cat ON cat.id = e.ctm_category_id
    WHERE e.id = @AssetID
      AND EXISTS (SELECT 1 FROM dbo.ctm_scan_entity_bu AS bu
                  WHERE bu.ctm_scan_entity_id = e.id AND bu.group_id = @EntityID);

    -- -----------------------------------------------------------------------------------------------------------------
    -- PART 2: SERVICES                                                                        >>> DO NOT EDIT <<<
    -- The service sent in the request (else every service this organisation links to the asset), and whether the
    -- asset is linked to it. Only checks the request (an unknown or deleted service = 404); not a fact.
    -- -----------------------------------------------------------------------------------------------------------------
    SELECT s.id, s.name,
           CAST(CASE WHEN EXISTS (SELECT 1 FROM dbo.ctm_scan_entity_bu AS bu
                                  WHERE bu.ctm_scan_entity_id = @AssetID AND bu.service_id = s.id
                                    AND bu.group_id = @EntityID)
                     THEN 1 ELSE 0 END AS BIT) AS linked
    FROM dbo.onboarding_services AS s
    WHERE s.is_deleted = 0
      AND ((@ServiceID IS NOT NULL AND s.id = @ServiceID)
           OR (@ServiceID IS NULL AND s.id IN (SELECT bu.service_id FROM dbo.ctm_scan_entity_bu AS bu
                                               WHERE bu.ctm_scan_entity_id = @AssetID
                                                 AND bu.group_id = @EntityID)));

    -- -----------------------------------------------------------------------------------------------------------------
    -- PART 3: SECTOR                                                                          >>> DO NOT EDIT <<<
    -- The sub-sector sent (else the sector sent) and its parent. Only checks the request (unknown or deleted = 404;
    -- a sector_id that is not the sub-sector's parent = 422); not a fact.
    -- -----------------------------------------------------------------------------------------------------------------
    SELECT s.id, s.name, s.parent_id, p.name AS parent_name
    FROM dbo.onboarding_sectors AS s
    LEFT JOIN dbo.onboarding_sectors AS p ON p.id = s.parent_id
    WHERE s.id = @sector_row AND s.is_deleted = 0;

    -- -----------------------------------------------------------------------------------------------------------------
-- PART 4: SUPPORTING SYSTEM FACTS                                                     >>> SHOW / HIDE HERE <<<
-- -----------------------------------------------------------------------------------------------------------------

SELECT
      ss.id                                             -- ALWAYS NEEDED: the system's id (never sent to the AI)
    , ss.name                                           -- ALWAYS NEEDED: the system's name
    , c.code AS category_code                           -- ALWAYS NEEDED: IT or OT; picks which controls fit

    ------ facts: put -- at the start of a line to hide it -------------------------------------------------------

    , c.name AS category_name
    , ss.description
   -- , ss.incident_description AS past_incidents
   --, Technology.technology_used
   -- , ss.vendor_name
   -- , DatabasePlatforms.database_platforms
   -- , TargetedUsers.targeted_users
   -- , SaaSPlatforms.saas_platform_list
   -- , PublicCloudPlatforms.public_cloud_platforms
   -- , AccessChannel.name AS accessability_channel
  --  , HostingLocation.name AS hosting_location
  --  , ss.dr_location
  --  , NetworkConnectivity.name AS network_connectivity_primary_dr
 --   , DrDrill.name AS dr_drill_frequency
 --   , ManagedBy.name AS managed_by
 --   , ss.maintenance_contract_exists
 --   , ss.last_dr_test_date
--    , ss.backup_multi_site
--    , ss.backup_retention_period_days
--    , ss.backup_tested
--    , ss.offsite_air_gapped_backup
--    , ss.data_residency_restrictions
  --  , ss.data_residency_restriction_justification
 --   , ss.document_drp_exists
  --  , ss.saas_backup_required
  --  , ss.rto_target_mins
  --  , ss.rpo_target_mins
   -- , ss.data_loss_incident_last_3_years

FROM dbo.onboarding_supporting_systems AS ss

JOIN dbo.ctm_scan_entity_supporting_system AS link
    ON link.onboarding_supporting_system_id = ss.id
   AND link.ctm_scan_entity_id = @AssetID

LEFT JOIN dbo.ctm_scan_category AS c
    ON c.id = ss.asset_type

-- Multi-select dropdowns (JSON arrays)

OUTER APPLY (
    SELECT STRING_AGG(ov.name, ', ') AS technology_used
    FROM OPENJSON(ss.technology_used) j
    JOIN dbo.option_value ov
        ON ov.id = TRY_CAST(j.value AS INT)
) Technology

OUTER APPLY (
    SELECT STRING_AGG(ov.name, ', ') AS database_platforms
    FROM OPENJSON(ss.database_platforms) j
    JOIN dbo.option_value ov
        ON ov.id = TRY_CAST(j.value AS INT)
) DatabasePlatforms

OUTER APPLY (
    SELECT STRING_AGG(ov.name, ', ') AS targeted_users
    FROM OPENJSON(ss.targeted_users) j
    JOIN dbo.option_value ov
        ON ov.id = TRY_CAST(j.value AS INT)
) TargetedUsers

OUTER APPLY (
    SELECT STRING_AGG(ov.name, ', ') AS saas_platform_list
    FROM OPENJSON(ss.saas_platform_list) j
    JOIN dbo.option_value ov
        ON ov.id = TRY_CAST(j.value AS INT)
) SaaSPlatforms

OUTER APPLY (
    SELECT STRING_AGG(ov.name, ', ') AS public_cloud_platforms
    FROM OPENJSON(ss.public_cloud_platforms) j
    JOIN dbo.option_value ov
        ON ov.id = TRY_CAST(j.value AS INT)
) PublicCloudPlatforms

-- Single-select dropdowns

LEFT JOIN dbo.option_value AccessChannel
    ON AccessChannel.id = TRY_CAST(ss.accessability_channel AS INT)

LEFT JOIN dbo.option_value HostingLocation
    ON HostingLocation.id = TRY_CAST(ss.hosting_location AS INT)

LEFT JOIN dbo.option_value NetworkConnectivity
    ON NetworkConnectivity.id = TRY_CAST(ss.network_connectivity_primary_dr AS INT)

LEFT JOIN dbo.option_value DrDrill
    ON DrDrill.id = TRY_CAST(ss.dr_drill_frequency AS INT)

LEFT JOIN dbo.option_value ManagedBy
    ON ManagedBy.id = TRY_CAST(ss.managed_by AS INT)

WHERE ss.is_deleted = 0
  AND ss.id IN (
        --SELECT CAST([value] AS INT)
        -- FROM OPENJSON(@SystemIDs)
        SELECT CAST(j.[value] AS INT) 
        FROM OPENJSON(@SystemIDs) as j
        
      )
  AND EXISTS (
        SELECT 1
        FROM dbo.ctm_scan_entity_bu AS bu
        WHERE bu.ctm_scan_entity_id = @AssetID
          AND bu.group_id = @EntityID
      );

    -- -----------------------------------------------------------------------------------------------------------------
    -- PART 5: DROPDOWN NAMES                                                                  >>> DO NOT EDIT <<<
    -- The names of the dropdown options, so the app can show "In-house" instead of 1. The platform saves the option's
    -- VALUE (1, 2, 3 ...); priority alone is saved by the option's id, because its values repeat (7 priorities share
    -- value 5). A new dropdown fact does not need a line here: it returns its name itself (see RULES above).
    -- -----------------------------------------------------------------------------------------------------------------
    SELECT o.code,
           CASE WHEN o.code = N'priority' THEN v.id ELSE v.value END AS value,
           v.name
    FROM dbo.[option] AS o
    JOIN dbo.option_value AS v ON v.option_id = o.id
    WHERE o.code IN (N'priority', N'acc-channel', N'hosting-location', N'network-connectivity', N'dr-drill',
                     N'managed-by', N'technology-used', N'database-platforms', N'targeted-users',
                     N'saas-platforms', N'pub-c-platforms');
END
GO