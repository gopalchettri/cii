-- The test database's tables (BLUEPRINT R-11): the 7 library tables and the 10 platform tables TSG's procedures
-- read, with only the columns they use, the same types as DevTest5, and the same unique keys (the procedures rely
-- on them: names are unique among non-deleted rows). Built by scripts/build_sql_test_database.py into a database
-- of its own (never DevTest5), then seeded by tests/sql/seed.sql.
SET NOCOUNT ON;

-- Platform tables (owned by the onboarding product; TSG only reads them through tsg_GetAssetContext).
CREATE TABLE dbo.[group] (id INT IDENTITY PRIMARY KEY, name NVARCHAR(255) NULL,
    is_deleted BIT NOT NULL DEFAULT 0, technology_context NVARCHAR(MAX) NULL);
CREATE TABLE dbo.ctm_scan_category (id INT IDENTITY PRIMARY KEY, code NVARCHAR(45) NULL, name NVARCHAR(255) NULL);
CREATE TABLE dbo.ctm_scan_entity (
    id INT IDENTITY PRIMARY KEY, type NVARCHAR(255) NULL, name NVARCHAR(255) NULL, ctm_category_id INT NULL,
    description TEXT NULL, operating_system NVARCHAR(255) NULL, location NVARCHAR(255) NULL, criticality INT NULL,
    target_rto_hours DECIMAL(18, 0) NULL, target_rpo_hours DECIMAL(18, 0) NULL, priority INT NULL,
    data_handled NVARCHAR(MAX) NULL, can_service_continue_without_asset BIT NULL,
    has_disaster_recovery_setup BIT NULL, is_deleted BIT NOT NULL DEFAULT 0);
CREATE TABLE dbo.onboarding_services (
    id INT IDENTITY PRIMARY KEY, name NVARCHAR(255) NOT NULL, description NVARCHAR(MAX) NULL,
    sector_id INT NULL, is_deleted BIT NOT NULL DEFAULT 0);
CREATE TABLE dbo.onboarding_sectors (
    id INT IDENTITY PRIMARY KEY, name NVARCHAR(255) NOT NULL, parent_id INT NULL, is_deleted BIT NOT NULL DEFAULT 0);
CREATE TABLE dbo.onboarding_sector_services (sector_id INT NOT NULL, service_id INT NOT NULL);
CREATE TABLE dbo.onboarding_service_entity (sector_id INT NOT NULL, service_id INT NOT NULL,
    group_id INT NOT NULL);
CREATE TABLE dbo.ctm_scan_entity_bu (
    id INT IDENTITY PRIMARY KEY, ctm_scan_entity_id INT NOT NULL, group_id INT NOT NULL, service_id INT NULL);
CREATE TABLE dbo.onboarding_supporting_systems (
    id INT IDENTITY PRIMARY KEY, name NVARCHAR(255) NOT NULL, asset_type INT NOT NULL,
    min_no_of_transactions INT NULL, max_no_of_transactions INT NULL, accessability_channel INT NULL,
    technology_used NVARCHAR(255) NULL, user_base_count INT NULL, targeted_users NVARCHAR(255) NULL,
    managed_by INT NOT NULL, vendor_name NVARCHAR(255) NULL, maintenance_contract_exists BIT NULL,
    hosting_location INT NULL, dr_location NVARCHAR(255) NULL, network_connectivity_primary_dr INT NULL,
    last_dr_test_date DATETIME NOT NULL, backup_multi_site BIT NULL, backup_retention_period_days INT NULL,
    backup_tested BIT NULL, offsite_air_gapped_backup BIT NULL, data_residency_restrictions BIT NULL,
    data_residency_restriction_justification NVARCHAR(500) NULL, document_drp_exists BIT NULL,
    dr_drill_frequency INT NOT NULL, database_platforms NVARCHAR(255) NULL, saas_backup_required BIT NULL,
    saas_platform_list NVARCHAR(500) NULL, public_cloud_platforms NVARCHAR(500) NULL,
    rto_target_mins DECIMAL(18, 0) NOT NULL, rpo_target_mins DECIMAL(18, 0) NOT NULL,
    data_loss_incident_last_3_years BIT NULL, incident_description NVARCHAR(MAX) NULL, is_deleted BIT NOT NULL,
    description NVARCHAR(MAX) NULL);
CREATE TABLE dbo.ctm_scan_entity_supporting_system (
    ctm_scan_entity_id INT NOT NULL, onboarding_supporting_system_id INT NOT NULL);
CREATE TABLE dbo.[option] (id INT IDENTITY PRIMARY KEY, code NVARCHAR(20) NULL);
CREATE TABLE dbo.option_value (
    id INT IDENTITY PRIMARY KEY, name NVARCHAR(50) NULL, value INT NULL, option_id INT NULL);
CREATE TABLE dbo.onboarding_dependencies (
    id INT IDENTITY PRIMARY KEY, source_type NVARCHAR(50) NOT NULL, source_id INT NOT NULL,
    target_type NVARCHAR(50) NOT NULL, target_id INT NOT NULL, dependency_type_id INT NOT NULL);

-- Library tables (TSG reads them all; the write procedures write the threat ones).
CREATE TABLE dbo.Threat_Category (
    ThreatCategoryID INT NOT NULL PRIMARY KEY, ThreatCategoryName NVARCHAR(200) NOT NULL,
    IsActive BIT NOT NULL, IsDeleted BIT NOT NULL, CreatedAt DATETIME2 NULL, CreatedBy NVARCHAR(200) NULL);
CREATE TABLE dbo.Threat_Type (
    ThreatTypeID INT IDENTITY PRIMARY KEY, ThreatTypeName NVARCHAR(300) NOT NULL, ThreatCategoryID INT NULL,
    IsActive BIT NOT NULL, IsDeleted BIT NOT NULL, Source NVARCHAR(50) NULL, CreatedAt DATETIME2 NULL,
    CreatedBy NVARCHAR(200) NULL, UpdatedAt DATETIME2 NULL, UpdatedBy NVARCHAR(200) NULL);
CREATE UNIQUE INDEX UX_ThreatType_NaturalKey ON dbo.Threat_Type (ThreatTypeName) WHERE IsDeleted = 0;
CREATE TABLE dbo.Threat_Catalogue (
    ThreatCatalogueID INT IDENTITY PRIMARY KEY, ThreatTypeID INT NOT NULL, ThreatName NVARCHAR(500) NOT NULL,
    IsActive BIT NOT NULL, IsDeleted BIT NOT NULL, Source NVARCHAR(100) NULL, CreatedAt DATETIME2 NULL,
    CreatedBy NVARCHAR(200) NULL, UpdatedAt DATETIME2 NULL, UpdatedBy NVARCHAR(200) NULL,
    AssetType NVARCHAR(100) NULL);
CREATE UNIQUE INDEX UX_ThreatCatalogue_NaturalKey ON dbo.Threat_Catalogue (ThreatName) WHERE IsDeleted = 0;
CREATE TABLE dbo.Threat_Actor (
    ThreatActorID INT IDENTITY PRIMARY KEY, ThreatActorName NVARCHAR(200) NOT NULL, IsCapable INT NOT NULL,
    IsActive BIT NOT NULL, IsDeleted BIT NOT NULL, Source NVARCHAR(100) NULL, CreatedAt DATETIME2 NULL,
    CreatedBy NVARCHAR(200) NULL);
CREATE UNIQUE INDEX UX_ThreatActor_NaturalKey ON dbo.Threat_Actor (ThreatActorName) WHERE IsActive = 1 AND IsDeleted = 0;
CREATE TABLE dbo.Threat_Catalogue_Category_Map (
    ThreatCatalogueID INT NOT NULL, ThreatCategoryID INT NOT NULL, CreatedAt DATETIME2 NULL,
    PRIMARY KEY (ThreatCategoryID, ThreatCatalogueID));
CREATE TABLE dbo.ThreatType_ThreatActor_Map (
    ThreatTypeID INT NOT NULL, ThreatActorID INT NOT NULL, CreatedAt DATETIME2 NULL,
    PRIMARY KEY (ThreatTypeID, ThreatActorID));
CREATE TABLE dbo.Control_Library (
    ControlLibraryID INT IDENTITY PRIMARY KEY, ControlCode NVARCHAR(100) NOT NULL, AssetType NVARCHAR(100) NOT NULL,
    Domain NVARCHAR(200) NOT NULL, ControlName NVARCHAR(500) NOT NULL, ControlDescription NVARCHAR(MAX) NOT NULL,
    IsActive BIT NOT NULL, IsDeleted BIT NOT NULL);
GO
