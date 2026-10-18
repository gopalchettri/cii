-- The test database's rows (BLUEPRINT R-11): entity 86 owns asset 103 (category OT) with supporting systems 321 and
-- 322; system 323 exists but is not linked to the asset; entity 99 owns nothing. The library: the 6 STRIDE
-- categories, 8 types, 20 live threats, 6 actors, 30 controls (each with an AssetType), plus one pending type with
-- its pending threat, one pending threat under a live type, and one curator-rejected threat.
SET NOCOUNT ON;

SET IDENTITY_INSERT dbo.[group] ON;
INSERT dbo.[group] (id, technology_context) VALUES
    (86, N'Siemens S7-1500 PLCs, OSIsoft PI historian, Windows Server 2019 domain.'), (99, NULL);
SET IDENTITY_INSERT dbo.[group] OFF;

SET IDENTITY_INSERT dbo.ctm_scan_category ON;
INSERT dbo.ctm_scan_category (id, code, name) VALUES
    (2, N'IT', N'Information Technology (IT)'), (3, N'OT', N'Operational Technology (OT)');
SET IDENTITY_INSERT dbo.ctm_scan_category OFF;

SET IDENTITY_INSERT dbo.[option] ON;
INSERT dbo.[option] (id, code) VALUES
    (1, N'priority'), (2, N'acc-channel'), (3, N'hosting-location'), (4, N'network-connectivity'), (5, N'dr-drill'),
    (6, N'managed-by'), (7, N'technology-used'), (8, N'database-platforms'), (9, N'targeted-users'),
    (10, N'saas-platforms'), (11, N'pub-c-platforms');
SET IDENTITY_INSERT dbo.[option] OFF;
SET IDENTITY_INSERT dbo.option_value ON;
-- The platform saves an option's value (1, 2, 3 ... per dropdown, never its id); priority alone is saved by id,
-- because its values repeat (High and Low share 5, as on DevTest5).
INSERT dbo.option_value (id, option_id, name, value) VALUES
    (1, 1, N'High', 5), (14, 1, N'Low', 5), (2, 2, N'Internal network', 1), (3, 3, N'On-premises', 1),
    (4, 4, N'Dedicated fibre', 1), (5, 5, N'Yearly', 1), (6, 6, N'In-house', 1), (7, 7, N'SCADA', 1),
    (8, 7, N'Historian', 2), (9, 7, N'Windows', 3), (10, 8, N'Microsoft SQL Server', 1),
    (11, 9, N'Control room operators', 1), (12, 10, N'None', 1), (13, 11, N'Azure', 1);
SET IDENTITY_INSERT dbo.option_value OFF;

SET IDENTITY_INSERT dbo.onboarding_sectors ON;
INSERT dbo.onboarding_sectors (id, name, parent_id, is_deleted) VALUES
    (10, N'Energy', NULL, 0), (11, N'Electricity', 10, 0), (12, N'Retired sub-sector', 10, 1);
SET IDENTITY_INSERT dbo.onboarding_sectors OFF;
SET IDENTITY_INSERT dbo.onboarding_services ON;
INSERT dbo.onboarding_services (id, name, is_deleted) VALUES
    (1, N'Electricity transmission', 0), (2, N'Customer billing', 0), (3, N'Retired service', 1);
SET IDENTITY_INSERT dbo.onboarding_services OFF;

SET IDENTITY_INSERT dbo.ctm_scan_entity ON;
INSERT dbo.ctm_scan_entity (id, type, name, ctm_category_id, description, operating_system, location, criticality,
                            target_rto_hours, target_rpo_hours, priority, data_handled)
VALUES (103, N'Control system', N'Grid control centre', 3,
        N'Monitors and switches the 132 kV transmission network.', N'Windows Server 2019', N'Abu Dhabi', 5,
        4, 1, 1, N'Telemetry and switching commands');
SET IDENTITY_INSERT dbo.ctm_scan_entity OFF;
INSERT dbo.ctm_scan_entity_bu (ctm_scan_entity_id, group_id, service_id) VALUES (103, 86, 1);

SET IDENTITY_INSERT dbo.onboarding_supporting_systems ON;
INSERT dbo.onboarding_supporting_systems (
    id, name, asset_type, accessability_channel, technology_used, user_base_count, targeted_users, managed_by,
    vendor_name, hosting_location, dr_location, network_connectivity_primary_dr, last_dr_test_date,
    backup_tested, dr_drill_frequency, database_platforms, saas_platform_list, public_cloud_platforms,
    rto_target_mins, rpo_target_mins, data_loss_incident_last_3_years, is_deleted)
VALUES
    (321, N'SCADA master station', 3, 2, N'[7]', 40, N'[11]', 6, N'Siemens', 3, N'Al Ain', 4, '2026-03-01', 1, 5,
     NULL, NULL, NULL, 60, 15, 0, 0),
    (322, N'Process historian', 2, 2, N'[8, 9]', 120, N'[11]', 6, N'AVEVA', 3, NULL, 4, '2026-01-15', 0, 5,
     N'[10]', N'[12]', N'[13]', 240, 60, 1, 0),
    (323, N'Corporate e-mail', 2, 2, N'[9]', 900, NULL, 6, N'Microsoft', 3, NULL, 4, '2026-02-01', 1, 5,
     NULL, NULL, NULL, 480, 60, 0, 0);
-- Every dropdown column (accessability_channel, managed_by, hosting_location, network_connectivity_primary_dr,
-- dr_drill_frequency, and the lists technology_used, targeted_users, database_platforms, saas_platform_list,
-- public_cloud_platforms) holds option IDS, as DevTest5 does: the procedure names them by id (G217).
SET IDENTITY_INSERT dbo.onboarding_supporting_systems OFF;
-- A system's own description (the procedure shows it, G217): 322 has none recorded (the required-facts tests).
UPDATE dbo.onboarding_supporting_systems SET description = N'Runs the transmission grid.' WHERE id = 321;
INSERT dbo.ctm_scan_entity_supporting_system (ctm_scan_entity_id, onboarding_supporting_system_id)
VALUES (103, 321), (103, 322);

-- The 6 STRIDE categories, with DevTest5's ids.
INSERT dbo.Threat_Category (ThreatCategoryID, ThreatCategoryName, IsActive, IsDeleted) VALUES
    (1, N'Spoofing', 1, 0), (2, N'Information Disclosure', 1, 0), (3, N'Elevation of Privilege', 1, 0),
    (4, N'Repudiation', 1, 0), (5, N'Tampering', 1, 0), (6, N'Denial of Service', 1, 0);

SET IDENTITY_INSERT dbo.Threat_Type ON;
INSERT dbo.Threat_Type (ThreatTypeID, ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source) VALUES
    (1, N'Identity spoofing', 1, 1, 0, N'seed'), (2, N'Malicious code', 5, 1, 0, N'seed'),
    (3, N'Data manipulation', 5, 1, 0, N'seed'), (4, N'Log tampering', 4, 1, 0, N'seed'),
    (5, N'Data exfiltration', 2, 1, 0, N'seed'), (6, N'Service disruption', 6, 1, 0, N'seed'),
    (7, N'Privilege abuse', 3, 1, 0, N'seed'), (8, N'Physical intrusion', 5, 1, 0, N'seed'),
    (9, N'Supply chain compromise', 5, 0, 0, N'ai');
SET IDENTITY_INSERT dbo.Threat_Type OFF;

-- 1-20 live; 21 pending under the pending type 9; 22 pending under a live type; 23 curator-rejected.
SET IDENTITY_INSERT dbo.Threat_Catalogue ON;
INSERT dbo.Threat_Catalogue (ThreatCatalogueID, ThreatTypeID, ThreatName, IsActive, IsDeleted, Source) VALUES
    (1, 1, N'Stolen operator credentials used on the HMI', 1, 0, N'seed'),
    (2, 1, N'Spoofed DNP3 master station', 1, 0, N'seed'),
    (3, 1, N'Phishing of control room staff', 1, 0, N'seed'),
    (4, 2, N'Ransomware on engineering workstations', 1, 0, N'seed'),
    (5, 2, N'Malicious PLC logic upload', 1, 0, N'seed'),
    (6, 3, N'Manipulated historian values', 1, 0, N'seed'),
    (7, 3, N'Falsified setpoints sent to field devices', 1, 0, N'seed'),
    (8, 4, N'Deleted SCADA event logs', 1, 0, N'seed'),
    (9, 4, N'Unattributed switching commands', 1, 0, N'seed'),
    (10, 5, N'Exfiltration of network topology', 1, 0, N'seed'),
    (11, 5, N'Leak of historian data to the cloud', 1, 0, N'seed'),
    (12, 6, N'Flooding of the control network', 1, 0, N'seed'),
    (13, 6, N'Jamming of the radio telemetry link', 1, 0, N'seed'),
    (14, 6, N'Wiper malware on the SCADA servers', 1, 0, N'seed'),
    (15, 7, N'Abuse of vendor remote access', 1, 0, N'seed'),
    (16, 7, N'Escalation through an unpatched Windows service', 1, 0, N'seed'),
    (17, 7, N'Shared administrator accounts', 1, 0, N'seed'),
    (18, 8, N'Tampering with substation RTUs on site', 1, 0, N'seed'),
    (19, 8, N'Theft of an engineering laptop', 1, 0, N'seed'),
    (20, 3, N'Modified firmware on protection relays', 1, 0, N'seed'),
    (21, 9, N'Compromised vendor software update', 0, 0, N'ai'),
    (22, 2, N'Malicious USB drive in the control room', 0, 0, N'manual'),
    (23, 8, N'Alien interference with the grid', 0, 1, N'ai');
SET IDENTITY_INSERT dbo.Threat_Catalogue OFF;
-- Threat_Catalogue.AssetType (G211): IT, OT or IT\OT; the others stay NULL (fit everywhere).
UPDATE dbo.Threat_Catalogue SET AssetType = N'IT\OT' WHERE ThreatCatalogueID = 1;

INSERT dbo.Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES
    (1, 1), (2, 1), (3, 1), (4, 5), (4, 6), (5, 5), (6, 5), (7, 5), (8, 4), (9, 4), (10, 2), (11, 2), (12, 6),
    (13, 6), (14, 6), (15, 3), (16, 3), (17, 3), (18, 5), (19, 2), (20, 5), (21, 5), (22, 5), (23, 5);

SET IDENTITY_INSERT dbo.Threat_Actor ON;
INSERT dbo.Threat_Actor (ThreatActorID, ThreatActorName, IsCapable, IsActive, IsDeleted, Source) VALUES
    (1, N'Nation-state group', 1, 1, 0, N'seed'), (2, N'Organised cybercrime group', 1, 1, 0, N'seed'),
    (3, N'Malicious insider', 1, 1, 0, N'seed'), (4, N'Hacktivist', 1, 1, 0, N'seed'),
    (5, N'Opportunistic attacker', 1, 1, 0, N'seed'), (6, N'Terrorist group', 1, 1, 0, N'seed');
SET IDENTITY_INSERT dbo.Threat_Actor OFF;
INSERT dbo.ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES
    (1, 1), (1, 2), (2, 2), (2, 1), (3, 1), (3, 3), (4, 3), (5, 1), (5, 4), (6, 4), (6, 6), (7, 3), (7, 2),
    (8, 3), (8, 6);

INSERT dbo.Control_Library (ControlCode, AssetType, Domain, ControlName, ControlDescription, IsActive, IsDeleted)
VALUES
    (N'AC-01', N'IT', N'Access control', N'Account management', N'Create, review and remove accounts.', 1, 0),
    (N'AC-02', N'IT\OT', N'Access control', N'Multi-factor authentication', N'Require a second factor for remote and privileged access.', 1, 0),
    (N'AC-03', N'OT', N'Access control', N'Vendor remote access gateway', N'Broker and record every vendor session.', 1, 0),
    (N'AC-04', N'IT\OT', N'Access control', N'Least privilege', N'Grant only the rights a role needs.', 1, 0),
    (N'AC-05', N'OT', N'Access control', N'Unique HMI accounts', N'No shared operator accounts on HMIs.', 1, 0),
    (N'AU-01', N'IT\OT', N'Audit', N'Central log collection', N'Send every security log to a protected collector.', 1, 0),
    (N'AU-02', N'OT', N'Audit', N'SCADA event integrity', N'Sign or write-once the SCADA event journal.', 1, 0),
    (N'AU-03', N'IT', N'Audit', N'Log review', N'Review security logs every day.', 1, 0),
    (N'CM-01', N'OT', N'Configuration', N'PLC logic change control', N'Approve and verify every logic download.', 1, 0),
    (N'CM-02', N'IT\OT', N'Configuration', N'Baseline configuration', N'Keep and compare a known-good baseline.', 1, 0),
    (N'CM-03', N'OT', N'Configuration', N'Firmware integrity', N'Verify firmware signatures before install.', 1, 0),
    (N'CP-01', N'IT\OT', N'Continuity', N'Offline backups', N'Keep tested offline copies of critical systems.', 1, 0),
    (N'CP-02', N'OT', N'Continuity', N'Manual operation fallback', N'Practise running the grid without SCADA.', 1, 0),
    (N'CP-03', N'IT', N'Continuity', N'Disaster recovery site', N'Fail over to a second site within the RTO.', 1, 0),
    (N'IR-01', N'IT\OT', N'Incident response', N'OT incident playbook', N'Steps for ransomware in the control network.', 1, 0),
    (N'IR-02', N'IT', N'Incident response', N'Phishing response', N'Report, contain and reset after a phishing click.', 1, 0),
    (N'MP-01', N'OT', N'Media protection', N'Removable media control', N'Block or scan USB media on OT hosts.', 1, 0),
    (N'NS-01', N'OT', N'Network security', N'IT/OT segmentation', N'Separate the control network with a DMZ.', 1, 0),
    (N'NS-02', N'OT', N'Network security', N'Protocol allow-listing', N'Allow only expected DNP3 and IEC 104 traffic.', 1, 0),
    (N'NS-03', N'IT\OT', N'Network security', N'Network monitoring', N'Detect anomalous traffic in the control network.', 1, 0),
    (N'NS-04', N'IT', N'Network security', N'Egress filtering', N'Allow only approved outbound connections.', 1, 0),
    (N'NS-05', N'OT', N'Network security', N'Radio link encryption', N'Encrypt and authenticate telemetry radio links.', 1, 0),
    (N'PE-01', N'OT', N'Physical security', N'Substation access control', N'Badge and log every substation entry.', 1, 0),
    (N'PE-02', N'IT\OT', N'Physical security', N'Device encryption', N'Encrypt the disks of portable engineering devices.', 1, 0),
    (N'SI-01', N'IT\OT', N'System integrity', N'Patch management', N'Patch within a risk-based window.', 1, 0),
    (N'SI-02', N'IT', N'System integrity', N'Endpoint protection', N'Run anti-malware on every Windows host.', 1, 0),
    (N'SI-03', N'OT', N'System integrity', N'Application allow-listing', N'Run only approved programs on OT hosts.', 1, 0),
    (N'SR-01', N'IT\OT', N'Supply chain', N'Vendor update verification', N'Verify the source and hash of every update.', 1, 0),
    (N'AT-01', N'IT', N'Awareness', N'Phishing training', N'Train staff to recognise phishing.', 1, 0),
    (N'DP-01', N'IT', N'Data protection', N'Data loss prevention', N'Detect and block sensitive data leaving.', 1, 0),
    -- Retired: never mapped; a register may still name it (owner, 2026-10-11).
    (N'AC-99', N'IT', N'Access control', N'Legacy dial-up access review', N'Review modem access monthly.', 0, 0);
GO
