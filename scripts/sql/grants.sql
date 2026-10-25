-- Least privilege: the app's SQL login may only EXECUTE TSG's own procedures; it gets no table
-- permission at all, so every read and write goes through the procedures in this folder. Each one is named: a
-- name pattern would also grant v1's deploy helpers (dbo.tsg_reconcile_column alters tables).
-- Run after the procedure scripts, as an administrator, naming the app's database user:
--   sqlcmd -E -I -b -S <server> -d <database> -v AppUser="tsg_app" -i scripts\sql\grants.sql
GRANT EXECUTE ON dbo.tsg_GetAssetContext TO [$(AppUser)];
GRANT EXECUTE ON dbo.tsg_GetThreatLibrary TO [$(AppUser)];
GRANT EXECUTE ON dbo.tsg_GetControlLibrary TO [$(AppUser)];
GRANT EXECUTE ON dbo.tsg_GetLibraryStamp TO [$(AppUser)];
GRANT EXECUTE ON dbo.tsg_ResolveThreat TO [$(AppUser)];
GRANT EXECUTE ON dbo.tsg_ListPendingThreats TO [$(AppUser)];
GRANT EXECUTE ON dbo.tsg_DecidePendingThreats TO [$(AppUser)];
GRANT EXECUTE ON dbo.tsg_ImportThreatLibrary TO [$(AppUser)];
GRANT EXECUTE ON dbo.tsg_GetServiceMapperAssociations TO [$(AppUser)];
GRANT EXECUTE ON dbo.tsg_Onboarding_GetSectorsAndSubsectorsList TO [$(AppUser)];
GRANT EXECUTE ON dbo.Onboarding_GetSectorServiceMappings TO [$(AppUser)];
GRANT EXECUTE ON dbo.tsg_Onboarding_GetServicesWithSectorDetails TO [$(AppUser)];
GO
