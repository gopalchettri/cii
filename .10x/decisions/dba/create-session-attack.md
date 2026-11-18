# dba: create-session-attack (17 Nov 2026)

MongoDB (the app creates everything itself; no migration):
- `tsg_attack` (new): one document per ATT&CK object or relationship, `_id` `"<source>:<stix id>"`, `record`
  `object` or `relationship`. Objects: `source`, `stix_id`, `type`, `attack_id`, `name`, `aliases`, `name_keys`,
  `description`, `url`, `version`. Relationships: `source`, `type` (`uses`, `mitigates`, `attributed-to`),
  `source_ref`, `target_ref`, `description`, `citations`, `version`. Indexes, created at start-up while external
  intelligence is on: `by_attack_id`, `by_name_key`, `by_type_and_source_ref`, `by_type_and_target_ref`,
  `by_source_and_version`. A source's graph is replaced whole: the new version is written, then the other versions
  are deleted, so it is never empty half way.
- `tsg_control_links` (new): one document per ATT&CK mitigation, `_id` its ATT&CK ID: `name`, `fingerprint`,
  `links` (`control_id`, `effect`, `reason`, `rerank`), `prepared_at`. Read and written by `_id`; no other index. No
  record is ever deleted: a mitigation no source lists any more keeps its links.
- `tsg_external_feed_status`: a source document's `approved` field is never read (D83: a source cannot be
  withdrawn); a value stored earlier stays. One more fixed document, `_id` `"schedule"` (`enabled`, `frequency`, `day_of_week`,
  `time`, `timezone`, `next_run_at`, `last_run_at`, `updated_at`, `updated_by`), beside `"switch"`.
- `tsg_sessions`: a create-session run adds `pipeline: "attack"`, `plan.target`, `plan.risks_listed_at`, `plan.risks_complete` and a `risk`
  on each plan path. `tsg_scenarios`: its cards add `content.attack` (group, techniques with the mitigations ATT&CK
  records, named mitigations) and, in `controls`, `picks`, `dropped` and `technique_states` (each technique's state:
  `matched`, `no_known_defence`, `not_prepared`, `no_library_control`, `type_mismatch`, `not_offered`, `not_picked`);
  a plan path the AI found no risk for carries `unselected_reason: "no_further_risk"`. None of these is in an API
  response. No existing field changed; runs of `POST /v1/sessions` are stored as before.
- `tsg_admin_jobs`: a new kind, `control_links`.

SQL Server:
- `scripts/sql/tsg_GetAssetContext.sql`: the line `, e.data_handled` is now shown, so the procedure returns the
  asset's data handled, for both start routes. No table, column, grant or other procedure changed. The database team
  must install the file on each SQL Server TSG reads (UAT, production); until then runs work and only lack that fact.
- Test database: `tests/sql/seed.sql` asset 103's `data_handled` is NULL and asset 105 carries a value.

Measured on the laptop by the live lane (ATT&CK release 20.1): `tsg_attack` holds 23,269 documents (Enterprise
22,305, ICS 964); `tsg_control_links` 93. The removed feeds' data (owner, 17 Nov: deleted): each import first deletes,
by name (`REMOVED_INTEL_SOURCES`), the records in `tsg_intel` and the status documents in `tsg_external_feed_status` of
`cisa_kev`, `first_epss`, `nist_nvd` and `cisa_ics_advisories` (`crud.intel.delete_removed_sources`); no one needs database access.
Not verified: the procedure on a UAT or production database; collection sizes on UAT.
