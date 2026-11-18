# sre: create-session-attack (17 Nov 2026)

- Import: on the saved schedule (default weekly, Sunday 02:00 UTC). Beat asks every 60 s; one compare-and-set claim
  on the schedule document lets one check start the import, so two ticks or two beat pods start one. A scheduled
  import that failed is due again in 3,600 s unless its next slot comes first; a slot missed while beat was down runs
  once. An import by hand (`POST /v1/tsg/intel/refresh`) ignores the schedule. Logs:
  `external_intelligence.schedule_saved`, `external_intelligence.schedule_claimed`, `attack.graph_stored`.
- Linking (`tsg_link_mitigations`): queued after every import and by `POST .../control-links/prepare`; one run at a
  time under the Redis lock `tsg:control_links:lock` (900 s, renewed every 120 s; a killed run frees it within 900 s);
  the one an import starts waits its turn, asking again every 60 s. One mitigation's failure keeps its earlier links;
  an embedding outage fails the run's mitigations and keeps every earlier link. It is an admin job with a heartbeat:
  `GET /v1/admin/jobs` shows it (kind `control_links`), and its cancel stops it at the next mitigation. Logs:
  `control_links.prepared` (judged, unchanged, failed, seconds), `.busy`, `.lock_lost`, `.not_queued`,
  `.embed_failed`, `.link_failed`.
- A create-session run uses the existing lease, retry, cancel, delete and reaper code. Logs:
  `attack.name_not_confirmed`, `attack.scenario_not_confirmed`, `controls.picked`, `controls.pick_dropped`,
  `controls.pick_unusable` (the control search then maps the set).
- AI usage: `create_session` is a counted API call; `link_controls` and `pick_controls` are activities of the
  `controls` bucket; `observability/grafana/dashboards/ai_usage.json` names all three. Both new chat calls use the
  threat-scenario model and its limits (`CII_SCENARIO_...`).
- No new metric and no new alert rule. Existing rules apply: `JobsFailing` leaves timer jobs out;
  `ScheduledJobsExpiring` counts a beat check dropped after its 180 s expiry.

- A new or upgraded system imports at beat's first check (the default schedule is stored due at that check's own
  time). A fetch that keeps under half of the stored graph objects or relationships fails the source and stores
  nothing. A controls delivery whose pick call loses one scenario's lease queues the others again, never maps them by
  the search; the run's controls time counts the one pick call once.
- Measured on the laptop by the live lane (17 Nov): first import of both sources 184 s, an unchanged one 1.4-4.1 s;
  first linking 537 s for 93 mitigations (93 chat, 93 rerank, 2 embedding calls), a later one under 1 s with no AI
  call; a scheduled claim 11 s after its slot.
- D83 (17 Nov): a source can no longer be withdrawn or approved again, so the evidence index can no longer be left
  without a source that was withdrawn and approved again; the log `attack.graph_deleted` is gone with the routes.

Not verified: the same figures on UAT; whether beat's 60 s checks expire (and raise
`ScheduledJobsExpiring` for `tsg_refresh_external_intelligence`) while an import, a linking run and an index build
hold all 3 threads of `worker-maintenance`; the load of about 100 linking calls on the threat-scenario model's
limits while users start runs.
