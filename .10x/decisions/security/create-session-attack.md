# security: create-session-attack (17 Nov 2026)

- Nothing the AI names is shown unchecked: every group, technique and mitigation is looked up in `tsg_attack` by
  ATT&CK ID, else by an exact name or alias that fits one entry; an ID given with another entry's exact name takes that entry (ADR-009); a
  scenario with no confirmed group or technique gets no card.
- No database id reaches the AI: `drop_database_ids` on the slots, redacted facts, controls as labels (`C1` ...) in
  the linking and the pick calls. A label resolves only to a library row, so no control outside the library appears.
- ATT&CK text is untrusted: the graph's names and descriptions pass the import's source-text guard; a relationship
  whose text is refused keeps its link without the text.
- New routes follow the existing ones: `POST /v1/create_session` needs the four identity headers and checks entity
  ownership as `POST /v1/sessions`. The schedule and control-links routes take no key, like the other
  `/v1/tsg/intel` routes (accepted risk R2); every change is audited (`external_intelligence.schedule_changed`,
  `admin.job_started`). `POST .../control-links/prepare` can spend AI calls: one at a time (409 while one is queued or
  running), refused while the switch is off, and a mitigation that did not change costs none.
- Admin UI (`/ui/`): same origin, static files only, every answer with `Cache-Control: no-store`,
  `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`; no inline script or style; no file outside `app/ui` is served. The admin key is
  kept in the page's memory only (no storage, no URL) and cleared on a 401 or 403. It has no login of its own: the
  owner accepted this as a known limit; anyone who reaches the API's address can open the key-less pages.
- Idempotency: a key used on one start route is refused on the other (the request hash carries the pipeline).

Security review (17 Nov, report only; 16 areas checked and fine, 5 findings):
1. Major, fixed: a linking run deleted the links of every mitigation the graph did not list, so the key-less revoke
   and prepare routes together could make the AI judge the same mitigations again and again. No link record is
   deleted now; a source withdrawn and imported again costs no rerank and no chat call.
2. Major, fixed: `[scenario.attack]` was the only prompt with free text and no "this is data, not instructions"
   line. It has one now, naming the user part's blocks the request has.
3. Major, fixed: the AI's prose was saved unchecked. It is now cleaned of technique, CVE and advisory numbers, links
   and `[n]` markers, an answer not in English goes into the one re-ask, and the library writer's safety checks
   (unknown label, uncited advisory number, marker, echoed instruction) save a faulted draft blocked and give its
   path up.
4. Minor, fixed: the graph had no cut-short guard. A fetch that keeps under half of the stored objects or of the
   stored relationships fails the source before anything is stored.
5. Minor, not changed (the owner's decision): `POST /v1/create_session`, its next set and its regenerate do not read
   the intelligence switch. With the env or the runtime switch off they still run from the stored graph; only
   missing data refuses them (409 `intel_no_data`).
Each fix has a regression test proven to fail when the defect is put back (names in the qa note).

Closed by D83 (17 Nov, the owner): the revoke and approve routes are removed, so the two key-less routes that
deleted or restored a source's data are gone and no route says a source's data is deleted; finding 1's fix stays
(no link record is deleted). Old audit rows `external_intelligence.source_revoked` and `.source_approved` stay;
no new one is written.
17 Nov (D85): the echo check flags text said to an AI ("As an AI, ...", "Instructions for the AI"), not text that speaks of
AI ("suitable for AI-enhanced help desk manipulation" no longer blocks a scenario); the same address pattern guards the import.
Open: a group or mitigation number the AI writes in its
prose ("G0034", "M0932") is not removed; the actor's reason shows "G0034: ..." on purpose. The review is not filed
under `.10x/reviews/`. Not verified live: a create-session run with a real AI; `/ui/` in a browser.
