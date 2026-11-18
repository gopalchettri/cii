# product-manager: create-session-attack (17 Nov 2026)

Scope: a second way to start a run (`POST /v1/create_session`, the payload of `/v1/sessions`; `data_handled` comes from the stored procedure, not the request), the ATT&CK graph in MongoDB, mitigation-to-control links, per-sentence control picks, a saved import schedule, an admin UI at `/ui/`. Out of scope: any change to `/v1/sessions` or an existing response; any library but ATT&CK Enterprise and ICS; a login for the UI. Success: every group, technique and mitigation shown exists in MITRE's data, every control is a library row, every runs and review API works on the new session, and the end-to-end run is clean. Limits the owner accepted: spec, "Known limits".

Owner decisions, 17 Nov 2026 (settled; D85, ADR-009):
- `POST /v1/create_session`, its next set and its regenerate keep working while the external intelligence switch is off, from the MITRE ATT&CK data already stored; only missing data refuses them (409 `intel_no_data`).
- A run whose first AI call fails for good ends with no scenarios: no change, a new start is needed.
- Asset type, in the owner's words: "Every asset will have asset type. it will either IT or OT or IT\OT both i.e., hybrid" (category codes IT, OT, IT\OT). An IT\OT asset is written from both ATT&CK matrices.
- The schedule stays as built: the first import at beat's first check after a deployment; a failed scheduled import due again hourly but never past its next slot; "prepare control links" refused with 409 while the switch is off; beat's check expires after 180 s.
- Re-ask only a scenario that would be lost, and list further risks in every writing call until the count is reached: "do not make the solution overly complex and over engineered". An ATT&CK ID given with another entry's exact name takes the entry of that name; a group's use recorded on its campaign counts as documented; the removed feeds' stored data is deleted by the app at import.
