# External intelligence (evidence for scenarios)

Built 2026-10-12. The decider for the two exceptions below is the owner.

## 1. What it is

Public threat intelligence (CISA Known Exploited Vulnerabilities, FIRST EPSS, MITRE ATT&CK Enterprise and ICS, CISA
ICS advisories, NIST NVD detail) is kept in MongoDB and searched when a scenario is written. A scenario then tells a
short story that cites real precedent by a marker such as `[1]`; the proof (which technique, which advisory, the link)
sits beside the text, never inside it. With **no evidence** a scenario is still written, "inferred", as before.

**Off means as before.** With the switch off the app writes scenarios with the original writer and prompts, stores
nothing about intelligence on a plan or a scenario, creates no intelligence collection, builds no snapshot and queues
no refresh. This is the first rule of the feature and is tested (`tests/external_intelligence/switch_off/`).

### Owner exceptions (2026-10-12, decided by the owner)

1. **An on/off switch, despite "no feature flags"** (BLUEPRINT section 4). The feature needs a way to be switched off
   without a release: the env master switch `EXTERNAL_INTELLIGENCE_ENABLED` and an admin run-time switch (it can turn
   the feature off, never on past the env).
2. **"Threat intel not buildable" is overridden** (BUILD_PLAN, comparison row 8). The sources are public and
   approved; every source can be revoked and purged by an admin.

## 2. Data flow

```
sources (6 feeds) --hourly beat / POST /v1/tsg/intel/refresh--> tsg_intel (one row per version, current flag)
      \-- sanitised, unsafe text quarantined --/                      |
                                                           snapshot (immutable index: keyword + vector)
                                                                      |
plan (no search) ---> write batch: EvidenceAtWrite ---ONE embedding call per batch---> EvidenceFinder
                                  |   (distinct threats of the paths about to be written, only)
                                  v
              evidence saved on the plan (a retry, redelivery or regenerate reuses it: same numbers)
                                  |
              brief --> writer prompt (evidence only inside a delimited untrusted block)
                                  |
              draft --> code rules (markers, ids, precedent, unknown applicability, echo, length) --> AI plan check
                                  |
              scenario: statement with [n] + content.evidence + content.intel_search (audit)
```

Rules that matter:

- A batch searches the threats of **its own** paths once (a threat shared by two paths once). A plan lists many more
  threats than are ever written; planning searches none.
- A search that could not be made (the embedding or rerank service is down, or no snapshot exists yet) is **not**
  saved on the plan: the scenario is written inferred, and a later batch, retry or regenerate searches again.
- An evidence failure never fails or retries a write. A lost lease still stops the job (it is the plan write, not the search).
- One audit row (`external_intelligence.evidence_used`) per batch that searched.
- `plan.made_with` carries `intel_snapshot_id` and `intel_sources` **only** while on.
- The writer style is chosen per batch from the switch. A regenerate keeps the style of the scenario it replaces
  (`content.prompt_version`: `scenario writer-1` original, `scenario writer-evidence-1` story).

## 3. Data format

A scenario read (`GET /v1/sessions/{id}/results`, scenarios endpoints) gains three optional fields. They are `null` /
`[]` on every scenario written in the original style.

```json
{
  "scenario": { "scenario_statement": "The SCADA server of Grid Control Centre shows operators ... Attackers have used a rogue firmware update to disable substation devices before [1]. ..." },
  "evidence_mode": "source-documented",
  "evidence": [
    {
      "n": 1,
      "ref": "T0839",
      "kind": "technique",
      "source": "mitre_attack_ics",
      "title": "Module Firmware",
      "url": "https://attack.mitre.org/techniques/T0839/",
      "facts": ["Sandworm used a rogue firmware update to disable substation devices in a real attack."],
      "applicability": null
    }
  ],
  "evidence_search": {
    "query": "Threat: Tampering: Unauthorised firmware update\nReason: ...",
    "asset_types": ["OT"],
    "snapshot_id": "snap-2026-10-12-1",
    "threshold": 1.0,
    "considered": [
      {"ref": "T0839", "score": 91.0, "decision": "used", "reason": ""},
      {"ref": "CVE-2024-0001", "score": 40.0, "decision": "no_product_link", "reason": "Concerns a specific product; ..."}
    ],
    "stale": false,
    "failure": null
  }
}
```

- `evidence` holds **only** what the text cites, in the order the text first cites it, without reranker scores. All
  evidence stays stored with the scenario (`content.evidence`).
- `applicability` is for a vulnerability or advisory: `confirmed`, `unknown` or `not_applicable` (those are left out).
  Unknown stays unknown: a CVE in KEV is never "exploitable here" on that alone.
- `evidence_search` is the audit: the query, the IT/OT filter, the snapshot, every candidate with its score and the
  decision (`used`, `below_threshold`, `not_applicable`, `no_product_link`, `duplicate`, `over_limit`).
- `known_groups` (G230, owner 2026-10-14: "Name the real group"): up to 3 real named groups behind the attack,
  shown beside the acting actor (never in the story), each `{name, attack_id, url, kind, who, match, fits_actor,
  technique, technique_title, through, how, cited}`. Picked in code, no AI call: groups of the actor's kind behind
  the card's evidence (`used_this_technique`), then behind another technique the search found
  (`used_related_technique`), then, only when neither, the nearest by shared attacker goals (`nearest`). An
  insider's or vendor's card (ATT&CK records no such group) gets the groups known for the attack, `fits_actor:
  false`. `through` names the campaign or malware that links the group (2015 Ukraine Electric Power Attack ->
  Sandworm Team; Triton -> TEMP.Veles); `cited` is the evidence number of its technique on this card.
- G232 (owner 2026-10-14, UAE relevance): `THREAT_CONTEXT_COUNTRY` names the country. Each group also carries the
  places and sectors its ATT&CK description says it ATTACKED (never where it comes from); within each step groups
  that attacked the country come first, then its region (the Gulf, the Middle East), then the asset's sector, each
  with `relevance` (in the API: `known_groups[].relevance`). Each evidence entry has `scope`: `country`, `regional` or `global`, from the groups behind it;
  a sentence saying something happened in the country must cite a `country` source (`country_claim_unsupported`).
  Planning ranks a threat whose techniques such groups use first among paths of equal coverage (keywords only).
  UAE incident feeds (aeCERT, UAE Cyber Security Council, DESC) are not sources yet: no readable feed, legal first.

Collections (created only while the env master switch is on): `tsg_intel` (records, one version per change),
`tsg_external_feed_status` (a row per source, plus the run-time switch `_id: "switch"`),
`tsg_external_intelligence_snapshots` (built snapshots, pointer `_id: "active"`), vectors in `tsg_embeddings`
(corpus `external_intelligence`).

## 4. Operating it (admin key)

| Call | Does |
|---|---|
| `GET /v1/tsg/intel/switch` | `{env_enabled, runtime_enabled, effective, changed_at, changed_by}` |
| `PUT /v1/tsg/intel/switch` `{"enabled": true}` | sets the run-time switch (audited); turning it ON also queues a refresh |
| `GET /v1/tsg/intel/health` | the switch, the active snapshot, every source's status, `stale`, `pending_sources`, `no_data` and `evidence`: `{rerank_model, threshold, threshold_calibrated, threshold_calibrated_on}` (see "Fresh, pending, stale" below) |
| `POST /v1/tsg/intel/refresh` `{"source": "cisa_kev"}` (body optional) | 202 `{job_id}`; one at a time (409 `job_in_progress`, `details.job_id`); 422 for an unknown or unapproved source; 409 while the env master switch is off |
| `GET /v1/tsg/intel/refresh/{job_id}` | the job: status, result, error |
| `POST /v1/tsg/intel/sources/{source}/revoke` | audited FIRST (`external_intelligence.source_revoked`), then marks the source unapproved with a blank health, purges its records and vectors and rebuilds the snapshot. Works whatever the switch says: with the env master OFF it only deletes what exists (no collection, row or snapshot is created) |
| `POST /v1/tsg/intel/sources/{source}/approve` | a revoked source approved again (audited `external_intelligence.source_approved`; 409 while the env master is OFF; 422 unknown source): it starts blank and a refresh of that source is queued (`refresh_job_id`, null when a refresh was already queued) |

First run: set `EXTERNAL_INTELLIGENCE_ENABLED=true`, restart API and worker, `POST /v1/tsg/intel/refresh`, read the job,
then `GET /v1/tsg/intel/health` until `snapshot_id` is set. After that sources refresh hourly when due (KEV, EPSS,
ICS, NVD daily; ATT&CK weekly) and a failed source keeps its last good data. NVD is slow without `CII_NVD_API_KEY`
(optional, raises the rate limit from 5 to 50 requests per 30 s).

**After the G230 and G232 updates, once each:** `POST /v1/tsg/intel/refresh` `{"source": "mitre_attack_ics"}`, then the same for
`mitre_attack_enterprise` (or one refresh of all). The ATT&CK reader keeps more now (the groups behind each
technique), so its checkpoint names the reader's format: an unchanged file is read again once. Until then cards
show no `known_groups`; the record texts are unchanged, so the new snapshot reuses every vector (no AI call).

**Fresh, pending, stale.** A source that has NEVER succeeded (not run yet, or only failed so far; NVD's first pass takes
about 12 hours without a key and is an enrichment only) is **pending**, not stale: it holds no data, so nothing it
holds is old. `stale` is true only when an approved source that HAS succeeded is older than
`IntelLimits.STALE_AFTER_HOURS` (48). `pending_sources` lists the approved sources still waiting for their first data
(their `status` and `last_error` are in `sources`); `no_data` is true when no approved source has ever succeeded (a fresh
install: nothing is stale, there is simply no data yet). A revoked source counts for none of the three. The health
report and the flag on a story's `evidence_search.stale` follow this one rule (`FeedFreshness`).

Revoking a source (Legal says no): `POST /v1/tsg/intel/sources/{source}/revoke` sets it unapproved and the purge removes its records and vectors; the next
snapshot no longer holds it. A refresh that is writing at that moment stops at its next batch (its claim is refused) and
deletes what it already wrote when it sees the source revoked, so nothing of the source is left. The switch does not delete
data: turning it off only stops its use.

**What a revoke does not remove:** the evidence already copied onto scenarios and plans that were written while the source
was approved (their `evidence` and `intel_search` fields) stays as written history. If Legal requires it gone too, an
operator must delete or regenerate those scenarios and plans (regenerating writes them again from the remaining sources).

**Record safety rules (all in code):**
- *Claim heartbeat.* A refresh renews its claim before every batch it writes and before the retirement. A worker that finds
  the claim taken over (it outlived `IntelLimits.CLAIM_STALE_SECONDS` without writing, for example in one very long
  download) or the source revoked writes nothing more, logs `external_intelligence.claim_lost` and leaves the new owner's
  status alone. The heartbeat cannot cover the download itself: a download longer than the claim limit loses the claim, writes
  nothing and is retried by the next hourly check.
- *Truncated feed.* A complete fetch that holds fewer than `IntelOperationsLimits.MIN_RETIRE_RATIO` (half) of the source's
  current records is a failed fetch: nothing is stored or retired, the source shows `failed` with the reason "looks cut
  short", and the last good data stays. A real shrink of up to half passes and retires what is gone. If a source genuinely
  dropped more than half of its records, revoke it and approve it again: that purges the old data and loads the source from
  the start.
- *Nothing to ask yet.* EPSS, NVD and ICS wait for KEV's CVEs; until KEV has loaded, their first runs change nothing (no
  failure, no audit) and look again at the next check.
- *Retention.* A version of a record that stops being current is stamped `retired_at` and deleted by a TTL index
  `IntelOperationsLimits.RETIRED_VERSION_DAYS` (90) later; current records are never deleted by it.

## 5. Security model

- **Sources are untrusted text.** Every stored field is cut to a size, stripped of control characters and quarantined when
  it reads as an instruction to an AI (never indexed). The checks are tuned on the live sources (a real run over ATT&CK,
  KEV and the ICS advisories quarantines nothing): a Windows registry key or a file or URL path (the backslash becomes a
  space, so the words stay apart), a file hash (an MD5 or SHA of the usual length that does not decode to readable text),
  a `<script>` tag quoted in backticks or `<code>`, a markdown heading, CJK text beside Latin letters, a unit such as the
  micro sign and ordinary verbs ("respond with", "show the NOP instructions", "do not disclose") are text, not
  instructions. An imperative at the start of a sentence, a payload that decodes to words, a lone `###` fence, live markup
  and a Latin word with a Cyrillic or Greek look-alike letter are still quarantined. A long encoded run split at `/`, `_`
  or `-` into short pieces counts as a path; that is the one deliberate gap, covered by the "decode" and role-phrase patterns.
- **The model never sees ids, links or titles.** Evidence reaches the prompt only as plain numbered facts, rebuilt from
  structured fields, inside a block delimited by `<<<UNTRUSTED_EVIDENCE_BEGIN>>>` / `<<<UNTRUSTED_EVIDENCE_END>>>`; the
  system prompt says the block is data to paraphrase, never instructions. Delimiter look-alikes in facts are stripped,
  each fact is sanitised again, and a fact that reads as an instruction is dropped. The AI plan check gets the evidence
  the same way.
- **Output rules in code (blockers):** a CVE/technique/advisory id or link in the prose; a marker with no evidence behind
  it; a real-world name from the evidence without its marker; "is vulnerable/exploitable/affected" stated on evidence whose
  applicability is unknown (with or without the marker); a draft that repeats an injection phrase; a story outside 80 to
  220 words or under four sentences. A blocked draft gets the one rewrite, then stays hidden as before.
- **Admin-only control**, audited. The health endpoint names the reranker by its name only, never its folder or address.
- **Concurrency:** the evidence is saved in the same fenced write family as the plan (a delivery that lost its lease cannot
  change it); a refresh is one active job per kind; a source is claimed atomically by one worker, which renews the claim before every write and stops when it is lost; one audit row and one log line per switch change.

## 6. Per environment

| | Dev (laptop) | UAT / production |
|---|---|---|
| Chat | Azure Kimi-K2.6 | LiteLLM `kimi-k2.5`, fallback `glm-5` |
| Embedding | `text-embedding-3-large`, 3072 dims | LiteLLM `qwen3-embedding-8b-mig`, 4096 dims, texts up to 4000 chars |
| Reranker | local `bge-reranker-v2-m3` | LiteLLM `qwen3-reranker-8b-mig` |
| Reranker scale | its own 0-100 | **a different scale** |
| `EXTERNAL_INTELLIGENCE_ENABLED` | `true`, written explicitly in `.env` | `true` since 2026-10-13 (owner; it shipped dormant until then), with the provisional, not calibrated cut-off 50. The code default is **false**: an environment that forgets the line stays the original TSG |
| `EVIDENCE_SIMILARITY_THRESHOLD` | `1.0`, calibrated on bge | `50`, **provisional, not calibrated**; must be set explicitly (start-up refuses it missing while enabled) |

The threshold cannot be shared between environments. The writer prompts and rules depend on no model: the length, beats,
markers and the other rules are enforced in code with the existing check-then-rewrite-once loop, so a draft from the
fallback model passes (or is rewritten) under the same rules.

### Enabling in UAT (checklist)

1. Calibrate (section 7) against UAT's reranker and set `EVIDENCE_SIMILARITY_THRESHOLD` in `.env.uat`; add the model name to
   `EVIDENCE_THRESHOLD_CALIBRATED_ON` (`app/core/constants/evidence_story.py`).
2. Set `EXTERNAL_INTELLIGENCE_ENABLED=true` (the master switch; the run-time `PUT /v1/tsg/intel/switch` cannot turn it on past the environment) and restart API and worker.
3. Run the first refresh: `POST /v1/tsg/intel/refresh`.
4. Check `GET /v1/tsg/intel/health`: `snapshot_id` set, sources `ok`, `threshold_calibrated` true.

## 7. Calibration

A reranker score is a ranking score, not a probability, and each model has its own scale. Calibrate on each environment:

1. Collect 60 or more (search text, record text) pairs from real threat searches (a threat's `evidence_search.considered`
   lists every candidate with its score) and label each `1` (real evidence for that threat) or `0`.
2. Save them as a CSV with the header `query,record,label`.
3. Run it against the environment's own `.env` (the script scores with the rerank model that file names, a local folder or a
   LiteLLM proxy alike):
   `.venv\Scripts\python scripts\calibrate_evidence_threshold.py labelled_pairs.csv`
4. It prints, per candidate threshold, the pairs kept, precision and recall, and the recommended value (the highest recall
   with precision of at least 0.9, else the best F1). Noise is worse than a miss, so precision comes first.
5. Set `EVIDENCE_SIMILARITY_THRESHOLD`, restart, record the model in `EVIDENCE_THRESHOLD_CALIBRATED_ON`.

## 8. Known limits

- The AI plan check judges whether a marker is supported; code checks only what is exact.
- "Unknown applicability" is checked by sentence patterns in code; a claim worded in an unusual way is left to the plan check.
- Already-written story scenarios keep showing their stored proof after the switch is turned off (the text carries its markers).
- The controls search does not yet read an evidence entry's mitigation facts.
