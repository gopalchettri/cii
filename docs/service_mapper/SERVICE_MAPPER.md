# Service Mapper

Finds the upstream and downstream services of one selected service in Dubai's critical infrastructure, for a
reviewer to accept or reject relationship by relationship. The definitions follow DESC's mapping guide:

- **Upstream:** a service the selected service needs: without it, the selected service cannot deliver its core
  function.
- **Downstream:** a service that needs or relies on the selected service: without it, that service cannot deliver
  its core function. Services taking the output straight from the selected service rank first.

## Flow

1. `POST /v1/service-mapper` (Generate) keeps the request (service name, description, sector, subsector, entity
   names) and the per-direction counts from `.env` (`SERVICE_MAPPER_UPSTREAM/DOWNSTREAM_TOTAL_COUNT`), then queues
   a run on `tsg_servicemapper`. A service (its name, sector and subsector, case and spacing forgiven) has **one
   mapping per entity** (a unique index): the first Generate makes it; a later one runs it again with the details
   it sends, on the same `mapping_id`.
2. The worker reads the SQL onboarding catalog (`app/worker/service_mapper/catalog_provider.py`): every service
   with its sectors and subsectors (`tsg_Onboarding_GetSectorsAndSubsectorsList`,
   `tsg_Onboarding_GetServicesWithSectorDetails`, `tsg_GetServiceMapperAssociations`: TSG's own procedures in
   `scripts/sql`), and the onboarding platform's `Onboarding_GetSectorServiceMappings`.
3. One AI call (`app/domain/service_mapper/generate.py`): the system prompt `app/prompts.toml` `[service_mapper.generate]` and a JSON user
   message with the selected service (with its recorded `known_upstream`/`known_downstream` when it is in the catalog), the counts (`upstream_count`, `downstream_count`, a
   maximum each), `already_mapped` (from the second run: the names the mapping holds, by direction; those
   services are left out of `catalog`, so the AI is not offered them again) and `catalog`: **every** database service, grouped by sector and subsector, groups and services
   ordered most relevant first by hybrid search (`app/search/service_mapper.py`); the selected service is left
   out. Only a catalog too large for the input keeps just its most relevant services. **No catalog ID ever
   reaches the AI**: services are named, and the answer names services.
4. The schema is checked (`GeneratedAnswer`). If an item would be dropped for a fault only the AI can fix, the
   AI is asked again once in the same conversation, with the reasons: an ambiguous name, a one-word unmatched
   name, a sector or subsector name used as a service, or a new service without a catalog sector. The selected
   service itself, a duplicate and a service in both lists are never asked about: reconcile drops the first,
   keeps the first mention of a duplicate, and keeps a service in both lists where the AI ranked it higher. A
   new service that looks like a database one (same sector or subsector and a
   distinctive word in common, e.g. "Water Supply" and "Water Production & Transmission") is asked again too:
   a service already in the database is never identified anew by the AI. An unusable re-ask, or one that finds
   the AI busy or down, keeps the first answer.
5. `reconcile.py` maps each name to its catalog service (exact name, then a name form; services that share a name
   are told apart by sector and subsector), drops what is left of the above, keeps each service in one direction,
   drops every service the mapping already holds (either direction, or another name form of one the AI named),
   caps each list at its count, and adds the new services after those the mapping holds: a run never rewrites
   or removes one. Each service has one `dependency_id` in its mapping. The status (`GET .../status`, SSE
   `mapping.updated`) shows `progress.timings` `{catalog, services}`: the latest run's seconds for step 2 and for
   steps 3-5, null until it is done (`job.timings.catalog_s` / `services_s`; the next run starts a new `job`).
6. A reviewer accepts or rejects each relationship (`POST .../dependencies/decision`), and may change a decision,
   at any time once the mapping has services, even while a later run goes on. Generate again for the same
   service, or `POST .../regenerate` (the details the mapping holds), runs it again: every service and decision
   stays, only new services are added. While a run goes on, another is refused (409 `generation_in_progress`;
   the same Generate body answers 200 with the running mapping). `SERVICE_MAPPER_MAX_GENERATIONS` caps the runs
   (409 `generation_limit_reached`); a failed run keeps everything and does not count. After a run that found
   nothing new, another with the same details, counts and catalog would send the AI the same prompt (temperature
   0: the same answer), so it is not started: the call answers 200 with the mapping as it is, no run used. The same Idempotency-Key
   answers 200 with the run it started. A retried delivery of the same run reuses the AI answer it already got
   (`reuse_earlier_answer`, keyed on the run), so each run asks afresh. There is no history collection: the
   mapping itself holds every run's services (owner, 2026-10-28).

## Settings

| Setting | Default | What it does |
|---|---|---|
| `SERVICE_MAPPER_UPSTREAM_TOTAL_COUNT` / `..._DOWNSTREAM_...` | 10 | The most new services per direction in one run (0 turns one off). |
| `SERVICE_MAPPER_MAX_GENERATIONS` | 5 | The most runs per mapping, the first included (0 = no limit). |

## Rules (owner, 2026-10-22)

- Services are Dubai-level: operated in or for the Emirate of Dubai. Generic global capabilities, other
  emirates' or countries' services, vendor products, single sites, internal functions and people are out.
- A service sits in one direction only. The API has `upstream_services` and `downstream_services`, and no
  `bidirectional_services`.
- The counts are a maximum. A list the AI keeps short stays short; nothing is padded.
- Database services come first: when one provides a dependency the AI must use it. The AI adds a service only
  when the database has none that provides it (e.g. telecommunications), shown as AI-suggested.
- The answer per item is `service_name, sector, subsector, dependency_reason, applicability`. Entity scope goes
  in `applicability`. Each reason starts `Recorded:` or `Inferred:`. `Recorded:` stays only when the database
  records that link: the selected service's known dependencies in that direction, or the other service's in the
  opposite one (`reconcile.resolve_both`). Otherwise the code turns it into `Inferred:`, so the AI cannot claim
  evidence that was never supplied (owner, 2026-10-23).

## Quality check

The prompt was tuned on the DESC register `Consolidated_Entity_Service_Dependencies_18RA.xlsx` (69 services, 18
entities) used as the catalog. Each case's answer was compared with the dependencies its risk assessment recorded.
The prompt carries one worked example from RTA's risk assessment ("nol Fare Collection"), marked as illustration
only; the tuning cases are not RTA services, so the example is never the answer being scored.

## Differences from the supplied prompt

The owner's original prompt is kept as supplied in
[SERVICE_MAPPER_DEPENDENCY_PROMPT.md](../SERVICE_MAPPER_DEPENDENCY_PROMPT.md). The runtime prompt keeps its
direction, evidence and no-fabrication rules, and differs in these ways:

- Downstream is "needs or relies on" (DESC's guide), not strictly one step.
- The sectors and subsectors come from the SQL catalog taxonomy, not a fixed list.
- `confidence`, `verification_status`, `evidence`, `applies_to_entities` and `dependency_type` are not asked for.
- Reciprocal pairs are not allowed: one direction only.
- The Dubai scope is added; what the AI decides first is the selected service's own recorded upstream/downstream from the SQL catalog, never a fixed list.
