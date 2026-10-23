# Service Mapper

Finds the upstream and downstream services of one selected service in Dubai's critical infrastructure, for a
reviewer to accept or reject relationship by relationship. The definitions follow DESC's mapping guide:

- **Upstream:** a service the selected service needs: without it, the selected service cannot deliver its core
  function.
- **Downstream:** a service that needs or relies on the selected service: without it, that service cannot deliver
  its core function. Services taking the output straight from the selected service rank first.

## Flow

1. `POST /v1/service-mapper` freezes the request (service name, description, sector, subsector, entity names) and
   the per-direction counts from `.env` (`SERVICE_MAPPER_UPSTREAM/DOWNSTREAM_TOTAL_COUNT`), then queues a job on
   `tsg_servicemapper`.
2. The worker reads the SQL onboarding catalog (`app/worker/service_mapper/catalog_provider.py`): every service
   with its sectors and subsectors (`Onboarding_GetServicesWithSectorDetails`, `tsg_GetServiceMapperAssociations`).
3. One AI call (`app/domain/service_mapper/generate.py`): the system prompt `prompts/generate.txt` and a JSON user
   message with the selected service (with its recorded `known_upstream`/`known_downstream` when it is in the catalog), the counts (`upstream_count`, `downstream_count`, a
   maximum each) and `catalog`: **every** database service, grouped by sector and subsector, groups and services
   ordered most relevant first by hybrid search (`app/search/service_mapper.py`); the selected service is left
   out. Only a catalog too large for the input keeps just its most relevant services. **No catalog ID ever
   reaches the AI**: services are named, and the answer names services.
4. The schema is checked (`GeneratedAnswer`). If any item would be dropped, the AI is asked again once in the
   same conversation, with the reasons. Drops are: an ambiguous name, the selected service, a one-word unmatched
   name, a sector or subsector name used as a service, a duplicate, a service in both lists, or a new service
   without a catalog sector. A new service that looks like a database one (same sector or subsector and a
   distinctive word in common, e.g. "Water Supply" and "Water Production & Transmission") is asked again too:
   a service already in the database is never identified anew by the AI. An unusable re-ask keeps the first
   answer.
5. `reconcile.py` maps each name to its catalog service (exact name, then a name form; services that share a name
   are told apart by sector and subsector), drops what is left of the above, keeps each service in one direction,
   caps each list at its count and stores the generation.
6. A reviewer accepts or rejects each relationship (`POST .../dependencies/decision`); regenerate starts a new
   generation with every relationship pending.

## Settings

| Setting | Default | What it does |
|---|---|---|
| `SERVICE_MAPPER_UPSTREAM_TOTAL_COUNT` / `..._DOWNSTREAM_...` | 10 | The most services per direction (0 turns one off). |

## Rules (owner, 2026-10-22)

- Services are Dubai-level: operated in or for the Emirate of Dubai. Generic global capabilities, other
  emirates' or countries' services, vendor products, single sites, internal functions and people are out.
- A service sits in one direction only. The API has `upstream_services` and `downstream_services`, and no
  `bidirectional_services`.
- The counts are a maximum. A list the AI keeps short stays short; nothing is padded.
- Database services come first: when one provides a dependency the AI must use it. The AI adds a service only
  when the database has none that provides it (e.g. telecommunications), shown as AI-suggested.
- The answer per item is `service_name, sector, subsector, dependency_reason, applicability`. Entity scope goes
  in `applicability`, and an inferred link says so in its reason.

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
