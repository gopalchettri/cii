# Service Mapper

Finds the direct upstream and downstream services of one selected service in Dubai's critical infrastructure,
for a reviewer to accept or reject relationship by relationship.

- **Upstream:** the selected service directly needs its output, capability or availability to operate.
- **Downstream:** it directly needs the selected service's output, capability or availability to operate.

## Flow

1. `POST /v1/service-mapper` freezes the request (service name, description, sector, subsector, entity names) and
   the per-direction counts from `.env` (`SERVICE_MAPPER_UPSTREAM/DOWNSTREAM_TOTAL_COUNT`), then queues a job on
   `tsg_servicemapper`.
2. The worker reads the SQL onboarding catalog (`app/worker/service_mapper/catalog_provider.py`) and retrieves up
   to 80 candidate services by hybrid search (`app/search/service_mapper.py`); the selected service itself is left
   out.
3. One AI call (`app/domain/service_mapper/generate.py`): the system prompt `prompts/generate.txt` and a JSON user
   message with the selected service, the sector taxonomy, the counts and the candidates that fit the budget.
   **No catalog ID ever reaches the AI**: candidates are named, and the answer names services.
4. The schema is checked (`GeneratedAnswer`). If any item would be dropped, the AI is asked again once in the
   same conversation, with the reasons. Drops are: an ambiguous name, the selected service, a one-word unmatched
   name, a duplicate, a service in both lists, or a new service without a taxonomy sector. An unusable re-ask
   keeps the first answer.
5. `reconcile.py` maps each name to its catalog service (exact name, then a name form; services that share a name
   are told apart by sector and subsector), drops what is left of the above, keeps each service in one direction,
   caps each list at its count and stores the generation.
6. A reviewer accepts or rejects each relationship (`POST .../dependencies/decision`); regenerate starts a new
   generation with every relationship pending.

## Rules (owner, 2026-10-22)

- Services are Dubai-level: operated in or for the Emirate of Dubai. Generic global capabilities, other
  emirates' or countries' services, vendor products, single sites and internal functions are out.
- A service sits in one direction only. The API has `upstream_services` and `downstream_services`, and no
  `bidirectional_services`.
- The counts are a maximum. A list the AI keeps short stays short; nothing is padded.
- The answer per item is `service_name, sector, subsector, dependency_reason, applicability`. Entity scope goes
  in `applicability`, and an inferred link says so in its reason.

## Differences from the supplied prompt

The owner's original prompt is kept as supplied in [SERVICE_MAPPER_DEPENDENCY_PROMPT.md](../SERVICE_MAPPER_DEPENDENCY_PROMPT.md). The runtime prompt
keeps its direction, directness, evidence and no-fabrication rules, and differs in these ways:

- The sectors and subsectors come from the SQL catalog taxonomy, not a fixed list.
- `confidence`, `verification_status`, `evidence`, `applies_to_entities` and `dependency_type` are not asked for.
- Reciprocal pairs are not allowed: one direction only.
- The Dubai scope is added.
