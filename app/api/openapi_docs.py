"""What the Swagger page (/docs) says above the endpoints: how to call the API, and each group in the order a
tester sets up and tests (ApiTag). Text only: no behaviour lives here."""

from typing import Any

from app.core.constants import ApiTag

API_DESCRIPTION = """
**Threat Scenario Generator (TSG) | Remedation | Service Mapper.

**Who is calling.** Every call in groups 5-9 and 11 sends four headers: `X-API-Key` (from group 2),
`X-User-Id`, `X-Entity-Id` (a number) and `X-Tenant-Id`. Groups 2, 3 and 10 send `X-Admin-Key` instead.
Groups 1 and 4 need no key.

**Long work runs in the background.** A start answers 202 with an id; poll its status (or open its live
updates, group 9) until it is done. Errors come as `application/problem+json`: `code`, `detail`, and a
`reason` on a 409.
"""

_GROUPS: dict[ApiTag, str] = {
    ApiTag.HEALTH: "Is the API alive (`/health`), and are its stores and workers ready (`/ready`)? No key.",
    ApiTag.API_KEYS: (
        "Mint the API key every caller sends as `X-API-Key` (shown once); list or revoke keys. Needs "
        "`X-Admin-Key`."
    ),
    ApiTag.EMBEDDINGS: (
        "Build the threat library's search vectors now and read the build. They are also built every 30 "
        "minutes and after each library change. Needs `X-Admin-Key`."
    ),
    ApiTag.INTELLIGENCE: (
        "Public threat feeds (CISA KEV, EPSS, MITRE ATT&CK, ICS advisories, NVD), when the env file says "
        "`EXTERNAL_INTELLIGENCE_ENABLED=true`. First time: `POST /refresh`, read it until `done`, then "
        "`GET /health` until `snapshot_id` is set. Turn it on or off with `PUT /switch`. No key."
    ),
    ApiTag.RUNS: "Start a run for one asset and its supporting systems, follow it, read its scenarios.",
    ApiTag.REVIEW: (
        "Accept, reject or regenerate a run's scenarios, ask for the next set, or propose an AI-written "
        "threat to the library."
    ),
    ApiTag.REMEDIATION: (
        "A remediation plan for an accepted scenario (generated or hand-written), in TSG v1's shape: "
        "request it, follow it, read it, accept or reject a version, regenerate or cancel it, list plans."
    ),
    ApiTag.JOBS: "My runs and plans that are queued or running; cancel a run; delete a run for good.",
    ApiTag.LIVE_UPDATES: "Server-Sent Events, for a run or a plan: its status now, then every change.",
    ApiTag.CURATION: (
        "Threats proposed by people or by the AI wait here for a curator to approve or reject. Needs "
        "`X-Admin-Key`."
    ),
    ApiTag.SERVICE_MAPPER: (
        "Generate upstream and downstream service dependencies from a described service (one mapping per "
        "service), review each relationship, and regenerate to add more. Requires the caller identity "
        "headers."
    ),
    ApiTag.AI_USAGE: (
        "How many AI calls each module, API call, session and request made, per part of the work "
        "(threats, scenario, controls, remediation, service mapper) and per model, successful and failed, "
        "with each activity's name and description. Counts only. No key."
    ),
}

#: Swagger shows the groups in this order (ApiTag's).
OPENAPI_TAGS: list[dict[str, Any]] = [{"name": tag.value, "description": _GROUPS[tag]} for tag in ApiTag]
