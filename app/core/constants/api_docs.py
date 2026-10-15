"""The Swagger page's groups (owner, 2026-10-15: "in order for easy configuration and testing"): numbered in
the order a tester uses them, set-up first. Each router names its group here; app/api/openapi_docs.py
describes each one."""

from enum import StrEnum


class ApiTag(StrEnum):
    HEALTH = "1. Health"
    API_KEYS = "2. Set-up: API keys"
    EMBEDDINGS = "3. Set-up: library embeddings"
    INTELLIGENCE = "4. Set-up: external intelligence"
    RUNS = "5. Threat scenarios: runs"
    REVIEW = "6. Threat scenarios: review"
    REMEDIATION = "7. Remediation plans"
    JOBS = "8. My jobs"
    LIVE_UPDATES = "9. Live updates"
    CURATION = "10. Library curation"
    SERVICE_MAPPER = "11. Service mapper"
