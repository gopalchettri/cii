# Handoff

Branch `tsg_simplify_codebase_2026-11-16_16-25` (stacked on `tsg_remediation_servicemapper_concurrent_user_16Nov2026`).
The approved plan is `specs/2026-11-16-simplify-codebase-design.md`; work it in its order, one commit per step.
Hard limits: no API change (`tests/contract/ui_api_frozen.json` and `openapi.json` untouched); no change to what the
AI is sent; every AI tuning setting stays a setting; the owner's architecture rules stand (one service class per
module, one repository per collection, the DI container, the scenario code in 3 files).
Proposed for later (not in this plan): type the `dict[str, Any]` plan/path/card records; merge the four prompt-text
builders (needs an A/B per the owner's rule); one lease runtime (ADR-003, awaiting the owner).
