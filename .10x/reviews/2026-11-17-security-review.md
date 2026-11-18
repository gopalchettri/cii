# security: scenario-simple (17 Nov 2026)

No auth, key or input-validation code changed. Intel source-text cleaning (prompt-injection defence), the redirect host
allow-list, the rerank gate and the switch outage fallback were kept untouched. Rejected ATT&CK objects are no longer
stored as rows; they are still refused and counted in the refresh log. The principal used for job origin and AI-usage
rows is found by type, verified by a mutation check.
