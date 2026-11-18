# product-manager: simplify-codebase

Success: fewer lines and moving parts, same results for users, API frozen, owner can operate it.

## 16 Nov 2026, later (owner)
- Target: `app/` under 20,000 physical lines (from 34,572), FastAPI layout (ADR-004), production ready, KISS, IO optimized,
  no functional or fundamental gap.
- External intelligence keeps only MITRE ATT&CK Enterprise and ATT&CK ICS. CISA KEV, FIRST EPSS, CISA ICS advisories and
  NIST NVD are removed. The `IntelSource` enum on the admin intel routes shrinks to those two values (approved API change,
  admin routes only); old records of removed sources stay in MongoDB unread.
- Jobs are acknowledged when they start (`task_acks_late=False`): the reaper alone brings back a killed pod's job (~2 min).
