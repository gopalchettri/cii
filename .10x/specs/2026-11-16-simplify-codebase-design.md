# Simplify the codebase: design (approved by the owner, 16 Nov 2026)

**Problem:** the owner finds the codebase too complicated. Three explorers measured it: app/ 34,572 lines (about 730
accidental, 2%), tests 49,394, scripts 6,556, docs about 9,500, deploy/configmap.yaml about 10,000 (copies of the
monitoring files). Most app complexity is essential (AI-verdict checks, source-text cleaning, leases, the shared
search cap that protects a reranker which drops connections and sends no 429, the token pacer).

**Scope, in the owner's order:**
- A. Outside the app: remove clean stale worktrees (local); delete 16 finished investigation scripts and their tests;
  ship the monitoring files with a kustomization instead of copying them into the configmap; delete tests that pin
  doc wording; remove outdated detail from the docs.
- B. App code: dead fields, dead enum values, guards for impossible states, old-format readers, duplicate helpers.
- C. Runtime: one AI limit path (no fail-open at cap 0, no double pacer wait, one wait policy, one retry loop), dev-only
  reranker turns as one lock, unused metrics, finished migration, rare claim edge cases.
- D. One lease runtime: proposal only (ADR-003).

**Not changed:** the API, what the AI is sent, AI tuning settings, the owner's architecture rules, the frozen UI
contract, `.env.uat.example`, `.env.dev.example`, the retired-index drops (until UAT has run this release once).

**Done when:** each step's code is gone, the full suite and the contract tests pass, logic changes keep or gain a
test that fails without them (mutation-checked), and the live end-to-end run (55 operations) matches before and after.
