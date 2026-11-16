# Status

| Phase | State |
|---|---|
| Discovery | Complete (16 Nov 2026): three read-only explorers; findings in `specs/2026-11-16-simplify-codebase-design.md` |
| 0 Brainstorming | Complete: owner chose order (outside app, then app code, then runtime), inner workings may change, API frozen, notes in `.10x/` |
| 1 Strategy | Complete |
| 2 Design | Complete: ADR-001 (configmap from files), ADR-002 (one AI limit path); ADR-003 (one lease runtime) Proposed |
| 3 Planning | Complete: tasks below |
| 4 Implementation | In progress |
| 5 Verification | Pending |
| 6 Delivery | Pending |

## Tasks
- [ ] A1 remove clean stale worktrees (local)
- [ ] A2 delete finished scripts, root clutter
- [ ] A3 configmap from files (ADR-001)
- [ ] A4 tests that pin doc wording
- [ ] A5 outdated docs
- [ ] B app code simplifications
- [ ] C runtime simplifications (ADR-002)
- [ ] D ADR-003 proposal, QA and security reviews, PR
