# Engineering manager: order of work (16 Nov 2026)

Owner: "go ahead, one feature at a time". Done so far: wave 1 (six areas in parallel worktrees, merged, 29,818 lines),
wave 2 (small cuts and merge fixes). Parallel worktrees stop here: the FastAPI moves cross area boundaries.

| Step | Feature | Gate |
|---|---|---|
| 1 | library curation | full suite, contract, goldens, mypy, conventions |
| 2 | admin + API keys | same |
| 3 | jobs + job monitor | same |
| 4 | AI usage | same |
| 5 | service mapper | same |
| 6 | external intelligence | same |
| 7 | remediation | same, plus the plan prompt pin |
| 8 | scenarios | same, plus the scenario goldens |
| 9 | platform close-out | container.py, services/, data_access/ deleted |
| 10 | style pass | 120 columns, no private-helper docstrings |
| 11 | C cuts the owner approves | |

Estimate: 25-40 min per feature plus a 10-minute sharded suite. No commit without the owner's yes.
