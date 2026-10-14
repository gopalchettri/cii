"""Stage E, the plan: which attack paths, in which order.
- best_threat.py     the AI picks each group's best threats by meaning (G209)
- path_grouping.py   one path per kind of attack per route of systems, at asset level (G216)
- path_selector.py   AttackPathSelector: the plan, selected up to the target count
- path_ranking.py    the paths in order, most relevant first
- path_progress.py   which paths are still to write, and why none is left"""
