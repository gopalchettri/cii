"""Stage C, finding the threats: which library threats apply to the asset.
- threat_finder.py     ThreatFinder: runs the steps below in order
- asset_landscape.py   the asset and its systems as one text for the AI
- threat_prompts.py    the approved threat-finding prompts (also the same-attack and attacker checks')
- category_check.py    one STRIDE category, all its threats
- relevance_gate.py    AI: does this threat apply?
- ai_gap_fill.py       AI proposes a threat when no library threat of the category applies
- library_matcher.py   an AI proposal matched back to the closest library threat"""
