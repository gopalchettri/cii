"""Steps shared by scenarios and remediation:
- ask_ai.py            ask the AI and check its answer (one re-ask with the problems listed)
- prompt_batches.py    pack many items into as few prompts as fit the model
- parallel.py          run AI calls at the same time; the most retryable error wins
- names.py             names as code compares, shows and quotes them
- prompt_redaction.py  what never reaches an AI: secrets, personal data, database ids"""
