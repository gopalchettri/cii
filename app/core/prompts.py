"""Every AI prompt and the prompt version, read once from app/prompts.toml and app/mitre_prompts.toml."""

import tomllib
from pathlib import Path
from typing import Any

PROMPTS: dict[str, Any] = tomllib.loads((Path(__file__).parents[1] / "prompts.toml").read_text(encoding="utf-8"))
MITRE_PROMPTS: dict[str, Any] = tomllib.loads(
    (Path(__file__).parents[1] / "mitre_prompts.toml").read_text(encoding="utf-8")
)
