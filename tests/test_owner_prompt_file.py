"""G245: the owner's prompt file is kept word for word, its trailing space too. `ruff format` stripped the
space twice; the formatter now leaves the file alone (pyproject [tool.ruff.format] exclude)."""

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OWNERS_FILE = "app/engine/scenarios/writing/writing_prompts.py"


def test_the_owners_prompt_file_keeps_its_trailing_space_and_the_formatter_leaves_it_alone() -> None:
    first_line = (ROOT / OWNERS_FILE).read_text(encoding="utf-8").split("\n", 1)[0]
    assert first_line.endswith("approved them. ")
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert OWNERS_FILE in config["tool"]["ruff"]["format"]["exclude"]
