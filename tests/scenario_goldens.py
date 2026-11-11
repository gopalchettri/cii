"""Shared parts of the scenario golden tests: recording fakes, fixed samples and the golden file check."""

import dataclasses
import enum
import json
import os
import pathlib
from datetime import date, datetime
from typing import Any

import numpy as np
from pydantic import BaseModel

from app.core.constants import AiTask, StrideCategory
from app.models.library.library import LibraryActor, LibraryThreat, ThreatLibrary
from tests.fakes import FakeChatModel, FakeEmbeddings, FakeRerankModel, items_in

GOLDENS = pathlib.Path(__file__).parent / "goldens" / "scenario"
#: CII_WRITE_GOLDENS=1 writes the golden files from the code as it is; otherwise each is compared.
WRITE_GOLDENS = os.environ.get("CII_WRITE_GOLDENS") == "1"
S = StrideCategory


def to_plain(value: Any) -> Any:
    """`value` as plain JSON data: dates as a placeholder, dataclasses, models and enums as their values."""
    if isinstance(value, datetime | date):
        return "<datetime>"
    if isinstance(value, BaseModel):
        return to_plain(value.model_dump(mode="json"))
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return to_plain(dataclasses.asdict(value))
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): to_plain(item) for key, item in value.items()}
    if isinstance(value, set | frozenset):
        return sorted(to_plain(item) for item in value)
    if isinstance(value, list | tuple):
        return [to_plain(item) for item in value]
    if isinstance(value, np.floating):
        return float(value)
    return value


def check_golden(name: str, data: Any) -> None:
    """Compare `data` with its golden file (or write the file when CII_WRITE_GOLDENS=1)."""
    path = GOLDENS / f"{name}.json"
    text = json.dumps(to_plain(data), indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    if WRITE_GOLDENS:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        return
    assert path.exists(), f"no golden {path.name}: run with CII_WRITE_GOLDENS=1 on the reference code"
    assert json.loads(path.read_text(encoding="utf-8")) == json.loads(text), f"golden {name} changed"


class RecordingChat(FakeChatModel):
    """The fake chat model, also keeping every ask's task, system prompt and user prompt in order."""

    def __init__(self, max_prompt_chars: int = 60_000) -> None:
        super().__init__(max_prompt_chars)
        self.asks: list[dict[str, str]] = []

    def ask_for_checked_json(  # type: ignore[override]
        self, task: AiTask, system_prompt: str, user_prompt: str, *args: Any, **kwargs: Any
    ) -> dict[str, Any]:
        self.asks.append({"task": str(task), "system": system_prompt, "user": user_prompt})
        return super().ask_for_checked_json(task, system_prompt, user_prompt, *args, **kwargs)


class RecordingEmbeddings(FakeEmbeddings):
    """The fake embeddings, also keeping every search query and compared text in order."""

    def __init__(self, words: tuple[str, ...] = FakeEmbeddings.WORDS) -> None:
        super().__init__(words)
        self.texts: list[dict[str, Any]] = []

    def embed_search_queries(self, texts: list[str], corpus: str) -> np.ndarray:
        self.texts.append({"call": "query", "corpus": corpus, "texts": list(texts)})
        return super().embed_search_queries(texts, corpus)

    def embed_texts_to_compare(self, texts: list[str]) -> np.ndarray:
        self.texts.append({"call": "compare", "texts": list(texts)})
        return super().embed_texts_to_compare(texts)


def rerank_calls(rerank: FakeRerankModel) -> list[dict[str, Any]]:
    """Every reranker call as (query, documents), in order."""
    return [{"query": query, "documents": list(documents)} for query, documents in rerank.calls]


def gate_by_spec(spec: dict[str, dict[str, Any]]) -> Any:
    """A relevance gate answering each candidate by its threat name's spec: missing = not relevant;
    keys: systems, entry_points, impacts {category: impact}, attacker, needs, actions, confidence, likelihood,
    plus any raw field to send as given (a broken answer)."""

    def answer(user_prompt: str) -> dict[str, Any]:
        verdicts = []
        for candidate in items_in(user_prompt, "CANDIDATES"):
            found = dict(spec.get(candidate["threat"]) or {})
            verdict: dict[str, Any] = {"slot": candidate["slot"], "threat": candidate["threat"]}
            if not found or found.pop("relevant", True) is False:
                verdict |= {"relevant": False, "reason": found.get("reason", "Nothing recorded allows it.")}
                verdicts.append(verdict | {"needs": found.get("needs", [])})
                continue
            given = found.pop("impacts", {})  # only the candidate's own categories; none of them: all HIGH
            own = {kind: impact for kind, impact in given.items() if kind in candidate["categories"]}
            impacts = own or dict.fromkeys(candidate["categories"], "HIGH")
            kinds = [
                {"name": kind, "impact": impact, "reason": f"{candidate['threat']} could hit SYS1 as {kind}."}
                for kind, impact in impacts.items()
            ]
            systems = found.pop("systems", ["SYS1"])
            verdict |= {
                "relevant": True,
                "categories": kinds,
                "systems": systems,
                "entry_points": found.pop("entry_points", systems),
                "confidence": found.pop("confidence", 80),
                "likelihood": found.pop("likelihood", "MEDIUM"),
                "needs": found.pop("needs", []),
                "attacker": found.pop(
                    "attacker", candidate["attackers"][0] if candidate["attackers"] else ""
                ),
                "attacker_reason": found.pop(
                    "attacker_reason", "It could reach SYS1 from the office network."
                ),
            }
            verdicts.append(verdict | found)
        return {"verdicts": verdicts}

    return answer


def gap_fill_by_spec(proposals: dict[str, dict[str, Any]]) -> Any:
    """The gap-fill answer: each listed category's proposal from `proposals`, else none applies."""

    def answer(user_prompt: str) -> dict[str, Any]:
        listed = [item["category"] for item in items_in(user_prompt, "EMPTY CATEGORIES")]
        none = {"applies": False, "reason": "The library covers it."}
        return {"proposals": [{"category": kind} | proposals.get(kind, none) for kind in listed]}

    return answer


#: A library for the batching golden: 45 threats, more than one gate batch of 40.
MANY_ACTORS = (LibraryActor(1, "Ransomware gang"), LibraryActor(3, "Malicious insider"))
MANY_THREATS = tuple(
    LibraryThreat(
        100 + number,
        f"Threat number {number} against control systems",
        1 + number % 3,
        ("Malware", "Social engineering", "Insider misuse")[number % 3],
        (list(StrideCategory)[number % 6],),
        (MANY_ACTORS[number % 2],),
    )
    for number in range(45)
)
MANY_LIBRARY = ThreatLibrary(MANY_THREATS, MANY_ACTORS)
