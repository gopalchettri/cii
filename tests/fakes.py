"""Stand-ins for the AI gateways, so the engine runs with no model: answers queued or worked out per AiTask,
vectors from shared words, rerank scores from a table. Each records what it was asked."""

import json
from collections import defaultdict
from collections.abc import Callable
from typing import Any

import numpy as np

from app.ai import TruncatedAiAnswer, UnreadableAiAnswer
from app.core.constants import AiTask, ErrorMessage
from app.core.exceptions import Unavailable

#: An answer: a JSON object, an exception to raise, or a function of the user prompt giving either.
Answer = dict[str, Any] | BaseException | Callable[[str], dict[str, Any]]


def brief_system_names(user_prompt: str) -> list[str]:
    """The supporting systems a writer prompt's BRIEF lists (the JSON object right after "BRIEF:")."""
    if "BRIEF:\n" not in user_prompt:
        return []
    brief, _ = json.JSONDecoder().raw_decode(user_prompt.split("BRIEF:\n", 1)[1])
    return [system["name"] for system in brief.get("supporting_systems") or []]


def items_in(user_prompt: str, heading: str) -> list[dict[str, Any]]:
    """The JSON list a planner prompt carries after `heading` ("CANDIDATES", "THREATS")."""
    return json.loads(user_prompt.rsplit(f"\n{heading}:\n", 1)[1])


#: The writer's own "why this threat applies" a fake answer gets when it gives none (G268).
WHY_APPLIES = "Vendor firmware sessions make this asset's control logic a place this attack could change."


class FakeChatModel:
    """ChatModel's planner surface. Per task, queued answers are used first, then the task's responder; a
    rejected first answer is re-asked once, as the real model is (ask_for_checked_json)."""

    def __init__(self, max_prompt_chars: int = 60_000) -> None:
        self._input_limit = max_prompt_chars
        self.queued: dict[AiTask, list[Answer]] = defaultdict(list)
        self.responders: dict[AiTask, Callable[[str], dict[str, Any]]] = {}
        self.calls: list[tuple[AiTask, str]] = []  # (task, user prompt), re-asks included

    @property
    def max_prompt_chars(self) -> int:
        return self._input_limit

    def queue(self, task: AiTask, *answers: Answer) -> None:
        self.queued[task].extend(answers)

    def ask_for_checked_json(
        self,
        task: AiTask,
        system_prompt: str,
        user_prompt: str,
        check_answer: Callable[[dict[str, Any]], list[str]],
    ) -> dict[str, Any]:
        for _attempt in (1, 2):
            answer = self._answer(task, user_prompt)
            if not check_answer(answer):
                return answer
        raise UnreadableAiAnswer(f"{task}: {check_answer(answer)[:3]}")

    def _answer(self, task: AiTask, user_prompt: str) -> dict[str, Any]:
        self.calls.append((task, user_prompt))
        answer: Answer = self.queued[task].pop(0) if self.queued[task] else self.responders[task]
        if isinstance(answer, BaseException):
            raise answer
        answered = answer(user_prompt) if callable(answer) else answer
        return self._with_system_reasons(task, answered, user_prompt)

    def _with_system_reasons(self, task: AiTask, answer: dict[str, Any], user_prompt: str) -> dict[str, Any]:
        """A writer answer that gives no system_reasons gets one per supporting system of the brief it
        answers (G216) and one with no why_applies a sentence (G268), so a test about something else need not
        write them; a test of either gives its own (empty included)."""
        if task != AiTask.WRITE_SCENARIO or not isinstance(answer, dict):
            return answer
        names = brief_system_names(user_prompt)
        reasons = {name: f"It could affect {name}." for name in names}
        filled = {"system_reasons": reasons, "why_applies": WHY_APPLIES}
        return {key: value for key, value in filled.items() if key not in answer} | answer

    def asked(self, task: AiTask) -> list[str]:
        """The user prompts of every call made for `task`, re-asks included."""
        return [user for called, user in self.calls if called == task]


def truncated() -> TruncatedAiAnswer:
    return TruncatedAiAnswer("cut off")


class FakeEmbeddings:
    """Deterministic vectors: one dimension per known word, so meaning = shared words."""

    WORDS = ("ransomware", "phishing", "backup", "insider", "flood")

    def __init__(self, words: tuple[str, ...] = WORDS) -> None:
        self.words = words
        self.calls: list[str] = []  # the corpus of every library call, "query" for search queries, in order
        self.sources: dict[str, list[dict]] = {}  # the rows given with each corpus
        self.queries_down = False  # True: a query call raises Unavailable, as an outage would

    def embed_library_texts(self, corpus: str, texts: list[str], sources: list[dict]) -> np.ndarray:
        self.calls.append(corpus)
        self.sources[corpus] = sources
        return self._vectors(texts)

    def embed_search_queries(self, texts: list[str]) -> np.ndarray:
        if self.queries_down:
            raise Unavailable(ErrorMessage.AI_UNREACHABLE)
        self.calls.append("query")
        return self._vectors(texts)

    def _vectors(self, texts: list[str]) -> np.ndarray:
        rows = [[1.0 if word in text.casefold() else 0.0 for word in self.words] + [0.01] for text in texts]
        matrix = np.array(rows, dtype=np.float32).reshape(len(texts), len(self.words) + 1)
        return matrix / np.linalg.norm(matrix, axis=1, keepdims=True)


class FakeRerankModel:
    """Scores 0-100 from a table of (query, document) pairs; 0 for any other pair."""

    def __init__(self, scores: dict[tuple[str, str], float] | None = None) -> None:
        self.scores = scores or {}
        self.calls: list[tuple[str, list[str]]] = []

    def score_relevance(self, query: str, documents: list[str]) -> list[float]:
        self.calls.append((query, documents))
        return [self.scores.get((query, document), 0.0) for document in documents]
