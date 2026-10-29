"""Stand-ins for the AI gateways, so the engine runs with no model: answers queued or worked out per AiTask,
vectors from shared words, rerank scores from a table. Each records what it was asked."""

import json
import re
from collections import defaultdict
from collections.abc import Callable
from typing import Any

import numpy as np

from app.ai import TruncatedAiAnswer, UnreadableAiAnswer
from app.core.constants import AI_OUTAGE_MESSAGES, AiOutage, AiTask
from app.core.exceptions import Unavailable

#: An answer: a JSON object, an exception to raise, or a function of the user prompt giving either.
Answer = dict[str, Any] | BaseException | Callable[[str], dict[str, Any]]


def brief_of(user_prompt: str) -> dict[str, Any]:
    """A writer prompt's BRIEF (the JSON object right after "BRIEF:"); {} for any other prompt."""
    if "BRIEF:\n" not in user_prompt:
        return {}
    brief, _ = json.JSONDecoder().raw_decode(user_prompt.split("BRIEF:\n", 1)[1])
    return dict(brief)


def brief_system_names(user_prompt: str) -> list[str]:
    """The supporting systems a writer prompt's BRIEF lists."""
    return [system["name"] for system in brief_of(user_prompt).get("supporting_systems") or []]


#: Where each slot of a set prompt starts ("SLOT SC1"), and the list its answer holds the slots' items under.
_SLOT = re.compile(r"^SLOT (\S+)\n", re.MULTILINE)
_SET_KEYS = {
    AiTask.WRITE_SCENARIO: "scenarios",
    AiTask.REPAIR_SCENARIO: "scenarios",
    AiTask.PLAN_CHECK: "reviews",
}


def slot_blocks(user_prompt: str) -> list[tuple[str, str]]:
    """A set prompt's slots, (label, its block), in order; [] for any other prompt."""
    starts = list(_SLOT.finditer(user_prompt))
    ends = [match.start() for match in starts[1:]] + [len(user_prompt)]
    return [(match[1], user_prompt[match.start() : end]) for match, end in zip(starts, ends, strict=False)]


def _slot_threat(block: str) -> str:
    """The threat name a slot's BRIEF or PLAN gives, as an answer copies it back."""
    heading = "BRIEF:\n" if "BRIEF:\n" in block else "PLAN:\n"
    record, _ = json.JSONDecoder().raw_decode(block.split(heading, 1)[1])
    return str(record["threat"]["threat"])


def items_in(user_prompt: str, heading: str) -> list[dict[str, Any]]:
    """The JSON list a planner prompt carries after `heading` ("CANDIDATES", "THREATS")."""
    return json.loads(user_prompt.rsplit(f"\n{heading}:\n", 1)[1])


class FakeChatModel:
    """ChatModel's planner surface. Per task, queued answers are used first, then the task's responder; a
    rejected first answer is re-asked once, and a usable first answer is kept when the re-ask is unusable or
    finds the AI unavailable, as the real model does (ask_for_checked_json).
    A set prompt (writer, rewrite, reviewer) is answered slot by slot: each slot takes the next queued answer
    or the responder's answer to its own block, with its slot and threat copied back; an exception in any slot
    fails the whole call, and a queued answer holding the set's list ("scenarios", "reviews") is the whole
    call's answer, as given. A rewrite with nothing of its own queued or responding is answered as a write."""

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
        first_answer_check: Callable[[dict[str, Any]], list[str]] | None = None,
        reuse_earlier_answer: bool = False,  # noqa: ARG002 - the real model's option; no records here
    ) -> dict[str, Any]:
        first = self._answer(task, user_prompt)
        usable = None if check_answer(first) else first
        if usable is not None and (first_answer_check is None or not first_answer_check(usable)):
            return usable
        try:
            answer = self._answer(task, user_prompt)
        except (UnreadableAiAnswer, TruncatedAiAnswer, Unavailable):
            if usable is None:
                raise
            return usable
        if not check_answer(answer):
            return answer
        if usable is not None:
            return usable
        raise UnreadableAiAnswer(f"{task}: {check_answer(answer)[:3]}")

    def _answer(self, task: AiTask, user_prompt: str) -> dict[str, Any]:
        self.calls.append((task, user_prompt))
        key, slots = _SET_KEYS.get(task), slot_blocks(user_prompt)
        if key is None or not slots:
            return self._one_answer(task, user_prompt)
        whole = self.queued[task][:1]
        if whole and isinstance(whole[0], dict) and key in whole[0]:
            return dict(self.queued[task].pop(0))  # type: ignore[arg-type]
        items = [
            {"slot": label, "threat": _slot_threat(block)} | self._one_answer(task, block)
            for label, block in slots
        ]
        return {key: items}

    def _one_answer(self, task: AiTask, user_prompt: str) -> dict[str, Any]:
        """The next answer of `task` to `user_prompt` (one slot's block in a set)."""
        answer = self._next(task)
        if answer is None and task is AiTask.REPAIR_SCENARIO:
            answer = self._next(AiTask.WRITE_SCENARIO)
        if answer is None:
            raise KeyError(task)
        if isinstance(answer, BaseException):
            raise answer
        answered = answer(user_prompt) if callable(answer) else answer
        return self._with_writer_defaults(task, answered, user_prompt)

    def _next(self, task: AiTask) -> Answer | None:
        """`task`'s next queued answer, else its responder; None when it has neither."""
        queued = self.queued[task]
        return queued.pop(0) if queued else self.responders.get(task)

    def _with_writer_defaults(self, task: AiTask, answer: dict[str, Any], user_prompt: str) -> dict[str, Any]:
        """A writer answer that gives no system_reasons gets one per supporting system of the brief it
        answers (G216), and one that gives no action_sentences gets its whole statement for each listed
        action, so a test about something else need not write them; a test of them gives its own (empty
        included)."""
        if task not in (AiTask.WRITE_SCENARIO, AiTask.REPAIR_SCENARIO) or not isinstance(answer, dict):
            return answer
        defaults: dict[str, Any] = {}
        if "system_reasons" not in answer:
            names = brief_system_names(user_prompt)
            defaults["system_reasons"] = {name: f"It could affect {name}." for name in names}
        acts = (brief_of(user_prompt).get("threat") or {}).get("threat_actions") or []
        if "action_sentences" not in answer and isinstance(answer.get("scenario_statement"), str):
            defaults["action_sentences"] = {act: answer["scenario_statement"] for act in acts}
        return defaults | answer

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
        self.query_corpora: list[str] = []  # the corpus each search query call searched
        self.sources: dict[str, list[dict]] = {}  # the rows given with each corpus
        self.queries_down = False  # True: a query call raises Unavailable, as an outage would

    def embed_library_texts(self, corpus: str, texts: list[str], sources: list[dict]) -> np.ndarray:
        self.calls.append(corpus)
        self.sources[corpus] = sources
        return self._vectors(texts)

    def embed_search_queries(self, texts: list[str], corpus: str) -> np.ndarray:
        if self.queries_down:  # as the embedding gateway raises a lost connection
            raise Unavailable(AI_OUTAGE_MESSAGES[AiOutage.UNREACHABLE], reason=AiOutage.UNREACHABLE)
        self.calls.append("query")
        self.query_corpora.append(corpus)
        return self._vectors(texts)

    def embed_texts_to_compare(self, texts: list[str]) -> np.ndarray:
        self.calls.append("compare")
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
