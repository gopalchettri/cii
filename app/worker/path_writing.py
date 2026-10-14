"""Writing one attack path's scenario, shared by the write job's batches (tasks/writing.py) and regenerate
(worker/regenerator.py): the brief and the writer with its checks, in a pool of up to Generation.WRITER_BATCH
threads, each outcome handed back to the job's own thread the moment it is done, for saving there."""

import contextvars
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import structlog

from app.ai import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core.constants import ErrorCode, ErrorMessage, Generation, LogEvent, WriterStyle, Writing
from app.core.exceptions import JobFailed, LeaseLost, PathNotWritable
from app.data_access.scenarios import ScenarioRepository, TitleTaken
from app.engine.scenarios.writing.brief_builder import build_brief
from app.engine.scenarios.writing.scenario_record import title_candidates
from app.engine.scenarios.writing.scenario_writer import ScenarioWriter
from app.engine.shared.names import name_match_key, shorten_text
from app.engine.shared.parallel import RETRYABLE_ERRORS
from app.models.asset_context import FrozenContext
from app.models.library import ThreatLibrary
from app.models.writing import LiveLibrary, PathFailure, WriterBrief, WrittenScenario

log = structlog.get_logger(__name__)

#: What writing one path gave: its brief and scenario, or why there is none.
PathOutcome = tuple[WriterBrief, WrittenScenario] | PathFailure
#: What one path's work raises instead of returning a card: the job retries, or fails as a whole.
#: A lost lease too (G214): the job stops, never a path's own failure card.
_RAISED_FROM_A_PATH: tuple[type[Exception], ...] = (*RETRYABLE_ERRORS, JobFailed, LeaseLost)


class PathWriter:
    """What every path of one delivery is written with: the run's frozen facts and threats, what the library
    holds live now, and the writer."""

    def __init__(
        self,
        run: dict[str, Any],
        chat: ChatModel,
        library: ThreatLibrary,
        style: WriterStyle = WriterStyle.ORIGINAL,
    ) -> None:
        self._run_id, self._style = run["_id"], style
        self._writer = ScenarioWriter(chat, tuple(actor.name for actor in library.actors))
        # The facts may use half the model input, as the landscape's: the rest is the prompt and one rewrite.
        self._budget = chat.max_prompt_chars // 2
        self._live = LiveLibrary.of(library)
        self._context = FrozenContext.from_record(run["context"])
        self.threats = {threat["key"]: threat for threat in run["plan"]["threats"]}

    def write(
        self,
        path: dict[str, Any],
        other_scenarios: tuple[str, ...] = (),
        style: WriterStyle | None = None,
    ) -> PathOutcome:
        """In a pool thread: the AI work for one path (`other_scenarios`: the path's versions a regenerate
        must differ from; `style`: the style it is written in, the delivery's own when not given). An outage
        or a job-wide failure is raised."""
        try:
            brief = build_brief(
                self.threats,
                path,
                self._context,
                self._budget,
                self._live,
                other_scenarios,
                style or self._style,
            )
            return brief, self._writer.write_scenario(brief)
        except PathNotWritable as exc:
            return PathFailure(exc.code, exc.message, final=True)
        except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
            return PathFailure(ErrorCode.GENERATION_FAILED, shorten_text(str(exc), Writing.PROBLEM_MAX_CHARS))
        except _RAISED_FROM_A_PATH:
            raise
        except Exception:  # noqa: BLE001 — one path's fault must not cost the run its other paths
            log.exception(LogEvent.WRITER_PATH_FAILED, path_id=path["path_id"])
            return PathFailure(
                ErrorCode.INTERNAL_ERROR, ErrorMessage.JOB_UNEXPECTED.format(record_id=self._run_id)
            )


def write_at_once(
    work: Mapping[str, Callable[[], PathOutcome]], save: Callable[[str, PathOutcome], None]
) -> dict[str, BaseException]:
    """Every item's AI work at once (log context copied into each thread), each outcome passed to `save` in
    this thread the moment it is done; the outages by item, for after the others are saved."""
    outages: dict[str, BaseException] = {}
    if not work:
        return outages
    with ThreadPoolExecutor(min(Generation.WRITER_BATCH, len(work)), thread_name_prefix="writer") as pool:
        futures = {pool.submit(contextvars.copy_context().run, job): key for key, job in work.items()}
        try:
            for future in as_completed(futures):
                if (error := future.exception()) is not None:
                    outages[futures[future]] = error
                else:
                    save(futures[future], future.result())
        except BaseException:  # a lost lease or a store outage: the items not started are not started
            for future in futures:
                future.cancel()
            raise
    return outages


def save_with_unique_title(scenarios: ScenarioRepository, record: dict[str, Any], qualifier: str) -> bool:
    """Saved under the first title no other current scenario of the run has (the index decides)."""
    titles = title_candidates(record["content"]["title"], qualifier)
    while True:
        title = next(titles)
        record["content"]["title"], record["title_key"] = title, name_match_key(title)
        try:
            return scenarios.save(record)
        except TitleTaken:
            continue
