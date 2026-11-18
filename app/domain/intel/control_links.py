"""Each MITRE ATT&CK mitigation linked to the library controls that do what it says: the nearest controls are
searched, reranked and judged by the AI, and the links stored in tsg_control_links. A mitigation whose text,
candidates, prompt and models are the ones stored costs no rerank and no AI call."""

import hashlib
import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from functools import partial
from typing import Any

import structlog
from redis.exceptions import LockError
from redis.lock import Lock

from app.ai import ChatModel, RerankModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.constants import (
    AiTask,
    ChatModule,
    ControlEffect,
    ControlLinkMessage,
    ControlLinkOutcome,
    ControlLinks,
    Dependency,
    LogEvent,
    RerankGateLimits,
)
from app.core.database import get_redis_client
from app.core.exceptions import REDIS_UNAVAILABLE_ERRORS, LeaseLost, Unavailable
from app.core.lease_signal import lease_lost_signal, raise_if_lease_lost
from app.core.prompts import PROMPTS
from app.crud.attack import get_attack_repository, get_control_link_repository
from app.domain.shared.ask_ai import ask_ai_and_check
from app.domain.shared.parallel import run_in_parallel
from app.domain.shared.prompt_redaction import redacted
from app.schemas.library import LibraryControl
from app.search.snapshot import LibrarySnapshot, describe_control

log = structlog.get_logger(__name__)
_SYSTEM_PROMPT: str = PROMPTS["controls"]["links"]["text"]
_EFFECTS = frozenset(effect.value for effect in ControlEffect)
#: A mitigation as tsg_attack lists it ({attack_id, name, description}), its search text and its candidates.
_Mitigation = tuple[dict[str, Any], str, list[LibraryControl]]


@dataclass(frozen=True)
class LinkTools:
    """What one linking run asks: the library's search, the reranker and the chat model."""

    snapshot: LibrarySnapshot
    rerank: RerankModel
    chat: ChatModel


def link_mitigations_to_controls(tools: LinkTools) -> dict[str, int] | None:
    """Link every mitigation some technique names: how many were judged, unchanged and failed; None when
    another run holds the lock."""
    started = time.perf_counter()
    with _hold_linking_lock() as lost:
        if lost is None:
            log.info(LogEvent.CONTROL_LINKS_BUSY)
            return None
        counts = _link_every_mitigation(tools)
        if lost.is_set():
            log.warning(LogEvent.CONTROL_LINKS_LOCK_LOST)
    log.info(LogEvent.CONTROL_LINKS_PREPARED, seconds=round(time.perf_counter() - started, 1), **counts)
    return counts


def is_linking_locked() -> bool:
    """Whether a linking run holds the lock now (a killed run's lasts up to ControlLinks.LOCK_SECONDS)."""
    return bool(get_redis_client().exists(ControlLinks.LOCK_KEY))


@contextmanager
def _hold_linking_lock() -> Iterator[threading.Event | None]:
    """The one-run-at-a-time lock, renewed while held: its lost signal, or None when another run holds it."""
    redis = get_redis_client()
    lock = redis.lock(ControlLinks.LOCK_KEY, timeout=ControlLinks.LOCK_SECONDS, thread_local=False)
    if not lock.acquire(blocking=False):
        yield None
        return
    stopped = threading.Event()
    with lease_lost_signal(ControlLinks.LOCK_KEY) as lost:
        renewer = threading.Thread(
            target=_renew_lock, args=(lock, lost, stopped), name="control-links-lock", daemon=True
        )
        renewer.start()
        try:
            yield lost
        finally:
            stopped.set()
            renewer.join()
            with suppress(LockError, *REDIS_UNAVAILABLE_ERRORS):  # lost or Redis down: it ends by itself
                lock.release()


def _renew_lock(lock: Lock, lost: threading.Event, stopped: threading.Event) -> None:
    while not stopped.wait(ControlLinks.LOCK_RENEW_SECONDS):
        try:
            lock.reacquire()
        except LockError:  # it ran out and is gone or another run's: this run starts nothing more
            lost.set()
            return
        except REDIS_UNAVAILABLE_ERRORS:  # the next round tries again
            log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=Dependency.REDIS, exc_info=True)


def _link_every_mitigation(tools: LinkTools) -> dict[str, int]:
    """Every mitigation's outcome counted; all search texts are embedded together, before any is judged."""
    counts = {outcome.value: 0 for outcome in ControlLinkOutcome}
    mitigations: dict[str, dict[str, Any]] = {}
    for row in get_attack_repository().list_mitigations():
        mitigations.setdefault(row["attack_id"], row)  # an ATT&CK ID two sources hold is linked once
    queries = [
        f"{row['name']}: {(row.get('description') or '')[: ControlLinks.DESCRIPTION_CHARS]}"
        for row in mitigations.values()
    ]
    try:
        found = tools.snapshot.find_controls(queries, ControlLinks.CANDIDATES, ai_controls=False)
    except LeaseLost:  # the lock was lost, or the admin job ended, while the texts were embedded
        return counts
    except Unavailable as exc:  # every mitigation keeps its earlier links
        log.warning(LogEvent.CONTROL_LINKS_EMBED_FAILED, count=len(queries), message=exc.detail)
        return counts | {ControlLinkOutcome.FAILED.value: len(queries)}
    items = [
        (row, query, [control for control, _ in hits])
        for row, query, hits in zip(mitigations.values(), queries, found, strict=True)
    ]
    # A mitigation no source lists now keeps its record (only a card that names it reads it): its fingerprint
    # makes a mitigation a later import lists again cost no AI call.
    link = partial(_link_or_keep_earlier_links, tools, get_control_link_repository().list_link_fingerprints())
    limits = RerankGateLimits  # each mitigation at work holds one reranker call
    at_once = limits.RERANKS_AT_ONCE if get_settings().rerank_base_url else limits.LOCAL_RERANKS_AT_ONCE
    for outcome in run_in_parallel(link, items, at_once, "control-links"):
        if outcome is not None:
            counts[outcome.value] += 1
    return counts


def _link_or_keep_earlier_links(
    tools: LinkTools, stored: dict[str, str], item: _Mitigation
) -> ControlLinkOutcome | None:
    """One mitigation's outcome; its failure keeps its earlier links and never stops the others. None once
    the lock is lost or the admin job ended: nothing more starts."""
    mitigation = item[0]["attack_id"]
    try:
        raise_if_lease_lost()
        return _link_one_mitigation(tools, item, stored.get(mitigation))
    except LeaseLost:
        return None
    except (Unavailable, UnreadableAiAnswer, TruncatedAiAnswer) as exc:  # an AI outage or an unusable answer
        log.warning(LogEvent.CONTROL_LINK_FAILED, mitigation=mitigation, error_type=type(exc).__name__)
    except Exception as exc:  # a store error, a bug: logged whole
        log.warning(LogEvent.CONTROL_LINK_FAILED, mitigation=mitigation, error_type=type(exc).__name__, exc_info=True)
    return ControlLinkOutcome.FAILED


def _link_one_mitigation(tools: LinkTools, item: _Mitigation, stored: str | None) -> ControlLinkOutcome:
    """One mitigation: unchanged when its fingerprint is the stored one (no call at all), else judged and saved."""
    mitigation, query, found = item
    settings = get_settings()
    basis = {
        "query": query,
        "candidates": sorted([control.control_id, describe_control(control)] for control in found),
        "prompt": _SYSTEM_PROMPT,
        "chat": settings.chat_of(ChatModule.SCENARIO).model,
        "embedding": settings.embedding_model,
        "rerank": settings.rerank_model,
    }
    fingerprint = hashlib.sha256(json.dumps(basis, sort_keys=True).encode()).hexdigest()
    if fingerprint == stored:
        return ControlLinkOutcome.UNCHANGED
    link = {
        "_id": mitigation["attack_id"],
        "name": mitigation["name"],
        "fingerprint": fingerprint,
        "links": _judge_candidates(tools, mitigation, query, found) if found else [],
        "prepared_at": utc_now(),
    }
    get_control_link_repository().save_link(link)
    return ControlLinkOutcome.JUDGED


def _judge_candidates(
    tools: LinkTools, mitigation: dict[str, Any], query: str, found: list[LibraryControl]
) -> list[dict[str, Any]]:
    """The best reranked candidates the AI says do what the mitigation says: one rerank call, one chat call.
    The AI reads each control by a label (C1 ...), never by its library id."""
    scores = tools.rerank.score_relevance(query, [describe_control(control) for control in found])
    best = sorted(zip(found, scores, strict=True), key=lambda pair: (-pair[1], pair[0].control_id))
    labelled = {f"{ControlLinks.LABEL_PREFIX}{n}": pair for n, pair in enumerate(best[: ControlLinks.JUDGED], 1)}
    defence = {
        "id": mitigation["attack_id"],
        "name": mitigation["name"],
        "description": (mitigation.get("description") or "")[: ControlLinks.DESCRIPTION_CHARS],
    }
    candidates = [
        {
            "label": label,
            "name": control.name,
            "description": (control.description or "")[: ControlLinks.JUDGE_TEXT_CHARS],
        }
        for label, (control, _) in labelled.items()
    ]
    asked = [json.dumps(redacted(part), ensure_ascii=False) for part in (defence, candidates)]
    prompt = (_SYSTEM_PROMPT, f"DEFENCE:\n{asked[0]}\nCANDIDATES:\n{asked[1]}")
    links: list[dict[str, Any]] = ask_ai_and_check(
        tools.chat, AiTask.LINK_CONTROLS, prompt, partial(_read_matches, labelled)
    )
    return links


def _read_matches(
    labelled: dict[str, tuple[LibraryControl, float]], answer: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[str]]:
    """The links an answer names, best reranked first, and its problems (a label that is no candidate, an
    effect that is none of the four): any problem has the answer asked again once."""
    matches = answer.get("matches")
    if not isinstance(matches, list) or not all(isinstance(match, dict) for match in matches):
        return [], [ControlLinkMessage.MATCHES_NOT_A_LIST.value]
    named = {str(match.get("label")): match for match in matches}
    problems = [ControlLinkMessage.NOT_A_CANDIDATE.format(label=label) for label in named if label not in labelled]
    problems += [
        ControlLinkMessage.BAD_EFFECT.format(effect=match.get("effect"))
        for match in matches
        if str(match.get("effect")) not in _EFFECTS
    ]
    links = [
        {
            "control_id": control.control_id,
            "effect": str(named[label].get("effect")),
            "reason": str(named[label].get("reason") or ""),
            "rerank": round(float(score), 1),
        }
        for label, (control, score) in labelled.items()
        if label in named
    ]
    return links, problems
