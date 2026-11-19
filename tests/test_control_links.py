"""Linking each MITRE ATT&CK mitigation to library controls, with fake AI models on the real MongoDB and
Redis: one embedding call for every mitigation, no rerank and no chat call for an unchanged one, a wrong
label asked again, one failure keeping its earlier links, one run at a time, and the admin job and routes."""

import json
import threading
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from celery.exceptions import Ignore, Retry
from fastapi.testclient import TestClient
from structlog.testing import capture_logs

from app import ai
from app.core.config import get_settings
from app.core.constants import (
    AI_OUTAGE_MESSAGES,
    CONTROL_LINKS_JOB_KIND,
    AiOutage,
    AiTask,
    AttackLink,
    AttackObjectType,
    AttackRecord,
    Collection,
    ControlLinkMessage,
    ControlLinks,
    Controls,
    ErrorCode,
    IntelSource,
    Lease,
    LogEvent,
    Status,
    TaskName,
)
from app.core.database import get_mongodb, get_redis_client
from app.core.exceptions import Conflict, LeaseLost, Unavailable
from app.crud.admin_jobs import get_admin_job_repository
from app.crud.attack import attack_doc_id, get_attack_repository, get_control_link_repository
from app.domain.intel import admin
from app.domain.intel.control_links import LinkTools, link_mitigations_to_controls
from app.schemas.library import LibraryControl, ThreatLibrary
from app.search.service import LibrarySearch
from app.worker import control_links as worker
from tests.fakes import FakeChatModel, FakeEmbeddings, items_in

ICS = IntelSource.ATTACK_ICS
URL = "/v1/tsg/intel/control-links"
#: Library ids no prompt may show (a number no text here holds by chance).
MFA_CONTROL, BACKUP_CONTROL, FILTER_CONTROL, AI_CONTROL = 900412, 900087, 900530, 900009
CONTROLS = (
    LibraryControl(MFA_CONTROL, "AC-7", "IT", "Access", "Operator authentication", "Require a second factor"),
    LibraryControl(BACKUP_CONTROL, "BC-1", "OT", "BCDR", "Offline backup", "Keep an offline backup copy"),
    LibraryControl(FILTER_CONTROL, "NW-3", None, "Network", "Zone filter", "Filter traffic between zones"),
    LibraryControl(AI_CONTROL, "AI-1", None, Controls.AI_DOMAIN, "Model backup", "Keep a backup of AI models"),
)
#: mitigation -> (name, description, the word its control shares with it)
MITIGATIONS = {
    "M0932": (
        "Multi-factor Authentication",
        "Use two or more pieces of evidence for authentication.",
        "authentication",
    ),
    "M0937": ("Filter Network Traffic", "Use appliances to filter ingress or egress traffic.", "filter"),
    "M0953": ("Data Backup", "Take and store a backup of data from end user systems. " + "x" * 2_000, "backup"),
}
WORDS = tuple(word for _, _, word in MITIGATIONS.values())


def _mitigation(attack_id: str, name: str, description: str) -> list[dict[str, Any]]:
    """A mitigation object and the relationship by which technique T0859 names it."""
    stix_id = f"course-of-action--{attack_id}"
    relationship = f"relationship--{attack_id}"
    return [
        {
            "_id": attack_doc_id(ICS, stix_id),
            "record": AttackRecord.OBJECT,
            "stix_id": stix_id,
            "type": AttackObjectType.MITIGATION,
            "attack_id": attack_id,
            "name": name,
            "description": description,
        },
        {
            "_id": attack_doc_id(ICS, relationship),
            "record": AttackRecord.RELATIONSHIP,
            "type": AttackLink.MITIGATES,
            "source_ref": stix_id,
            "target_ref": "attack-pattern--valid-accounts",
        },
    ]


class Reranker:
    """90 for a control sharing the mitigation's word, 5 for any other; records what it was asked."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str]]] = []

    def score_relevance(self, query: str, documents: list[str]) -> list[float]:
        self.calls.append((query, documents))
        shared = [word for word in WORDS if word in query.casefold()]
        return [90.0 if any(word in document.casefold() for word in shared) else 5.0 for document in documents]


class ByNumber(Reranker):
    """A control named "... 07" scores 7."""

    def score_relevance(self, query: str, documents: list[str]) -> list[float]:
        self.calls.append((query, documents))
        return [float(document.split(":")[0][-2:]) for document in documents]


def defence_of(user_prompt: str) -> dict[str, Any]:
    return dict(json.loads(user_prompt.split("\nCANDIDATES:\n")[0].removeprefix("DEFENCE:\n")))


def matching_controls(user_prompt: str) -> dict[str, Any]:
    """The AI's answer: each candidate whose name shares the mitigation's word, as a prevention."""
    word = MITIGATIONS[defence_of(user_prompt)["id"]][2]
    labels = [item["label"] for item in items_in(user_prompt, "CANDIDATES") if word in item["name"].casefold()]
    return {"matches": [{"label": label, "effect": "prevent", "reason": f"It does {word}."} for label in labels]}


class Linking:
    """One linking set-up: the fake models, the stored graph and links, and a run."""

    def __init__(self, controls: tuple[LibraryControl, ...] = CONTROLS) -> None:
        self.embeddings, self.rerank, self.chat = FakeEmbeddings(WORDS), Reranker(), FakeChatModel()
        self.chat.responders[AiTask.LINK_CONTROLS] = matching_controls
        self.use_library(controls)

    def use_library(self, controls: tuple[LibraryControl, ...]) -> None:
        stamp = (("Control_Library", b""),)  # as the library cache stamps every loaded version
        library = SimpleNamespace(threat_library=ThreatLibrary((), ()), control_library=controls, stamp=stamp)
        loaded = SimpleNamespace(get_loaded_libraries=lambda: library)
        self.snapshot = LibrarySearch(loaded, self.embeddings).snapshot()  # type: ignore[arg-type]

    def run(self) -> dict[str, int] | None:
        tools = LinkTools(self.snapshot, self.rerank, self.chat)  # type: ignore[arg-type]
        return link_mitigations_to_controls(tools)

    def prompts(self) -> list[str]:
        return self.chat.asked(AiTask.LINK_CONTROLS)


def store_graph(version: str, *mitigations: str) -> None:
    """The source's graph replaced by one listing only these mitigations."""
    docs = [doc for attack_id in mitigations for doc in _mitigation(attack_id, *MITIGATIONS[attack_id][:2])]
    get_attack_repository().replace_source(ICS, docs, version)


def save_unlisted_link() -> None:
    """The links of M0001, a mitigation no stored source lists (retired by ATT&CK)."""
    link = {"control_id": MFA_CONTROL, "effect": "prevent", "reason": "x", "rerank": 90.0}
    unlisted = {"_id": "M0001", "name": "Retired", "fingerprint": "f", "links": [link]}
    get_control_link_repository().save_link(unlisted | {"prepared_at": datetime.now(UTC)})


def stored_links() -> dict[str, dict[str, Any]]:
    return {doc["_id"]: doc for doc in get_mongodb()[Collection.CONTROL_LINKS].find({})}


def linked_controls(mitigation: str) -> list[int]:
    return [link["control_id"] for link in stored_links()[mitigation]["links"]]


@pytest.fixture(autouse=True)
def attack_graph() -> Iterator[None]:
    """Three mitigations a technique names, ATT&CK's "not a mitigation" entry, and one no technique names."""
    database, redis = get_mongodb(), get_redis_client()
    for collection in (Collection.ATTACK, Collection.CONTROL_LINKS):
        database[collection].delete_many({})
    database[Collection.ADMIN_JOBS].delete_many({"kind": CONTROL_LINKS_JOB_KIND})
    redis.delete(ControlLinks.LOCK_KEY)
    docs = [doc for attack_id, (name, text, _) in MITIGATIONS.items() for doc in _mitigation(attack_id, name, text)]
    docs += _mitigation("M0816", "Mitigation Limited or Not Effective", "This type of attack is hard to prevent.")
    docs += _mitigation("M0999", "Named By No Technique", "Nothing names this backup.")[:1]
    get_attack_repository().replace_source(ICS, docs, "v1")
    yield
    redis.delete(ControlLinks.LOCK_KEY)


@pytest.fixture
def linking() -> Linking:
    return Linking()


@pytest.fixture
def one_at_a_time(monkeypatch: pytest.MonkeyPatch) -> None:
    """A local reranker: the mitigations are linked one after another, in ATT&CK ID order."""
    monkeypatch.setattr(get_settings(), "rerank_base_url", "")


def test_every_mitigation_a_technique_names_is_judged_and_its_links_saved(linking: Linking) -> None:
    assert linking.run() == {"judged": 3, "unchanged": 0, "failed": 0}
    stored = stored_links()
    assert set(stored) == set(MITIGATIONS)  # never "not a mitigation", never one no technique names
    assert {mitigation: linked_controls(mitigation) for mitigation in stored} == {
        "M0932": [MFA_CONTROL],
        "M0937": [FILTER_CONTROL],
        "M0953": [BACKUP_CONTROL],
    }
    mfa = stored["M0932"]
    assert set(mfa) >= {"_id", "name", "fingerprint", "links", "prepared_at"}
    assert mfa["name"] == "Multi-factor Authentication" and len(mfa["fingerprint"]) == 64
    assert mfa["links"] == [
        {"control_id": MFA_CONTROL, "effect": "prevent", "reason": "It does authentication.", "rerank": 90.0}
    ]


def test_all_search_texts_go_in_one_embedding_call_and_each_mitigation_costs_one_rerank_and_one_chat_call(
    linking: Linking,
) -> None:
    """Mutation: embed inside the per-mitigation work and there are three query calls."""
    linking.run()
    assert linking.embeddings.calls.count("query") == 1 and linking.embeddings.query_corpora == ["control"]
    assert len(linking.rerank.calls) == len(linking.prompts()) == 3
    queries = {query for query, _ in linking.rerank.calls}
    assert "Multi-factor Authentication: Use two or more pieces of evidence for authentication." in queries
    backup = next(query for query in queries if query.startswith("Data Backup: "))
    assert len(backup) == len("Data Backup: ") + ControlLinks.DESCRIPTION_CHARS  # the description is cut


def test_a_long_mitigation_text_is_cut_in_the_prompt_as_it_is_in_the_search(linking: Linking) -> None:
    """Mutation: send the whole text and a long mitigation costs its full length in its judging call."""
    linking.run()
    backup = next(defence_of(prompt) for prompt in linking.prompts() if defence_of(prompt)["id"] == "M0953")
    assert len(MITIGATIONS["M0953"][1]) > ControlLinks.DESCRIPTION_CHARS
    assert len(backup["description"]) == ControlLinks.DESCRIPTION_CHARS


def test_an_ai_domain_control_is_never_a_candidate(linking: Linking) -> None:
    linking.run()
    documents = [document for _, asked in linking.rerank.calls for document in asked]
    assert documents and not any(document.startswith("Model backup") for document in documents)
    assert AI_CONTROL not in linked_controls("M0953")


def test_no_library_id_reaches_the_ai_and_each_candidate_is_named_by_its_label(linking: Linking) -> None:
    """Mutation: send control_id in CANDIDATES and the id shows in the prompt."""
    linking.run()
    for prompt in linking.prompts():
        assert "control_id" not in prompt
        assert not any(str(control.control_id) in prompt or control.code in prompt for control in CONTROLS)
        candidates = items_in(prompt, "CANDIDATES")
        assert [item["label"] for item in candidates] == [f"C{n}" for n in range(1, len(candidates) + 1)]
        assert all(set(item) == {"label", "name", "description"} for item in candidates)
        assert set(defence_of(prompt)) == {"id", "name", "description"} and defence_of(prompt)["id"] in MITIGATIONS


def test_a_mail_address_in_a_mitigations_or_a_controls_text_never_reaches_the_ai(linking: Linking) -> None:
    """Mutation: send the texts as stored and the prompt shows both addresses."""
    noted = LibraryControl(BACKUP_CONTROL, "BC-1", "OT", "BCDR", "Offline backup", "Keep a backup; ask ops@plant.test")
    linking.use_library((CONTROLS[0], noted, *CONTROLS[2:]))
    reported = _mitigation("M0953", "Data Backup", "Store a backup of data; report to soc@vendor.example first.")
    get_attack_repository().replace_source(ICS, reported, "v2")
    assert linking.run() == {"judged": 1, "unchanged": 0, "failed": 0}
    (prompt,) = linking.prompts()
    assert "@" not in prompt and "[REDACTED]" in defence_of(prompt)["description"]
    assert [item["description"] for item in items_in(prompt, "CANDIDATES") if "[REDACTED]" in item["description"]] == [
        "Keep a backup; ask [REDACTED]"
    ]


def test_a_mitigation_two_sources_hold_is_judged_once(linking: Linking) -> None:
    """Mutation: judge each source's row and the same ATT&CK ID costs two rerank and two chat calls."""
    other = IntelSource.ATTACK_ENTERPRISE
    twin = [doc | {"_id": doc["_id"].replace(ICS, other, 1)} for doc in _mitigation("M0932", *MITIGATIONS["M0932"][:2])]
    get_attack_repository().replace_source(other, twin, "v1")
    assert [row["source"] for row in get_attack_repository().list_mitigations() if row["attack_id"] == "M0932"] == [
        other,
        ICS,
    ]
    assert linking.run() == {"judged": 3, "unchanged": 0, "failed": 0}
    assert sorted(defence_of(prompt)["id"] for prompt in linking.prompts()) == sorted(MITIGATIONS)


def test_the_thirty_nearest_are_reranked_and_the_best_fifteen_judged_with_short_texts() -> None:
    """Mutation: judge every candidate and the prompt holds 30; drop the sort and C1 is not the best."""
    many = tuple(
        LibraryControl(n, f"B-{n}", None, "BCDR", f"Backup rule {n:02}", "backup " + "y" * 1_000) for n in range(1, 41)
    )
    linking = Linking(many)
    linking.rerank = ByNumber()
    linking.chat.responders[AiTask.LINK_CONTROLS] = lambda prompt: {"matches": []}
    linking.run()
    reranked = next(documents for query, documents in linking.rerank.calls if query.startswith("Data Backup"))
    backup = next(prompt for prompt in linking.prompts() if defence_of(prompt)["id"] == "M0953")
    candidates = items_in(backup, "CANDIDATES")
    assert len(reranked) == ControlLinks.CANDIDATES and len(candidates) == ControlLinks.JUDGED
    best_first = sorted((document.split(":")[0] for document in reranked), reverse=True)
    assert [item["name"] for item in candidates] == best_first[: ControlLinks.JUDGED]
    assert all(len(item["description"]) == ControlLinks.JUDGE_TEXT_CHARS for item in candidates)
    assert stored_links()["M0953"]["links"] == []  # an empty list is a valid answer, saved


def test_an_unchanged_mitigation_makes_no_rerank_and_no_chat_call_on_the_next_run(linking: Linking) -> None:
    """Mutation: compare the fingerprint after the rerank and the second run reranks three times."""
    linking.run()
    first = stored_links()
    reranks, chats = len(linking.rerank.calls), len(linking.prompts())
    assert linking.run() == {"judged": 0, "unchanged": 3, "failed": 0}
    assert (len(linking.rerank.calls), len(linking.prompts())) == (reranks, chats)
    assert stored_links() == first  # not even re-saved


def test_only_the_mitigation_whose_candidates_changed_is_judged_again(linking: Linking) -> None:
    linking.run()
    edited = LibraryControl(BACKUP_CONTROL, "BC-1", "OT", "BCDR", "Offline backup", "Keep offline backup copies weekly")
    linking.use_library((CONTROLS[0], edited, *CONTROLS[2:]))
    linking.chat.calls.clear()
    assert linking.run() == {"judged": 1, "unchanged": 2, "failed": 0}
    assert [defence_of(prompt)["id"] for prompt in linking.prompts()] == ["M0953"]


@pytest.mark.parametrize("setting", ["rerank_model", "embedding_model", "scenario_chat_model"])
def test_another_model_has_every_mitigation_judged_again(
    linking: Linking, monkeypatch: pytest.MonkeyPatch, setting: str
) -> None:
    """Mutation: leave a model out of the fingerprint and its change keeps the stale links."""
    linking.run()
    monkeypatch.setattr(get_settings(), setting, "another-model")
    assert linking.run() == {"judged": 3, "unchanged": 0, "failed": 0}


def test_another_prompt_has_every_mitigation_judged_again(linking: Linking, monkeypatch: pytest.MonkeyPatch) -> None:
    """Mutation: leave the prompt out of the fingerprint and the links judged under the old wording stay."""
    linking.run()
    monkeypatch.setattr("app.domain.intel.control_links._SYSTEM_PROMPT", "Judge each candidate more strictly.")
    assert linking.run() == {"judged": 3, "unchanged": 0, "failed": 0}


def test_a_mitigation_whose_own_text_changed_is_judged_again(linking: Linking) -> None:
    """ATT&CK rewords a mitigation and its candidates stay the same. Mutation: leave the search text out of the
    fingerprint and the links judged for the old wording stay."""
    linking.run()
    kept = [doc for attack_id in ("M0932", "M0953") for doc in _mitigation(attack_id, *MITIGATIONS[attack_id][:2])]
    reworded = _mitigation("M0937", "Filter Network Traffic", "Filter the traffic that crosses each zone boundary.")
    get_attack_repository().replace_source(ICS, kept + reworded, "v2")
    linking.chat.calls.clear()
    assert linking.run() == {"judged": 1, "unchanged": 2, "failed": 0}
    assert [defence_of(prompt)["id"] for prompt in linking.prompts()] == ["M0937"]


@pytest.mark.parametrize(
    "wrong",
    [
        {"matches": [{"label": "C99", "effect": "prevent", "reason": "x"}]},
        {"matches": [{"label": "C1", "effect": "stop", "reason": "x"}]},
        {"matches": "C1"},
    ],
)
def test_a_label_outside_the_candidates_or_a_wrong_effect_is_asked_again_once(
    linking: Linking, one_at_a_time: None, wrong: dict[str, Any]
) -> None:
    """Mutation: drop the candidate check and "C99" is taken as an answer (a KeyError, or a wrong link)."""
    linking.chat.queue(AiTask.LINK_CONTROLS, wrong)  # the first mitigation's first answer
    assert linking.run() == {"judged": 3, "unchanged": 0, "failed": 0}
    asked = [defence_of(prompt)["id"] for prompt in linking.prompts()]
    assert asked == ["M0932", "M0932", "M0937", "M0953"]
    assert linked_controls("M0932") == [MFA_CONTROL]  # from the second answer


def test_a_mitigation_wrong_twice_fails_alone_and_saves_nothing(linking: Linking, one_at_a_time: None) -> None:
    wrong = {"matches": [{"label": "C99", "effect": "prevent", "reason": "x"}]}
    linking.chat.queue(AiTask.LINK_CONTROLS, wrong, wrong)
    assert linking.run() == {"judged": 2, "unchanged": 0, "failed": 1}
    assert set(stored_links()) == {"M0937", "M0953"}
    assert linking.run() == {"judged": 1, "unchanged": 2, "failed": 0}  # the next run judges only the failed one
    assert linked_controls("M0932") == [MFA_CONTROL]


def test_a_mitigation_with_no_candidate_is_saved_with_no_links_and_no_call() -> None:
    linking = Linking(())  # an empty control library
    assert linking.run() == {"judged": 3, "unchanged": 0, "failed": 0}
    assert linking.rerank.calls == [] and linking.prompts() == []
    assert {mitigation: doc["links"] for mitigation, doc in stored_links().items()} == dict.fromkeys(MITIGATIONS, [])
    assert linking.run() == {"judged": 0, "unchanged": 3, "failed": 0}


@pytest.mark.parametrize(
    "failure",
    [Unavailable(AI_OUTAGE_MESSAGES[AiOutage.DOWN], reason=AiOutage.DOWN), RuntimeError("a bug in the judging")],
)
def test_one_mitigations_failure_keeps_its_earlier_links_and_the_others_go_on(
    linking: Linking, monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    """Mutation: let the failure out of the per-mitigation work and the run stops with nothing counted."""
    linking.run()
    earlier = stored_links()
    monkeypatch.setattr(get_settings(), "rerank_model", "another-model")  # every mitigation is judged again

    def failing_for_mfa(prompt: str) -> dict[str, Any]:
        if defence_of(prompt)["id"] == "M0932":
            raise failure
        return {"matches": []}

    linking.chat.responders[AiTask.LINK_CONTROLS] = failing_for_mfa
    with capture_logs() as logs:
        assert linking.run() == {"judged": 2, "unchanged": 0, "failed": 1}
    now = stored_links()
    assert now["M0932"] == earlier["M0932"]  # its earlier links and fingerprint, so the next run tries again
    assert now["M0937"]["links"] == now["M0953"]["links"] == []
    failed = [line for line in logs if line["event"] == LogEvent.CONTROL_LINK_FAILED]
    assert [(line["mitigation"], line["error_type"]) for line in failed] == [("M0932", type(failure).__name__)]


def test_a_mitigation_left_out_of_a_release_and_listed_again_costs_no_rerank_and_no_chat_call(linking: Linking) -> None:
    """A whole run deleted the links of every mitigation the graph did not list at that moment, fingerprints
    and all, so a mitigation a later release lists again was judged again. Mutation: delete the unlisted links
    at the end of a run and the last run judges M0953."""
    linking.run()
    earlier = stored_links()
    reranks, chats = len(linking.rerank.calls), len(linking.prompts())
    store_graph("v2", "M0932", "M0937")  # ATT&CK left M0953 out of one release
    assert linking.run() == {"judged": 0, "unchanged": 2, "failed": 0} and stored_links() == earlier
    store_graph("v3", *MITIGATIONS)  # the next release lists the same three mitigations
    assert linking.run() == {"judged": 0, "unchanged": 3, "failed": 0}
    assert (len(linking.rerank.calls), len(linking.prompts())) == (reranks, chats) and stored_links() == earlier


def test_an_embedding_outage_fails_every_mitigation_and_keeps_every_link(linking: Linking) -> None:
    linking.run()
    save_unlisted_link()  # a run cut short deletes nothing
    earlier = stored_links()
    linking.embeddings.queries_down = True
    reranks, chats = len(linking.rerank.calls), len(linking.prompts())
    assert linking.run() == {"judged": 0, "unchanged": 0, "failed": 3}
    assert (len(linking.rerank.calls), len(linking.prompts())) == (reranks, chats) and stored_links() == earlier


def test_a_run_stopped_while_its_texts_are_embedded_starts_nothing(linking: Linking) -> None:
    """The embedding gateway raises LeaseLost once the lock is lost or the admin job ended."""

    def stopped(texts: list[str], corpus: str) -> None:
        raise LeaseLost(ControlLinks.LOCK_KEY)

    linking.embeddings.embed_search_queries = stopped  # type: ignore[method-assign]
    assert linking.run() == {"judged": 0, "unchanged": 0, "failed": 0}
    assert linking.rerank.calls == [] and stored_links() == {} and _lock_holder() is None


def test_no_mitigation_stored_is_a_run_with_nothing_to_do(linking: Linking) -> None:
    get_mongodb()[Collection.ATTACK].delete_many({})
    assert linking.run() == {"judged": 0, "unchanged": 0, "failed": 0}
    assert linking.embeddings.calls.count("query") == 0


def _lock_holder() -> str | None:
    return get_redis_client().get(ControlLinks.LOCK_KEY)


def test_a_second_run_at_the_same_time_is_refused_and_does_nothing(linking: Linking) -> None:
    """Mutation: take no lock and the second run judges every mitigation too."""
    judging, release = threading.Event(), threading.Event()

    def slow(prompt: str) -> dict[str, Any]:
        judging.set()
        assert release.wait(10)
        return matching_controls(prompt)

    linking.chat.responders[AiTask.LINK_CONTROLS] = slow
    first: list[dict[str, int] | None] = []
    running = threading.Thread(target=lambda: first.append(linking.run()))
    running.start()
    try:
        assert judging.wait(10)
        second = Linking()
        with capture_logs() as logs:
            assert second.run() is None
        assert second.rerank.calls == [] and second.prompts() == [] and second.embeddings.calls.count("query") == 0
        assert LogEvent.CONTROL_LINKS_BUSY in [line["event"] for line in logs]
        assert _lock_holder() is not None  # the refused run never released the first run's lock
    finally:
        release.set()
        running.join(10)
    assert first == [{"judged": 3, "unchanged": 0, "failed": 0}]
    assert _lock_holder() is None


def test_the_lock_is_released_when_the_run_ends_or_breaks(linking: Linking, monkeypatch: pytest.MonkeyPatch) -> None:
    linking.run()
    assert _lock_holder() is None
    monkeypatch.setattr(get_attack_repository(), "list_mitigations", lambda: 1 / 0)
    with pytest.raises(ZeroDivisionError):
        linking.run()
    assert _lock_holder() is None
    monkeypatch.undo()
    assert linking.run() == {"judged": 0, "unchanged": 3, "failed": 0}


def test_the_lock_is_renewed_while_the_run_lasts(
    linking: Linking, one_at_a_time: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mutation: start no renewer and the lock runs out under a run longer than its life."""
    monkeypatch.setattr(ControlLinks, "LOCK_SECONDS", 1)
    monkeypatch.setattr(ControlLinks, "LOCK_RENEW_SECONDS", 0.05)
    held: list[bool] = []

    def slow(prompt: str) -> dict[str, Any]:
        if not held:
            time.sleep(1.5)  # longer than the lock's life
        held.append(_lock_holder() is not None)
        return matching_controls(prompt)

    linking.chat.responders[AiTask.LINK_CONTROLS] = slow
    assert linking.run() == {"judged": 3, "unchanged": 0, "failed": 0}
    assert held == [True, True, True]


def test_a_run_that_lost_its_lock_starts_no_further_mitigation(
    linking: Linking, one_at_a_time: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mutation: never check the lost signal and all three are judged under a lock another run may hold."""
    monkeypatch.setattr(ControlLinks, "LOCK_RENEW_SECONDS", 0.02)
    save_unlisted_link()

    def lock_taken_meanwhile(prompt: str) -> dict[str, Any]:
        get_redis_client().set(ControlLinks.LOCK_KEY, "another run")
        time.sleep(0.5)  # the renewer finds the lock is another's
        return matching_controls(prompt)

    linking.chat.responders[AiTask.LINK_CONTROLS] = lock_taken_meanwhile
    with capture_logs() as logs:
        assert linking.run() == {"judged": 1, "unchanged": 0, "failed": 0}
    assert len(linking.prompts()) == 1 and set(stored_links()) == {"M0932", "M0001"}  # nothing deleted either
    assert LogEvent.CONTROL_LINKS_LOCK_LOST in [line["event"] for line in logs]
    assert _lock_holder() == "another run"  # never released: it is not this run's


# --- the admin job ---


def _queued_job() -> str:
    job = {"_id": uuid.uuid4().hex, "kind": CONTROL_LINKS_JOB_KIND, "status": Status.QUEUED, "requested_by": "op-1"}
    assert get_admin_job_repository().create_admin_job(job | {"created_at": datetime.now(UTC)}) == job["_id"]
    return str(job["_id"])


def _job(job_id: str) -> dict[str, Any]:
    found = get_admin_job_repository().get_any_admin_job(job_id)
    assert found is not None
    return found


@pytest.fixture
def worker_models(linking: Linking, monkeypatch: pytest.MonkeyPatch) -> Linking:
    """The task's own library search and models answer from the fakes."""
    monkeypatch.setattr(worker, "get_library_search", lambda: SimpleNamespace(snapshot=lambda wait: linking.snapshot))
    monkeypatch.setattr(ai.rerank, "get_rerank_model", lambda: linking.rerank)
    monkeypatch.setattr(ai.chat, "get_scenario_chat_model", lambda: linking.chat)
    return linking


def test_an_admins_preparation_ends_done_with_its_counts(worker_models: Linking) -> None:
    job_id = _queued_job()
    worker.run_control_links_job(job_id)
    job = _job(job_id)
    assert (job["status"], job["result"]) == (Status.DONE, {"judged": 3, "unchanged": 0, "failed": 0})
    assert job["started_at"] <= job["finished_at"] and "active" not in job and "error" not in job
    again = _queued_job()  # one active job per kind: the first one ended
    worker.link_mitigations(again)
    assert _job(again)["result"] == {"judged": 0, "unchanged": 3, "failed": 0}
    worker.run_control_links_job(again)  # a repeated message for an ended job does nothing
    assert len(worker_models.prompts()) == 3


def _jobs_requested_by_import() -> list[dict[str, Any]]:
    requested = {"kind": CONTROL_LINKS_JOB_KIND, "requested_by": ControlLinks.AFTER_IMPORT}
    return list(get_mongodb()[Collection.ADMIN_JOBS].find(requested))


def test_the_task_without_a_job_links_after_an_import_under_a_job_record_of_its_own(
    client: TestClient, sent: list[tuple[str, str]], worker_models: Linking
) -> None:
    """Without a record the run after an import was unseen by "one at a time": an admin's Prepare meanwhile got
    202 and then failed on the lock. Mutation: run it with no record and the first Prepare is accepted."""
    while_it_runs: list[Any] = []
    answer = worker_models.chat.responders[AiTask.LINK_CONTROLS]

    def prepare_meanwhile(prompt: str) -> dict[str, Any]:
        try:
            while_it_runs.append(admin.create_control_links_job("op-9")["job_id"])  # accepted: the fault
        except Conflict as refused:
            while_it_runs.append(refused.details)
        return answer(prompt)

    worker_models.chat.responders[AiTask.LINK_CONTROLS] = prepare_meanwhile
    worker.link_mitigations()
    assert set(stored_links()) == set(MITIGATIONS)
    (job,) = _jobs_requested_by_import()
    assert (job["status"], job["result"]) == (Status.DONE, {"judged": 3, "unchanged": 0, "failed": 0})
    assert "active" not in job and sent == []
    assert while_it_runs == [{"job_id": job["_id"]}] * 3  # each Prepare was told which job runs
    shown = client.get(f"{URL}/{job['_id']}").json()  # followed and read as an admin's own
    assert (shown["requested_by"], shown["status"]) == ("import", "done")


def test_the_run_after_an_import_waits_its_turn_while_another_preparation_is_active(worker_models: Linking) -> None:
    """An import that ends while a preparation runs: that one may have listed the graph before the import, and
    the import's own run was dropped at the lock, so its mitigations were never linked. Mutation: return
    instead of retrying and nothing brings the import's run back."""
    store_graph("before the import", "M0932", "M0937")
    active = _queued_job()  # an admin's preparation is active when the import ends
    store_graph("after the import", *MITIGATIONS)
    with pytest.raises(Retry):
        worker.link_mitigations()
    assert _jobs_requested_by_import() == [] and stored_links() == {}
    worker.link_mitigations(active)  # it ends; the message comes back after ControlLinks.WAIT_TURN_SECONDS
    get_mongodb()[Collection.CONTROL_LINKS].delete_one({"_id": "M0953"})  # as if it had listed the earlier graph
    worker.link_mitigations()
    assert linked_controls("M0953") == [BACKUP_CONTROL]
    assert [job["result"] for job in _jobs_requested_by_import()] == [{"judged": 1, "unchanged": 2, "failed": 0}]


def test_the_run_after_an_import_waits_while_an_ended_run_still_holds_the_lock(worker_models: Linking) -> None:
    """A cancelled run finishing its mitigation, or a killed one's lock: no job is active, yet a run now would
    end busy and the import's linking be lost. Mutation: drop the lock check and it leaves a failed job."""
    held = get_redis_client().lock(ControlLinks.LOCK_KEY, timeout=30)
    assert held.acquire(blocking=False)
    with pytest.raises(Retry):
        worker.link_mitigations()
    assert _jobs_requested_by_import() == [] and stored_links() == {}  # not even a failed record
    held.release()
    worker.link_mitigations()
    assert set(stored_links()) == set(MITIGATIONS)
    assert [job["status"] for job in _jobs_requested_by_import()] == [Status.DONE]


def test_a_preparation_that_finds_the_lock_held_fails_saying_so(worker_models: Linking) -> None:
    held = get_redis_client().lock(ControlLinks.LOCK_KEY, timeout=30)
    assert held.acquire(blocking=False)
    job_id = _queued_job()
    worker.run_control_links_job(job_id)
    held.release()
    job = _job(job_id)
    assert (job["status"], job["error"]) == (
        Status.FAILED,
        {"code": ErrorCode.CONFLICT, "message": ControlLinkMessage.BUSY},
    )
    assert worker_models.prompts() == [] and stored_links() == {}


def test_a_preparation_that_breaks_ends_failed_and_frees_the_kind(
    worker_models: Linking, monkeypatch: pytest.MonkeyPatch
) -> None:
    def library_down() -> None:
        raise Unavailable("SQL Server is unreachable.")

    monkeypatch.setattr(worker, "get_library_search", library_down)
    job_id = _queued_job()
    with pytest.raises(Unavailable):
        worker.run_control_links_job(job_id)
    job = _job(job_id)
    assert (job["status"], job["error"]["code"]) == (Status.FAILED, ErrorCode.UNAVAILABLE)
    _queued_job()  # a new one can start


def test_a_job_cancelled_meanwhile_that_then_breaks_ends_quietly(
    worker_models: Linking, monkeypatch: pytest.MonkeyPatch
) -> None:
    job_id = _queued_job()

    def cancelled_then_broken() -> None:
        assert get_admin_job_repository().cancel_admin_job(job_id, datetime.now(UTC), "op-2")
        raise RuntimeError("the library broke after its job ended")

    monkeypatch.setattr(worker, "get_library_search", cancelled_then_broken)
    with pytest.raises(Ignore):
        worker.run_control_links_job(job_id)
    assert _job(job_id)["status"] == Status.CANCELLED


def test_a_cancel_stops_the_preparation_at_the_next_mitigation(
    worker_models: Linking, one_at_a_time: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mutation: keep the heartbeat "never lost" and a cancelled preparation judges every mitigation."""
    monkeypatch.setattr(Lease, "RENEW_EVERY_SECONDS", 0.02)
    job_id = _queued_job()

    def cancelled_meanwhile(prompt: str) -> dict[str, Any]:
        get_admin_job_repository().cancel_admin_job(job_id, datetime.now(UTC), "op-2")
        time.sleep(0.5)  # the heartbeat finds the job ended
        return matching_controls(prompt)

    worker_models.chat.responders[AiTask.LINK_CONTROLS] = cancelled_meanwhile
    worker.run_control_links_job(job_id)
    job = _job(job_id)
    assert job["status"] == Status.CANCELLED and "result" not in job
    assert len(worker_models.prompts()) == 1
    assert _lock_holder() is None


# --- the routes ---


@pytest.fixture(autouse=True)
def switch(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """External intelligence on (the suite runs with it off); a test turns it off with `switch.on = False`."""
    state = SimpleNamespace(on=True)
    monkeypatch.setattr(admin, "get_intelligence_switch", lambda: SimpleNamespace(is_on=lambda: state.on))
    return state


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """The job queue: every send accepted and kept."""
    queue: list[tuple[str, str]] = []
    monkeypatch.setattr(admin, "send_admin_job", lambda task, job_id: queue.append((task, job_id)) or True)
    return queue


def test_a_preparation_starts_while_external_intelligence_is_off(
    client: TestClient, sent: list[tuple[str, str]], switch: SimpleNamespace
) -> None:
    """ADR-010: the MITRE run's controls start from these links, so they are prepared with the switch off too."""
    switch.on = False
    assert client.post(f"{URL}/prepare").status_code == 202
    assert (
        len(sent) == 1 and get_mongodb()[Collection.ADMIN_JOBS].count_documents({"kind": CONTROL_LINKS_JOB_KIND}) == 1
    )
    assert client.get(URL).status_code == 200  # the summary is still read


def test_a_preparation_is_queued_once_at_a_time_read_back_and_audited(
    client: TestClient, sent: list[tuple[str, str]]
) -> None:
    started = client.post(f"{URL}/prepare", headers={"X-User-Id": "op-7"})  # no key, as the other intel routes
    assert started.status_code == 202 and started.json()["status"] == "queued"
    job_id = started.json()["job_id"]
    assert sent == [(TaskName.LINK_MITIGATIONS, job_id)]
    again = client.post(f"{URL}/prepare")
    assert again.status_code == 409 and len(sent) == 1
    assert (again.json()["reason"], again.json()["details"]) == ("job_in_progress", {"job_id": job_id})
    assert again.json()["detail"] == ControlLinkMessage.IN_PROGRESS
    job = client.get(f"{URL}/{job_id}")
    assert job.status_code == 200
    assert (job.json()["kind"], job.json()["status"], job.json()["requested_by"]) == ("control_links", "queued", "op-7")
    assert job.json()["result"] is None
    audited = get_mongodb()[Collection.AUDIT].find_one({"action": "admin.job_started", "target.id": job_id})
    assert audited is not None
    assert (audited["after"], audited["actor"]["user_id"]) == ({"kind": "control_links"}, "op-7")


def test_a_finished_preparation_shows_its_counts_and_the_next_one_may_start(
    client: TestClient, sent: list[tuple[str, str]], worker_models: Linking
) -> None:
    job_id = client.post(f"{URL}/prepare").json()["job_id"]
    worker.link_mitigations(job_id)
    job = client.get(f"{URL}/{job_id}").json()
    assert (job["status"], job["result"]) == ("done", {"judged": 3, "unchanged": 0, "failed": 0})
    assert job["error"] is None and job["finished_at"]
    assert client.post(f"{URL}/prepare").status_code == 202


def test_a_job_of_another_kind_or_an_unknown_one_is_not_found_here(client: TestClient) -> None:
    database = get_mongodb()[Collection.ADMIN_JOBS]
    database.delete_many({"_id": "refresh-1"})
    database.insert_one({"_id": "refresh-1", "kind": "intel_refresh", "status": "done", "requested_by": "x"})
    assert client.get(f"{URL}/refresh-1").status_code == 404
    assert client.get(f"{URL}/no-such-job").status_code == 404
    assert client.get(f"{URL}/{'j' * 65}").status_code == 422
    database.delete_many({"_id": "refresh-1"})


def test_an_unreachable_queue_answers_503_and_leaves_no_job_in_the_way(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(admin, "send_admin_job", lambda task, job_id: False)
    refused = client.post(f"{URL}/prepare")
    assert refused.status_code == 503 and refused.json()["detail"] == ControlLinkMessage.NOT_SENT
    failed = get_mongodb()[Collection.ADMIN_JOBS].find_one({"kind": CONTROL_LINKS_JOB_KIND})
    assert failed is not None and failed["status"] == Status.FAILED and "active" not in failed
    assert get_mongodb()[Collection.AUDIT].find_one({"action": "admin.job_started", "target.id": failed["_id"]}) is None


def test_the_summary_counts_linked_and_unlinked_mitigations(client: TestClient, linking: Linking) -> None:
    empty = client.get(URL)
    assert empty.status_code == 200
    nothing = {"mitigations": 0, "linked": 0, "without_links": 0, "prepared_at": None}
    assert empty.json() == nothing | {"not_prepared": 3}  # the graph lists three, none is judged yet
    linking.chat.responders[AiTask.LINK_CONTROLS] = lambda prompt: (
        {"matches": []} if defence_of(prompt)["id"] == "M0937" else matching_controls(prompt)
    )
    linking.run()
    summary = client.get(URL).json()
    assert (summary["mitigations"], summary["linked"], summary["without_links"]) == (3, 2, 1)
    newest = max(doc["prepared_at"] for doc in stored_links().values())
    assert datetime.fromisoformat(summary["prepared_at"]).replace(tzinfo=UTC) == newest.replace(tzinfo=UTC)


def test_the_summary_counts_against_the_stored_graph(client: TestClient, linking: Linking) -> None:
    """It counted every link document and nothing else: an unlisted mitigation stayed "prepared", and
    one whose judging failed was in no number, so a half-done linking read as complete."""
    wrong = {"matches": [{"label": "C99", "effect": "prevent", "reason": "x"}]}
    linking.chat.responders[AiTask.LINK_CONTROLS] = lambda prompt: (
        wrong if defence_of(prompt)["id"] == "M0932" else matching_controls(prompt)
    )
    assert linking.run() == {"judged": 2, "unchanged": 0, "failed": 1}
    save_unlisted_link()  # newer than any other, with a control: never counted
    summary = client.get(URL).json()
    counted = (summary["mitigations"], summary["linked"], summary["without_links"], summary["not_prepared"])
    assert counted == (2, 2, 0, 1)
    listed = max(doc["prepared_at"] for mitigation, doc in stored_links().items() if mitigation != "M0001")
    assert datetime.fromisoformat(summary["prepared_at"]).replace(tzinfo=UTC) == listed.replace(tzinfo=UTC)


def test_the_three_routes_are_in_the_api_document_and_the_summary_is_not_read_as_a_job(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    assert set(paths[URL]) == {"get"} and set(paths[f"{URL}/prepare"]) == {"post"}
    assert set(paths[f"{URL}/{{job_id}}"]) == {"get"}
    shown = paths[URL]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    assert shown.endswith("/ControlLinksSummary")
