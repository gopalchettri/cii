"""A written ATT&CK set's controls, picked per sentence, with fake AI models on the real MongoDB: the shortlist
code builds (the prepared links of its named and its techniques' recorded mitigations first, then the nearest by
meaning, only fitting rows, a copy once), the one AI call
for the set, every pick checked with its drop reason recorded, the fall-back to the search, and the stored
record as the API view and a remediation plan read it."""

import dataclasses
import json
import threading
import time
import uuid
from collections import Counter, defaultdict
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from structlog.testing import capture_logs

from app.ai import TruncatedAiAnswer, UnreadableAiAnswer
from app.core.config import get_settings
from app.core.constants import (
    AI_OUTAGE_MESSAGES,
    AiOutage,
    AiTask,
    AttackMessage,
    Collection,
    ControlLinks,
    ControlMatch,
    ControlMatchStatus,
    ControlPickDrop,
    Controls,
    ErrorCode,
    IntelSource,
    LogEvent,
    Remediation,
    ReviewFlag,
    ScenarioStatus,
    Status,
    Step,
    TaskName,
    TechniqueControlState,
)
from app.core.database import get_mongodb
from app.core.exceptions import JobFailed, LeaseLost, Unavailable
from app.crud import scenarios as scenario_crud
from app.crud import work_control
from app.crud.attack import AttackRepository, ControlLinkRepository
from app.crud.audit import AuditRepository
from app.crud.remediation import PLANNED_SCENARIO_FIELDS
from app.domain.remediation.write import assess_controls, build_snapshot, list_affected_systems, plan_prompt
from app.domain.scenario import attack_controls
from app.domain.scenario.attack_controls import is_attack_scenario, pick_set_controls
from app.domain.scenario.session import build_scenario_view
from app.domain.scenario.write import find_alternative_controls, map_controls
from app.schemas.library import LibraryControl
from app.worker import remediation as plan_job
from app.worker.scenario import controls_job
from tests.fakes import FakeChatModel, FakeEmbeddings
from tests.test_control_mapping import _OT_CONTEXT, _SCENARIO, _ScoresByText, _snapshot
from tests.test_v1_scenario_format import _record

ICS = IntelSource.ATTACK_ICS
#: Library ids no prompt may show (numbers no text here holds by chance). The two authentication rows are one
#: control's IT and OT copies.
MFA_IT, MFA_OT, BACKUP_OT, FILTER, PATCH_IT, AI_BACKUP = CONTROLS = (
    LibraryControl(900412, "AC-7", "IT", "Access", "Operator authentication", "Require a second factor"),
    LibraryControl(900413, "AC-7", "OT", "Access", "Operator authentication", "Require a second factor"),
    LibraryControl(900087, "BC-1", "OT", "BCDR", "Offline backup", "Keep an offline backup copy"),
    LibraryControl(900530, "NW-3", None, "Network", "Zone filter", "Filter traffic between zones"),
    LibraryControl(900600, "PM-2", "IT", "Operations", "Server patching", "Apply each patch to office servers"),
    LibraryControl(900009, "AI-1", None, Controls.AI_DOMAIN, "Model backup", "Keep a backup of AI models"),
)
WORDS = ("authentication", "backup", "filter", "patch")
#: S1 names the OT system, S2 the IT one, S3 none; R1 is the risk statement's one sentence.
S1 = "Sandworm Team defeats authentication on the SCADA server with stolen operator accounts."
S2 = "It then wipes the backup on the Historian."
S3 = "No filter between zones slows it and no patch is applied."
R1 = "Loss of the backup could stop electricity transmission."
NAMES = {
    "T0859": "Valid Accounts",
    "T0800": "Activate Firmware Update Mode",
    "T0809": "Data Destruction",
    "T0886": "Remote Services",
    "M0932": "Multi-factor Authentication",
    "M0953": "Data Backup",
    "M0930": "Network Segmentation",
}
#: technique -> the mitigations ATT&CK records for it, as the writer stores them on the card
MITIGATED_BY = {"T0859": ["M0932"], "T0800": [], "T0809": ["M0953"], "T0886": ["M0930"]}
SCADA, HISTORIAN = 321, 322  # _OT_CONTEXT's OT and IT supporting systems
NOW = datetime(2026, 11, 17, 2, 0, tzinfo=UTC)


def _link(mitigation: str, *controls: tuple[int, float]) -> None:
    """Store a mitigation's prepared links: (library control id, rerank score) each."""
    links = [
        {"control_id": control_id, "effect": "prevent", "reason": "r", "rerank": score}
        for control_id, score in controls
    ]
    get_mongodb()[Collection.CONTROL_LINKS].replace_one(
        {"_id": mitigation},
        {
            "_id": mitigation,
            "name": NAMES.get(mitigation, mitigation),
            "fingerprint": "f",
            "links": links,
            "prepared_at": NOW,
        },
        upsert=True,
    )


def _scenario(
    scenario_id: str = "sc-1",
    systems: tuple[int, ...] = (SCADA, HISTORIAN),
    techniques: tuple[str, ...] = ("T0859",),
    mitigations: tuple[str, ...] = ("M0932",),
    **content: Any,
) -> dict[str, Any]:
    """A scenario card of an ATT&CK run, as the controls job claims it."""
    attack = {
        "group": {"id": "G0034", "name": "Sandworm Team"},
        "techniques": [
            {"id": technique, "name": NAMES[technique], "source": ICS, "mitigations": MITIGATED_BY[technique]}
            for technique in techniques
        ],
        "mitigations": [{"id": mitigation, "name": NAMES[mitigation]} for mitigation in mitigations],
    }
    written = {
        "title": "Operator accounts abused",
        "statement": f"{S1} {S2} {S3}",
        "risk_statement": R1,
        "category": "Spoofing",
        "threat": {"type": "Credential abuse", "name": "Stolen operator accounts"},
        "actors": [{"name": "Sandworm Team", "role": "acting"}],
        "systems": [{"id": system_id} for system_id in systems],
        "attack": attack,
    }
    return {"_id": scenario_id, "content": written | content}


def scenarios_in(user_prompt: str) -> list[dict[str, Any]]:
    """The pick prompt's scenarios."""
    return list(json.loads(user_prompt.removeprefix("SCENARIOS:\n")))


def picking(*picks: tuple[str, str, str, str]) -> Callable[[str], dict[str, Any]]:
    """The AI's answer: per (slot, sentence, control name, effect), the label the prompt gives that control;
    a name the prompt does not list is answered as the label itself."""

    def answer(user_prompt: str) -> dict[str, Any]:
        by_slot: dict[str, list[dict[str, Any]]] = defaultdict(list)
        asked = scenarios_in(user_prompt)
        labels = {item["slot"]: {control["name"]: control["label"] for control in item["CONTROLS"]} for item in asked}
        for slot, sentence, name, effect in picks:
            by_slot[slot].append({"sentence": sentence, "label": labels[slot].get(name, name), "effect": effect})
        return {"scenarios": [{"slot": item["slot"], "picks": by_slot[item["slot"]]} for item in asked]}

    return answer


class Picking:
    """One pick set-up: the fake models and the library's search."""

    def __init__(self) -> None:
        self.embeddings, self.chat = FakeEmbeddings(WORDS), FakeChatModel()
        self.rerank = _ScoresByText({"Offline backup": 80.0, "Zone filter": 60.0})
        self.use_library(*CONTROLS)

    def use_library(self, *controls: LibraryControl) -> None:
        self.snapshot = _snapshot(*controls, embeddings=self.embeddings)

    def answer(self, *picks: tuple[str, str, str, str]) -> None:
        self.chat.queue(AiTask.PICK_CONTROLS, picking(*picks))

    def pick(self, *scenarios: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return pick_set_controls(self.rerank, list(scenarios), _OT_CONTEXT, self.snapshot)  # type: ignore[arg-type]

    def prompts(self) -> list[str]:
        return self.chat.asked(AiTask.PICK_CONTROLS)

    def offered(self, slot: int = 1) -> list[str]:
        """The control names the last prompt offered a slot, in label order."""
        return [control["name"] for control in scenarios_in(self.prompts()[-1])[slot - 1]["CONTROLS"]]


@pytest.fixture(autouse=True)
def control_links() -> None:
    """M0932 linked to the IT copy of the authentication control, and no other link."""
    get_mongodb()[Collection.CONTROL_LINKS].delete_many({})
    _link("M0932", (MFA_IT.control_id, 90.0))


@pytest.fixture
def picker(monkeypatch: pytest.MonkeyPatch) -> Picking:
    picker = Picking()
    monkeypatch.setattr(attack_controls, "get_scenario_chat_model", lambda: picker.chat)
    return picker


def _ids(entries: list[dict[str, Any]]) -> list[int]:
    return [entry["control_id"] for entry in entries]


def test_the_shortlist_is_the_linked_controls_first_then_the_nearest_by_meaning_and_nothing_is_padded(
    picker: Picking,
) -> None:
    picker.answer()
    (record,) = picker.pick(_scenario()).values()
    shortlist = _ids(record["shortlist"])
    assert shortlist[:2] == [MFA_IT.control_id, BACKUP_OT.control_id]  # the link, then the risk statement's nearest
    assert set(shortlist[2:]) == {FILTER.control_id, PATCH_IT.control_id}  # the third sentence's two
    assert MFA_OT.control_id not in shortlist  # an IT and an OT copy of one control: offered once
    assert AI_BACKUP.control_id not in shortlist  # an AI-domain control: only for an AI threat
    assert picker.offered()[:2] == ["Operator authentication", "Offline backup"]
    assert (record["items"], record["picks"], record["dropped"]) == ([], [], [])  # the AI picked none: none shown
    assert set(record) == {"items", "query", "shortlist", "made_with", "picks", "dropped", "technique_states"}


def test_the_best_reranked_link_comes_first_and_the_shortlist_never_passes_its_size(picker: Picking) -> None:
    many = tuple(LibraryControl(900700 + n, f"X-{n}", None, "Ops", f"Extra rule {n:02d}", "Text") for n in range(20))
    picker.use_library(*CONTROLS, *many)
    _link("M0932", (MFA_IT.control_id, 40.0), *((control.control_id, 50.0 + n) for n, control in enumerate(many)))
    picker.answer()
    (record,) = picker.pick(_scenario()).values()
    shortlist = _ids(record["shortlist"])
    assert len(shortlist) == ControlLinks.SHORTLIST
    assert shortlist == [control.control_id for control in reversed(many)][: ControlLinks.SHORTLIST]
    # One place left after the links: the first searched text's nearest takes it, and the turn ends there.
    _link("M0932", (MFA_IT.control_id, 40.0), *((control.control_id, 50.0 + n) for n, control in enumerate(many[:10])))
    picker.answer()
    (record,) = picker.pick(_scenario()).values()
    linked = [control.control_id for control in reversed(many[:10])] + [MFA_IT.control_id]
    assert _ids(record["shortlist"]) == [*linked, BACKUP_OT.control_id]


@pytest.mark.parametrize("named", [(), ("M0953",)], ids=["no mitigation named", "an unrelated one named"])
def test_the_links_of_a_mitigation_attack_records_for_a_technique_are_offered_though_the_ai_did_not_name_it(
    picker: Picking, named: tuple[str, ...]
) -> None:
    """Mutation: shortlist only the named mitigations' links, and the technique's linked control no longer
    leads the shortlist: the risk statement's nearest does."""
    picker.answer(("SC1", "S1", "Operator authentication", "prevent"))
    (record,) = picker.pick(_scenario(mitigations=named)).values()
    assert _ids(record["shortlist"])[:2] == [MFA_IT.control_id, BACKUP_OT.control_id]
    assert record["technique_states"] == [{"id": "T0859", "state": TechniqueControlState.MATCHED}]


def test_a_technique_whose_linked_controls_did_not_reach_the_shortlist_is_not_offered_never_not_picked(
    picker: Picking,
) -> None:
    """The named mitigation's links fill the shortlist, so the technique's own linked control is never shown."""
    many = tuple(LibraryControl(900700 + n, f"X-{n}", None, "Ops", f"Extra rule {n:02d}", "Text") for n in range(20))
    picker.use_library(*CONTROLS, *many)
    _link("M0953", *((control.control_id, 50.0 + n) for n, control in enumerate(many)))
    _link("M0932", (MFA_IT.control_id, 40.0))
    picker.answer()
    (record,) = picker.pick(_scenario(mitigations=("M0953",))).values()
    assert MFA_IT.control_id not in _ids(record["shortlist"]) and len(record["shortlist"]) == ControlLinks.SHORTLIST
    assert record["technique_states"] == [{"id": "T0859", "state": TechniqueControlState.NOT_OFFERED}]


def test_only_controls_of_the_scenarios_own_it_ot_type_are_offered_a_linked_one_as_its_fitting_copy(
    picker: Picking,
) -> None:
    """An OT scenario: the link names the IT copy, so its OT copy is offered; the IT-only control never is."""
    picker.answer()
    (record,) = picker.pick(_scenario(systems=(SCADA,))).values()
    assert _ids(record["shortlist"]) == [MFA_OT.control_id, BACKUP_OT.control_id, FILTER.control_id]


#: One linked control of each stored type, so each is offered whenever its type fits.
TYPED = {
    "IT": LibraryControl(900801, "HY-1", "IT", "Access", "Office account lockout", "Lock office accounts"),
    "OT": LibraryControl(900802, "HY-2", "OT", "Access", "Plant account lockout", "Lock plant accounts"),
    r"IT\OT": LibraryControl(900803, "HY-3", r"IT\OT", "Access", "Shared account lockout", "Lock every account"),
}


@pytest.mark.parametrize(
    ("asset", "systems", "offered"),
    [
        (r"IT\OT", (), {"IT", "OT", r"IT\OT"}),
        (r"IT\OT", (r"IT\OT",), {"IT", "OT", r"IT\OT"}),
        ("IT", (), {"IT", r"IT\OT"}),
        ("OT", (), {"OT", r"IT\OT"}),
    ],
    ids=["hybrid asset, no system", "hybrid asset and system", "IT asset", "OT asset"],
)
def test_a_hybrid_asset_is_offered_every_type_and_an_it_or_ot_one_never_the_other_sides(
    picker: Picking, asset: str, systems: tuple[str, ...], offered: set[str]
) -> None:
    r"""IT\OT fits both sides; IT gets IT and IT\OT rows, never OT, and OT the reverse.
    Mutation: map IT\OT to itself only, and a hybrid asset is never offered an IT or an OT row."""
    picker.use_library(*TYPED.values())
    _link("M0932", *((control.control_id, 90.0 - n) for n, control in enumerate(TYPED.values())))
    listed = [_OT_CONTEXT.systems[0] | {"category_code": code} for code in systems]
    context = dataclasses.replace(_OT_CONTEXT, asset=_OT_CONTEXT.asset | {"category_code": asset}, systems=listed)
    picker.answer()
    scenario = _scenario(systems=tuple(system["id"] for system in listed))
    (record,) = pick_set_controls(picker.rerank, [scenario], context, picker.snapshot).values()  # type: ignore[arg-type]
    by_id = {control.control_id: kind for kind, control in TYPED.items()}
    assert {by_id[control_id] for control_id in _ids(record["shortlist"])} == offered


def test_an_ai_domain_control_is_offered_only_for_a_threat_about_ai(picker: Picking) -> None:
    picker.answer()
    about_ai = {"type": "AI misuse", "name": "LLM model theft"}
    (record,) = picker.pick(_scenario(threat=about_ai)).values()
    assert AI_BACKUP.control_id in _ids(record["shortlist"])
    assert record["made_with"]["ai_controls"] is True


def test_with_no_prepared_links_yet_the_shortlist_is_filled_by_meaning_alone(picker: Picking) -> None:
    get_mongodb()[Collection.CONTROL_LINKS].delete_many({})
    picker.answer(("SC1", "R1", "Offline backup", "recover"))
    (record,) = picker.pick(_scenario()).values()
    in_library = {MFA_IT.control_id, BACKUP_OT.control_id, FILTER.control_id, PATCH_IT.control_id}
    assert set(_ids(record["shortlist"])) == in_library
    assert _ids(record["items"]) == [BACKUP_OT.control_id]
    # Mutation: read "no link record yet" as "judged, no control does it", and this says no_library_control.
    assert record["technique_states"] == [{"id": "T0859", "state": TechniqueControlState.NOT_PREPARED}]


def test_each_searched_text_gives_its_few_nearest_taken_in_turn(picker: Picking) -> None:
    """Five backup controls sit near the risk statement and two filter controls near the one sentence: the
    risk statement gives ControlLinks.MEANING_HITS of them, one at a time with the sentence's."""
    backups = [
        LibraryControl(900900 + n, f"B-{n}", None, "BCDR", f"Backup rule {n}", "Keep a backup") for n in range(5)
    ]
    filters = [LibraryControl(900950 + n, f"F-{n}", None, "Net", f"Filter rule {n}", "Filter it") for n in range(2)]
    picker.use_library(*backups, *filters)
    get_mongodb()[Collection.CONTROL_LINKS].delete_many({})
    picker.answer()
    picker.pick(_scenario(statement="No filter between zones slows it."))
    kinds = [name.split()[0] for name in picker.offered()]
    assert kinds == ["Backup", "Filter", "Backup", "Filter", "Backup"]


def test_a_kept_pick_is_an_exact_item_with_its_effect_and_sentence_risk_sentence_picks_first(picker: Picking) -> None:
    picker.answer(
        ("SC1", "S3", "Zone filter", "contain"), ("SC1", "S2", "Server patching", "prevent"),
        ("SC1", "R1", "Offline backup", "recover"),
    )  # fmt: skip
    (record,) = picker.pick(_scenario()).values()
    assert [(item["code"], item["rank"], item["rationale"]) for item in record["items"]] == [
        ("BC-1", 1, f"recover: {R1}"),
        ("PM-2", 2, f"prevent: {S2}"),
        ("NW-3", 3, f"contain: {S3}"),
    ]
    first = record["items"][0]
    assert first == {
        "control_id": BACKUP_OT.control_id, "code": "BC-1", "name": "Offline backup", "domain": "BCDR",
        "asset_type": "OT", "description": "Keep an offline backup copy", "rank": 1, "score": None,
        "match": ControlMatch.EXACT, "tier": "strong", "rationale": f"recover: {R1}",
    }  # fmt: skip
    searched = map_controls(picker.rerank, _scenario(), _OT_CONTEXT, picker.snapshot)  # type: ignore[arg-type]
    assert list(first) == list(searched["items"][0])  # the search's own item, field for field
    assert [(pick["sentence"], pick["text"], pick["effect"]) for pick in record["picks"]] == [
        ("S3", S3, "contain"), ("S2", S2, "prevent"), ("R1", R1, "recover"),
    ]  # fmt: skip
    assert record["query"] is None and record["dropped"] == []
    assert set(record["made_with"]) == {"chat_model", "embedding_model", "library", "max_controls", "ai_controls"}


def test_no_more_than_max_controls_are_shown_and_every_kept_pick_stays_recorded(
    picker: Picking, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "max_controls", 1)
    picker.answer(("SC1", "S3", "Zone filter", "contain"), ("SC1", "R1", "Offline backup", "recover"))
    (record,) = picker.pick(_scenario()).values()
    assert _ids(record["items"]) == [BACKUP_OT.control_id]
    assert _ids(record["picks"]) == [FILTER.control_id, BACKUP_OT.control_id]


def test_every_pick_code_refuses_is_dropped_with_its_reason_and_the_others_are_kept(picker: Picking) -> None:
    picker.answer(
        ("SC1", "S9", "Operator authentication", "prevent"),  # no such sentence
        ("SC1", "S2", "C99", "prevent"),  # no such label
        ("SC1", "S2", "Offline backup", "stop"),  # no such effect
        ("SC1", "S1", "Server patching", "prevent"),  # an IT-only control on the OT system's sentence
        ("SC1", "S3", "Zone filter", "contain"),
        ("SC1", "S2", "Zone filter", "detect"),  # the control is picked already
        ("SC1", "R1", "Offline backup", "recover"),
        ("SC1", "R1", "Operator authentication", "prevent"),
        ("SC1", "R1", "Server patching", "contain"),  # a third on one sentence
    )
    with capture_logs() as logs:
        (record,) = picker.pick(_scenario()).values()
    assert [(drop["sentence"], drop["effect"], drop["reason"]) for drop in record["dropped"]] == [
        ("S9", "prevent", ControlPickDrop.NO_SENTENCE),
        ("S2", "prevent", ControlPickDrop.NOT_LISTED),
        ("S2", "stop", ControlPickDrop.BAD_EFFECT),
        ("S1", "prevent", ControlPickDrop.WRONG_TYPE),
        ("S2", "detect", ControlPickDrop.TWICE),
        ("R1", "contain", ControlPickDrop.TOO_MANY.format(most=ControlLinks.PER_SENTENCE)),
    ]
    assert record["dropped"][1]["label"] == "C99"
    assert [(pick["sentence"], pick["name"]) for pick in record["picks"]] == [
        ("S3", "Zone filter"), ("R1", "Offline backup"), ("R1", "Operator authentication"),
    ]  # fmt: skip
    assert len(record["items"]) == 3  # nothing padded in place of the dropped ones
    dropped = [entry for entry in logs if entry["event"] == LogEvent.CONTROLS_PICK_DROPPED]
    assert len(dropped) == 6 and {entry["scenario_id"] for entry in dropped} == {"sc-1"}


@pytest.mark.parametrize("pick", ["C1", None, {"sentence": ["S1"], "label": "C1", "effect": "prevent"}, {}])
def test_a_pick_that_is_no_pick_is_dropped_never_an_error(picker: Picking, pick: Any) -> None:
    picker.chat.queue(AiTask.PICK_CONTROLS, {"scenarios": [{"slot": "SC1", "picks": [pick]}]})
    (record,) = picker.pick(_scenario()).values()
    assert [drop["reason"] for drop in record["dropped"]] == [ControlPickDrop.NO_SENTENCE]
    assert record["items"] == []


def test_a_pick_on_a_sentence_about_a_system_of_the_other_type_takes_the_controls_copy_of_that_type(
    picker: Picking,
) -> None:
    """The shortlist lists the IT copy; S1 tells the OT system, so the pick is stored as the OT copy; on S2,
    which tells the IT system, the listed row is kept."""
    picker.answer(("SC1", "S1", "Operator authentication", "prevent"))
    (record,) = picker.pick(_scenario()).values()
    assert _ids(record["shortlist"])[0] == MFA_IT.control_id
    assert (_ids(record["picks"]), _ids(record["items"])) == ([MFA_OT.control_id], [MFA_OT.control_id])
    assert record["items"][0]["asset_type"] == "OT"
    picker.answer(("SC1", "S2", "Operator authentication", "prevent"))
    (record,) = picker.pick(_scenario()).values()
    assert _ids(record["items"]) == [MFA_IT.control_id]


def test_a_control_outside_the_library_can_never_appear(picker: Picking) -> None:
    """A link to a control the library no longer holds is not offered, and a label the prompt did not give
    (a library id included) resolves to nothing."""
    gone = 123456
    _link("M0932", (gone, 99.0), (MFA_IT.control_id, 90.0))
    picker.answer(
        ("SC1", "S2", str(gone), "prevent"), ("SC1", "S2", str(BACKUP_OT.control_id), "prevent"),
        ("SC1", "S2", "C13", "prevent"), ("SC1", "R1", "Offline backup", "recover"),
    )  # fmt: skip
    (record,) = picker.pick(_scenario()).values()
    in_library = {control.control_id for control in CONTROLS}
    assert gone not in _ids(record["shortlist"]) and set(_ids(record["shortlist"])) <= in_library
    assert _ids(record["items"]) == [BACKUP_OT.control_id]
    assert [drop["reason"] for drop in record["dropped"]] == [ControlPickDrop.NOT_LISTED] * 3


def test_no_database_id_reaches_the_ai_and_each_control_is_cut_to_its_card_text(picker: Picking) -> None:
    long_text = LibraryControl(900800, "LG-1", None, "Ops", "Backup log", "backup " * 100)
    picker.use_library(*CONTROLS, long_text)
    picker.answer()
    picker.pick(_scenario("sc-secret-id"))
    (prompt,) = picker.prompts()
    for control in (*CONTROLS, long_text):
        assert str(control.control_id) not in prompt and control.code not in prompt
    assert "control_id" not in prompt and "sc-secret-id" not in prompt
    assert str(SCADA) not in prompt and str(HISTORIAN) not in prompt
    (asked,) = scenarios_in(prompt)
    assert asked["SENTENCES"] == {"S1": S1, "S2": S2, "S3": S3, "R1": R1}
    assert set(asked) == {"slot", "SENTENCES", "CONTROLS"} and asked["slot"] == "SC1"
    assert all(set(control) == {"label", "name", "description"} for control in asked["CONTROLS"])
    assert [control["label"] for control in asked["CONTROLS"]] == [
        f"C{n}" for n in range(1, len(asked["CONTROLS"]) + 1)
    ]
    cut = next(control for control in asked["CONTROLS"] if control["name"] == "Backup log")
    assert len(cut["description"]) == ControlLinks.CARD_TEXT_CHARS


def test_a_set_costs_one_links_read_one_embedding_call_and_one_chat_call(
    picker: Picking, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each technique's recorded mitigations are on its card: the ATT&CK graph is not read again."""
    reads: list[str] = []

    def counted(owner: type, name: str) -> None:
        method = getattr(owner, name)

        def read(self: Any, *args: Any, **kwargs: Any) -> Any:
            reads.append(name)
            return method(self, *args, **kwargs)

        monkeypatch.setattr(owner, name, read)

    counted(ControlLinkRepository, "find_links")
    for name in ("find_objects", "find_mitigations", "find_uses", "list_mitigations"):
        counted(AttackRepository, name)
    picker.answer(("SC2", "R1", "Offline backup", "recover"))
    embedded = picker.embeddings.calls.count("query")
    scenarios = [_scenario(f"sc-{n}", techniques=("T0859", "T0809")) for n in (1, 2, 3)]
    records = picker.pick(*scenarios)
    assert list(records) == ["sc-1", "sc-2", "sc-3"]
    assert reads == ["find_links"]
    assert picker.embeddings.calls.count("query") - embedded == 1
    assert len(picker.prompts()) == 1 and [item["slot"] for item in scenarios_in(picker.prompts()[0])] == [
        "SC1",
        "SC2",
        "SC3",
    ]
    assert [len(record["items"]) for record in records.values()] == [0, 1, 0]
    assert picker.rerank.asked == []  # the reranker serves the search only


def test_each_technique_states_what_the_picks_gave_it(picker: Picking) -> None:
    """An OT scenario: T0859's linked control is picked or not, T0800 has no mitigation in ATT&CK, T0809's
    mitigation was linked to no control, T0886's is linked to an IT-only control."""
    _link("M0930", (PATCH_IT.control_id, 80.0))
    _link("M0953")  # judged: no library control does it
    card = _scenario(systems=(SCADA,), techniques=("T0859", "T0800", "T0809", "T0886"))
    picker.answer(("SC1", "S1", "Operator authentication", "prevent"))
    (record,) = picker.pick(card).values()
    assert record["technique_states"] == [
        {"id": "T0859", "state": TechniqueControlState.MATCHED},
        {"id": "T0800", "state": TechniqueControlState.NO_KNOWN_DEFENCE},
        {"id": "T0809", "state": TechniqueControlState.NO_LIBRARY_CONTROL},
        {"id": "T0886", "state": TechniqueControlState.TYPE_MISMATCH},
    ]
    picker.answer(("SC1", "R1", "Offline backup", "recover"))
    (record,) = picker.pick(card).values()
    assert record["technique_states"][0] == {"id": "T0859", "state": TechniqueControlState.NOT_PICKED}


def test_an_answer_unusable_after_the_re_ask_has_the_set_mapped_by_the_search(picker: Picking) -> None:
    picker.chat.queue(AiTask.PICK_CONTROLS, {"scenarios": "none"}, {"scenarios": [{"slot": "SC1", "picks": "C1"}]})
    scenarios = [_scenario("sc-1"), _scenario("sc-2", systems=(SCADA,))]
    with capture_logs() as logs:
        records = picker.pick(*scenarios)
    assert len(picker.prompts()) == 2  # asked again once, then no more
    for scenario in scenarios:
        searched = map_controls(picker.rerank, scenario, _OT_CONTEXT, picker.snapshot)  # type: ignore[arg-type]
        assert searched["items"] and isinstance(searched["query"], str)
        assert records[scenario["_id"]] == searched | {"picks": [], "dropped": [], "technique_states": []}
    (unusable,) = [entry for entry in logs if entry["event"] == LogEvent.CONTROLS_PICK_UNUSABLE]
    assert (unusable["count"], unusable["error_type"]) == (2, UnreadableAiAnswer.__name__)


def test_an_answer_cut_off_at_its_limit_has_the_set_mapped_by_the_search(picker: Picking) -> None:
    """Mutation: fall back for an unreadable answer only, and a cut-off one is raised with no record made."""
    picker.chat.queue(AiTask.PICK_CONTROLS, TruncatedAiAnswer("the answer was cut off"))
    scenario = _scenario()
    with capture_logs() as logs:
        records = picker.pick(scenario)
    searched = map_controls(picker.rerank, scenario, _OT_CONTEXT, picker.snapshot)  # type: ignore[arg-type]
    assert searched["items"] and records == {"sc-1": searched | {"picks": [], "dropped": [], "technique_states": []}}
    (unusable,) = [entry for entry in logs if entry["event"] == LogEvent.CONTROLS_PICK_UNUSABLE]
    assert (unusable["count"], unusable["error_type"]) == (1, TruncatedAiAnswer.__name__)


def test_the_scenarios_sent_to_the_search_have_their_queries_embedded_in_one_call(
    picker: Picking, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mutation: leave each search to embed its own query, and a set of 2 pays 2 embedding calls for 1."""
    embedded: list[list[str]] = []
    embed = type(picker.snapshot).embed_control_queries

    def noting(snapshot: Any, queries: list[str]) -> None:
        embedded.append(list(queries))
        embed(snapshot, queries)

    monkeypatch.setattr(type(picker.snapshot), "embed_control_queries", noting)
    picker.chat.queue(AiTask.PICK_CONTROLS, {"scenarios": "none"}, {"scenarios": "none"})
    records = picker.pick(_scenario("sc-1"), _scenario("sc-2", systems=(SCADA,)))
    assert embedded == [[record["query"] for record in records.values()]] and len(embedded[0]) == 2


def test_a_slot_the_answer_leaves_out_is_asked_again_and_only_a_slot_left_out_twice_goes_to_the_search(
    picker: Picking, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mutation: keep only the re-ask's answer, and the slots the first answer held lose their picks to the
    search."""

    def only(slot: str, *picks: tuple[str, str, str, str]) -> Callable[[str], dict[str, Any]]:
        answer = picking(*picks)
        return lambda prompt: {"scenarios": [item for item in answer(prompt)["scenarios"] if item["slot"] == slot]}

    told: list[list[str]] = []  # what each first answer was faulted for: the re-ask's lines
    ask = picker.chat.ask_for_checked_json

    def noting(*asked: Any, first_answer_check: Callable[[dict[str, Any]], list[str]], **options: Any) -> Any:
        check = lambda answer: told.append(first_answer_check(answer)) or told[-1]  # noqa: E731 - notes the lines
        return ask(*asked, first_answer_check=check, **options)

    monkeypatch.setattr(picker.chat, "ask_for_checked_json", noting)
    first = only("SC1", ("SC1", "R1", "Offline backup", "recover"))
    picker.chat.queue(AiTask.PICK_CONTROLS, first, only("SC2", ("SC2", "S3", "Zone filter", "contain")))
    records = picker.pick(_scenario("sc-1"), _scenario("sc-2"))
    assert told == [[f"slot SC2: {AttackMessage.SLOT_MISSING}"]]  # the writer's own line, said one way
    assert len(picker.prompts()) == 2
    assert [record["query"] for record in records.values()] == [None, None]  # both picked, neither searched
    assert _ids(records["sc-1"]["items"]) == [BACKUP_OT.control_id]  # the first answer's pick is kept
    assert _ids(records["sc-2"]["items"]) == [FILTER.control_id]  # the re-ask gave the slot left out
    picker.chat.queue(AiTask.PICK_CONTROLS, first, first)
    records = picker.pick(_scenario("sc-1"), _scenario("sc-2"))
    assert records["sc-1"]["query"] is None and _ids(records["sc-1"]["items"]) == [BACKUP_OT.control_id]
    assert isinstance(records["sc-2"]["query"], str) and records["sc-2"]["items"]  # the search's record


def test_an_ai_outage_is_raised_and_no_scenario_maps_nothing(picker: Picking) -> None:
    picker.chat.queue(AiTask.PICK_CONTROLS, Unavailable(AI_OUTAGE_MESSAGES[AiOutage.DOWN], reason=AiOutage.DOWN))
    with pytest.raises(Unavailable):
        picker.pick(_scenario())
    assert picker.pick() == {} and len(picker.prompts()) == 1  # no scenario: no call


def test_the_api_view_of_a_picked_scenario_is_valid(picker: Picking) -> None:
    picker.answer(("SC1", "R1", "Offline backup", "recover"))
    (record,) = picker.pick(_scenario()).values()
    view = build_scenario_view(_record(controls={"status": Status.DONE, "attempts": 1, **record}))
    shown = view.model_dump(mode="json")
    assert shown["controls"] == [
        {
            "control_id": BACKUP_OT.control_id, "control_code": "BC-1", "itot": "OT", "domain": "BCDR",
            "control_name": "Offline backup", "control_description": "Keep an offline backup copy", "map_rank": 1,
            "score": None, "mapping_relevance": None, "match_type": "EXACT", "match_reason": f"recover: {R1}",
            "tier": "strong",
        }
    ]  # fmt: skip
    assert (shown["control_match_status"], shown["controls_mapped"]) == (ControlMatchStatus.EXACT, True)
    assert not {ReviewFlag.NEAREST_CONTROL, ReviewFlag.CONTROL_LIBRARY_GAP} & set(shown["review_flags"])
    picker.answer()
    (none_picked,) = picker.pick(_scenario()).values()
    view = build_scenario_view(_record(controls={"status": Status.DONE, "attempts": 1, **none_picked}))
    assert (view.controls, view.control_match_status) == ([], ControlMatchStatus.CONTROL_LIBRARY_GAP)
    assert ReviewFlag.CONTROL_LIBRARY_GAP in view.review_flags


def test_a_remediation_plan_finds_alternative_controls_on_a_picked_record(picker: Picking) -> None:
    """The picked record holds no query and no scores, so the plan searches and reranks afresh."""
    picker.answer(("SC1", "R1", "Offline backup", "recover"))
    scenario = _scenario()
    (record,) = picker.pick(scenario).values()
    picker.rerank.scores = {"Zone filter": 60.0, "Offline backup": 80.0, "Operator authentication": 40.0}
    found = find_alternative_controls(
        picker.rerank, scenario, _OT_CONTEXT, picker.snapshot, _ids(record["items"]), 5, record  # type: ignore[arg-type]
    )  # fmt: skip
    assert len(picker.rerank.asked) == 1
    assert [(control.name, score) for control, score in found][:2] == [
        ("Zone filter", 60.0), ("Operator authentication", 40.0),
    ]  # fmt: skip
    assert BACKUP_OT.control_id not in [control.control_id for control, _ in found]


# --- the controls job ---------------------------------------------------------------------------------------


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch, picker: Picking) -> Iterator[dict[str, Any]]:
    """A finished run with no scenario yet; the job's search, reranker, publishes and sent messages are the
    test's own."""
    record_id, now = f"run-{uuid.uuid4().hex}", datetime.now(UTC)
    get_mongodb()[Collection.SESSIONS].insert_one(
        {"_id": record_id, "entity_id": 86, "asset_id": 1, "status": Status.DONE, "step": Step.SCENARIOS,
         "context": _OT_CONTEXT.to_record(), "counts": {}, "updated_at": now, "job": {"request_id": "req-run"}}
    )  # fmt: skip
    state: dict[str, Any] = {"record_id": record_id, "published": [], "sent": [], "written": 0}
    monkeypatch.setattr(controls_job, "get_library_search", lambda: SimpleNamespace(snapshot=lambda: picker.snapshot))
    monkeypatch.setattr(controls_job, "get_rerank_model", lambda: picker.rerank)
    monkeypatch.setattr(controls_job, "publish_session_status", state["published"].append)
    monkeypatch.setattr(controls_job, "send_job", lambda *args: state["sent"].append(args))
    yield state


def _write(run: dict[str, Any], content: dict[str, Any]) -> str:
    """Save a written scenario whose controls wait; its id."""
    run["written"] += 1
    scenario_id, now = f"{run['record_id']}-{run['written']}", datetime.now(UTC)
    get_mongodb()[Collection.SCENARIOS].insert_one(
        {"_id": scenario_id, "session_id": run["record_id"], "path_id": f"p{run['written']}",
         "status": ScenarioStatus.DONE, "superseded_by": None, "decision": "pending", "content": content,
         "created_at": now + timedelta(milliseconds=run["written"]),
         "controls": {"status": Status.QUEUED, "attempts": 0, "queued_at": now}}
    )  # fmt: skip
    return scenario_id


def _stored_controls(scenario_id: str) -> dict[str, Any]:
    return get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id})["controls"]


def _deliver(run: dict[str, Any]) -> int:
    return controls_job.map_threat_scenario_controls(run["record_id"], "task-1")


@pytest.mark.parametrize("rerank_base_url", ["", "http://rerank.test"], ids=["local reranker", "rerank gateway"])
def test_the_job_picks_a_runs_attack_scenarios_as_one_set_and_recounts_and_publishes(
    run: dict[str, Any], picker: Picking, monkeypatch: pytest.MonkeyPatch, rerank_base_url: str
) -> None:
    monkeypatch.setattr(get_settings(), "rerank_base_url", rerank_base_url)
    written = [_write(run, _scenario()["content"] | {"title": f"Scenario {n}"}) for n in (1, 2, 3)]
    assert is_attack_scenario(get_mongodb()[Collection.SCENARIOS].find_one({"_id": written[0]}))
    picker.answer(("SC1", "R1", "Offline backup", "recover"), ("SC3", "S2", "Server patching", "prevent"))
    assert _deliver(run) == 3
    assert len(picker.prompts()) == 1  # one AI call for the set, whatever the reranker takes at once
    stored = [_stored_controls(scenario_id) for scenario_id in written]
    assert [controls["status"] for controls in stored] == [Status.DONE] * 3
    assert [_ids(controls["items"]) for controls in stored] == [[BACKUP_OT.control_id], [], [PATCH_IT.control_id]]
    assert all(controls["query"] is None and "technique_states" in controls for controls in stored)
    counts = get_mongodb()[Collection.SESSIONS].find_one({"_id": run["record_id"]})["counts"]
    assert (counts["controls_waiting"], counts["controls_failed"]) == (0, 0)
    assert run["published"].count(run["record_id"]) >= 3
    assert picker.rerank.asked == []


def test_a_picked_set_pays_no_embedding_call_for_queries_nothing_searches(run: dict[str, Any], picker: Picking) -> None:
    """Mutation: embed the search's query of every claimed scenario, and a picked set makes a second call."""
    for number in (1, 2):
        _write(run, _scenario()["content"] | {"title": f"Scenario {number}"})
    picker.answer(("SC1", "R1", "Offline backup", "recover"))
    embedded = picker.embeddings.calls.count("query")
    assert _deliver(run) == 2
    assert picker.embeddings.calls.count("query") - embedded == 1  # the shortlist's one search of the set


def test_a_sessions_route_scenario_still_goes_through_the_search_untouched(
    run: dict[str, Any], picker: Picking, monkeypatch: pytest.MonkeyPatch
) -> None:
    picked: list[list[dict[str, Any]]] = []

    def spy(rerank: Any, scenarios: list[dict[str, Any]], *rest: Any) -> dict[str, dict[str, Any]]:
        picked.append(scenarios)
        return pick_set_controls(rerank, scenarios, *rest)

    monkeypatch.setattr(controls_job, "pick_set_controls", spy)
    scenario_id = _write(run, _SCENARIO["content"])
    assert not is_attack_scenario(_SCENARIO)
    assert _deliver(run) == 1
    stored = _stored_controls(scenario_id)
    expected = map_controls(_ScoresByText(picker.rerank.scores), _SCENARIO, _OT_CONTEXT, picker.snapshot)  # type: ignore[arg-type]
    assert {key: stored[key] for key in expected} == expected
    assert not {"picks", "dropped", "technique_states"} & set(stored)
    assert picked == [[]] and picker.chat.calls == []  # no scenario went to the picker, no AI was asked


def test_with_an_empty_control_library_the_job_fails_the_scenario_and_asks_no_ai(
    run: dict[str, Any], picker: Picking
) -> None:
    picker.use_library()
    scenario_id = _write(run, _scenario()["content"])
    assert _deliver(run) == 0
    stored = _stored_controls(scenario_id)
    assert (stored["status"], stored["error"]["code"]) == (Status.FAILED, ErrorCode.CONTROL_LIBRARY_EMPTY)
    assert picker.chat.calls == []


def test_an_ai_outage_in_the_pick_queues_the_set_again_for_the_jobs_retry(run: dict[str, Any], picker: Picking) -> None:
    written = [_write(run, _scenario()["content"] | {"title": f"Scenario {n}"}) for n in (1, 2)]
    picker.chat.queue(AiTask.PICK_CONTROLS, Unavailable(AI_OUTAGE_MESSAGES[AiOutage.DOWN], reason=AiOutage.DOWN))
    with pytest.raises(Unavailable):
        _deliver(run)
    stored = [_stored_controls(scenario_id) for scenario_id in written]
    assert [(controls["status"], controls["attempts"]) for controls in stored] == [(Status.QUEUED, 1)] * 2
    assert all(controls["error"]["reason"] == AiOutage.DOWN for controls in stored)
    picker.answer(("SC1", "R1", "Offline backup", "recover"))
    assert _deliver(run) == 2  # the retry picks the set
    assert [_stored_controls(scenario_id)["status"] for scenario_id in written] == [Status.DONE] * 2


def test_a_fault_in_the_picker_is_logged_and_the_search_maps_the_set(
    run: dict[str, Any], picker: Picking, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_: Any) -> dict[str, dict[str, Any]]:
        raise RuntimeError("a bug")

    monkeypatch.setattr(controls_job, "pick_set_controls", broken)
    scenario_id = _write(run, _scenario()["content"])
    with capture_logs() as logs:
        assert _deliver(run) == 1
    stored = _stored_controls(scenario_id)
    assert stored["status"] == Status.DONE and isinstance(stored["query"], str) and stored["items"]
    assert LogEvent.CONTROLS_PICK_UNUSABLE in [entry["event"] for entry in logs]
    assert scenario_crud.get_threat_scenario_repository().count(session_id=run["record_id"], controls_waiting=True) == 0


# --- what the skeptics found ----------------------------------------------------------------------------------


def test_a_pick_the_control_limit_cuts_from_the_items_matches_no_technique(
    picker: Picking, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MAX_CONTROLS 1: the risk sentence's pick is the one item, so the pick linked to T0859 is not shown.
    Mutation: read the states from every kept pick, and T0859 is "matched" by a control the scenario lacks."""
    picks = (("SC1", "S1", "Operator authentication", "prevent"), ("SC1", "R1", "Offline backup", "recover"))
    monkeypatch.setattr(get_settings(), "max_controls", 1)
    picker.answer(*picks)
    (record,) = picker.pick(_scenario()).values()
    assert _ids(record["items"]) == [BACKUP_OT.control_id] and len(record["picks"]) == 2
    assert record["technique_states"] == [{"id": "T0859", "state": TechniqueControlState.NOT_PICKED}]
    monkeypatch.setattr(get_settings(), "max_controls", 2)
    picker.answer(*picks)
    (record,) = picker.pick(_scenario()).values()
    assert record["technique_states"] == [{"id": "T0859", "state": TechniqueControlState.MATCHED}]


def test_a_linked_control_the_ai_domain_rule_keeps_out_is_not_offered_never_a_type_mismatch(picker: Picking) -> None:
    """M0932 is linked only to the AI-domain row, whose type (none) fits every system; the threat is not about AI.
    Mutation: call every linked control that is not offerable a type mismatch, and the state names the wrong rule."""
    _link("M0932", (AI_BACKUP.control_id, 90.0))
    picker.answer()
    (record,) = picker.pick(_scenario()).values()
    assert AI_BACKUP.asset_type is None and AI_BACKUP.control_id not in _ids(record["shortlist"])
    assert record["technique_states"] == [{"id": "T0859", "state": TechniqueControlState.NOT_OFFERED}]


def test_a_re_ask_that_repeats_an_answered_slot_with_no_pick_does_not_erase_its_first_picks(picker: Picking) -> None:
    """The first answer holds SC1 alone, with a pick; the re-ask gives SC2 its pick and repeats SC1 empty.
    Mutation: let the re-ask's answer win for every slot it lists, and SC1 loses its pick."""
    first, again = picking(("SC1", "R1", "Offline backup", "recover")), picking(("SC2", "S3", "Zone filter", "contain"))
    picker.chat.queue(AiTask.PICK_CONTROLS, lambda prompt: {"scenarios": first(prompt)["scenarios"][:1]}, again)
    records = picker.pick(_scenario("sc-1"), _scenario("sc-2"))
    assert len(picker.prompts()) == 2
    assert [_ids(record["items"]) for record in records.values()] == [[BACKUP_OT.control_id], [FILTER.control_id]]


def test_a_pick_call_stopped_by_one_scenarios_lost_lease_leaves_the_others_queued_never_searched(
    run: dict[str, Any], picker: Picking, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The scenario whose thread makes the set's one AI call is taken over by another delivery mid-call. The
    other two are queued again with no attempt used, and the next delivery picks them.
    Mutation: read the lost lease as no outage, and the other two are mapped by the search and stored done."""
    monkeypatch.setattr(get_settings(), "rerank_base_url", "http://rerank.test")
    written = [_write(run, _scenario()["content"] | {"title": f"Scenario {n}"}) for n in (1, 2, 3)]
    leased: dict[int, str] = {}  # the scenario whose lease each thread holds
    keep = controls_job.keep_lease_alive

    def noting(record_id: str, *renewing: Any) -> Any:
        leased[threading.get_ident()] = record_id
        return keep(record_id, *renewing)

    monkeypatch.setattr(controls_job, "keep_lease_alive", noting)
    taken: list[str] = []

    def taken_over(prompt: str) -> dict[str, Any]:
        taken.append(leased[threading.get_ident()])
        get_mongodb()[Collection.SCENARIOS].update_one({"_id": taken[0]}, {"$set": {"controls.task_id": "another"}})
        raise LeaseLost(taken[0])  # as every AI call does once its lease's renewer is refused

    picker.chat.queue(AiTask.PICK_CONTROLS, taken_over)
    with capture_logs() as logs:
        assert _deliver(run) == 0
    others = [scenario_id for scenario_id in written if scenario_id not in taken]
    stored = [_stored_controls(scenario_id) for scenario_id in others]
    assert len(others) == 2 and [(held["status"], held["attempts"]) for held in stored] == [(Status.QUEUED, 0)] * 2
    assert not any("items" in held for held in stored) and picker.rerank.asked == []
    assert LogEvent.CONTROLS_MAPPED not in [entry["event"] for entry in logs]
    assert [task for task, *_ in run["sent"]] == [TaskName.MAP_CONTROLS]  # the two are delivered again
    picker.answer(("SC1", "R1", "Offline backup", "recover"))
    assert _deliver(run) == 2
    assert all(_stored_controls(scenario_id)["query"] is None for scenario_id in others)  # picked, not searched


def test_a_picked_sets_one_ai_call_is_counted_once_in_the_runs_controls_time(
    run: dict[str, Any], picker: Picking, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Four scenarios wait for one pick call of half a second.
    Mutation: add each scenario's own wait, and the run's controls time is four times the call: over the
    delivery's whole wall time."""
    monkeypatch.setattr(get_settings(), "rerank_base_url", "")
    for number in range(4):
        _write(run, _scenario()["content"] | {"title": f"Scenario {number}"})
    answer = picking()

    def slow(prompt: str) -> dict[str, Any]:
        time.sleep(0.5)
        return answer(prompt)

    picker.chat.queue(AiTask.PICK_CONTROLS, slow)
    started = time.perf_counter()
    assert _deliver(run) == 4
    wall = time.perf_counter() - started
    timings = get_mongodb()[Collection.SESSIONS].find_one({"_id": run["record_id"]})["timings"]
    assert 0.45 <= timings["controls_s"] <= wall + 0.05


def _map_for_a_plan(picker: Picking, scenario_id: str) -> dict[str, Any]:
    """The plan job's own step that gets a plan its scenario's controls."""
    scenario = scenario_crud.get_threat_scenario_repository().get(fields=PLANNED_SCENARIO_FIELDS, _id=scenario_id)
    by_id = {row.control_id: row for row in picker.snapshot.library.control_library}
    lease = SimpleNamespace(task_id="plan-task-1")
    return plan_job._mapped_controls(lease, scenario, _OT_CONTEXT, picker.snapshot, by_id, picker.rerank)  # type: ignore[arg-type]


def test_a_plan_asked_for_while_the_controls_wait_picks_them_as_the_controls_job_does(
    run: dict[str, Any], picker: Picking, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An accepted scenario's plan may be asked for while its controls are still queued.
    Mutation: let the plan job map every scenario by the search, and this one never gets its per-sentence
    picks: the controls job then finds nothing waiting."""
    monkeypatch.setattr(plan_job, "publish_session_status", lambda *_: None)
    scenario_id = _write(run, _scenario()["content"])
    picker.answer(("SC1", "S1", "Operator authentication", "prevent"))
    mapped = _map_for_a_plan(picker, scenario_id)
    stored = _stored_controls(scenario_id)
    assert _ids(mapped["items"]) == _ids(stored["items"]) == [MFA_OT.control_id]
    assert (stored["status"], stored["query"], len(stored["picks"])) == (Status.DONE, None, 1)
    assert stored["technique_states"] == [{"id": "T0859", "state": TechniqueControlState.MATCHED}]
    assert len(picker.prompts()) == 1 and picker.rerank.asked == []
    assert _deliver(run) == 0  # nothing is left for the controls job


def test_a_plan_on_a_scenario_the_ai_picked_no_control_for_is_never_padded_by_the_search(
    run: dict[str, Any], picker: Picking, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mutation: let the plan job map it by the search, and the scenario that showed "no control" gains the
    search's controls beside the pick's technique states."""
    monkeypatch.setattr(plan_job, "publish_session_status", lambda *_: None)
    _link("M0953")
    scenario_id = _write(run, _scenario(techniques=("T0809",), mitigations=())["content"])
    picker.answer()
    assert _deliver(run) == 1 and _stored_controls(scenario_id)["items"] == []
    picker.answer()
    mapped = _map_for_a_plan(picker, scenario_id)
    stored = _stored_controls(scenario_id)
    assert mapped["items"] == stored["items"] == [] and (stored["status"], stored["query"]) == (Status.DONE, None)
    assert stored["technique_states"] == [{"id": "T0809", "state": TechniqueControlState.NO_LIBRARY_CONTROL}]
    assert len(picker.prompts()) == 2 and picker.rerank.asked == []  # picked again, never searched


def test_a_plan_on_an_attack_scenario_with_an_empty_control_library_fails_as_any_plan_does(
    run: dict[str, Any], picker: Picking, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(plan_job, "publish_session_status", lambda *_: None)
    scenario_id = _write(run, _scenario()["content"])
    picker.use_library()
    with pytest.raises(JobFailed) as failed:
        _map_for_a_plan(picker, scenario_id)
    assert failed.value.code == ErrorCode.CONTROL_LIBRARY_EMPTY and picker.chat.calls == []
    assert _stored_controls(scenario_id)["status"] == Status.FAILED


# --- a MITRE plan's candidates (owner 2026-11-27) ----------------------------------------------------------


def _mitre_card(steps: dict[str, list[str]], targeted: dict[str, str] | None = None, **fields: Any) -> dict[str, Any]:
    """A MITRE card as its plan reads it, on the SCADA server (OT) and the Historian (IT): each step's technique
    with its MITRE mitigations and MITRE's words on each, and the system a step targets when given."""
    card = _scenario(techniques=(), mitigations=())
    content = card["content"]
    content["attack"]["techniques"] = [
        {"id": technique, "name": f"Step {technique}", "source": ICS, "mitigations": mitigations}
        for technique, mitigations in steps.items()
    ]
    said = [
        {"technique": technique, "mitigations": [{"mitre_id": m, "name": f"Mitigation {m}", "text": f"MITRE: {m}"}]}
        for technique, mitigations in steps.items()
        for m in mitigations
    ]
    targets = [{"technique": technique, "supporting_system": system} for technique, system in (targeted or {}).items()]
    content["mitre"] = {"mitigations": said, "systems_targeted": targets}
    return card | fields


class _PlanSearch:
    """The snapshot surface gather_plan_candidates reads: the library, and one search answering each step's
    query (it opens with the step's name) with that step's rows."""

    def __init__(self, controls: tuple[LibraryControl, ...], nearest: dict[str, list[LibraryControl]] | None = None):
        self.library = SimpleNamespace(control_library=controls)
        self.nearest = nearest or {}
        self.searched: list[tuple[list[str], int]] = []
        self.down = False  # True: the search's embedding call is down

    def find_controls(self, queries: list[str], top_k: int) -> list[list[tuple[LibraryControl, float]]]:
        if self.down:
            raise Unavailable(AI_OUTAGE_MESSAGES[AiOutage.UNREACHABLE], reason=AiOutage.UNREACHABLE)
        self.searched.append((list(queries), top_k))
        steps = [query.split(":")[0].removeprefix("Step ") for query in queries]
        return [[(row, 0.9) for row in self.nearest.get(step, [])] for step in steps]


def _gather(card: dict[str, Any], search: _PlanSearch) -> list[dict[str, Any]]:
    return attack_controls.gather_plan_candidates(card, _OT_CONTEXT, search)  # type: ignore[arg-type]


def _offered_for(rows: list[dict[str, Any]]) -> list[tuple[str, list[tuple[str, str]]]]:
    return [(row["code"], [(entry["technique"], entry["found_by"]) for entry in row["offered_for"]]) for row in rows]


def _many(first: int, count: int) -> list[LibraryControl]:
    return [
        LibraryControl(n, f"X-{n}", None, "Network", f"Control {n}", f"Does {n}") for n in range(first, first + count)
    ]


def _per_step(rows: list[dict[str, Any]]) -> dict[str, tuple[int, int]]:
    """Each step's candidates: (linked to its MITRE mitigations, by meaning)."""
    found = Counter(
        (entry["technique"], entry["found_by"] == ControlLinks.FOUND_BY_MEANING)
        for row in rows
        for entry in row["offered_for"]
    )
    return {technique: (found[(technique, False)], found[(technique, True)]) for technique, _ in found}


def _card_of(sizes: list[tuple[int, int]]) -> tuple[dict[str, Any], _PlanSearch]:
    """A card of one step per (linked, by meaning) size, each step's own controls, and its search."""
    library: list[LibraryControl] = []
    nearest, steps = {}, {}
    for number, (linked_count, meaning_count) in enumerate(sizes, 1):
        technique, mitigation = f"T{2000 + number}", f"M{2000 + number}"
        linked, meaning = _many(10_000 * number, linked_count), _many(10_000 * number + 5_000, meaning_count)
        _link(mitigation, *((row.control_id, 90.0 - place) for place, row in enumerate(linked)))
        library += linked + meaning
        nearest[technique], steps[technique] = meaning, [mitigation]
    return _mitre_card(steps), _PlanSearch(tuple(library), nearest)


@pytest.mark.parametrize(("steps", "each"), [(3, 20), (6, 10)])
def test_a_mitre_plans_candidates_share_the_limit_fairly_between_its_steps_and_both_kinds(
    steps: int, each: int
) -> None:
    """PLAN_CANDIDATES_LIMIT (120): each step's share is the limit over its steps, half linked to its MITRE
    mitigations (best link first), half by meaning, at most 20 of each. Mutation: give each step the whole limit
    and a 6-step card's last three steps get none."""
    card, search = _card_of([(30, 30)] * steps)
    rows = _gather(card, search)
    assert len(rows) == get_settings().plan_candidates_limit == 120
    assert _per_step(rows) == {f"T{2000 + number}": (each, each) for number in range(1, steps + 1)}
    assert rows[0] == {
        "control_id": 10_000, "code": "X-10000", "score": None, "match": "alternative",
        "offered_for": [{"technique": "T2001", "found_by": "M2001"}],
    }  # fmt: skip


def test_slots_one_kind_leaves_go_to_the_other_kind_then_a_slot_each_in_turn_to_the_other_steps() -> None:
    """Six steps, a share of 20 each: the first has 5 by meaning only, the second 3 linked, so its meaning takes
    17; the 15 slots the first left go to the others in turn, linked first. Mutation: drop the turns and the card
    stops at 105."""
    card, search = _card_of([(0, 5), (3, 30), (30, 30), (30, 30), (30, 30), (30, 30)])
    rows = _gather(card, search)
    assert len(rows) == 120
    assert _per_step(rows) == {"T2001": (0, 5), "T2002": (3, 20)} | {f"T200{n}": (13, 10) for n in range(3, 7)}


def test_a_row_another_step_took_names_this_step_too_once_the_limit_is_reached() -> None:
    """Six steps fill the 120 slots; the last step's 16th row by meaning is the first step's first linked row,
    past its share: that row still names both steps. Mutation: stop merging at the limit and it names T2001
    only."""
    card, search = _card_of([(30, 30)] * 6)
    first_linked = search.library.control_library[0]
    search.nearest["T2006"].insert(15, first_linked)
    rows = _gather(card, search)
    assert len(rows) == 120 and rows[0]["control_id"] == first_linked.control_id
    assert rows[0]["offered_for"] == [
        {"technique": "T2001", "found_by": "M2001"}, {"technique": "T2006", "found_by": "meaning"},
    ]  # fmt: skip


def test_gathering_logs_each_kinds_count_the_rows_offered_and_the_steps_without_a_candidate() -> None:
    """Seven steps, the last finding nothing: 20 + 20 found on each of the six, 120 offered. Mutation: log no step
    without, or no offered count, and it fails."""
    card, search = _card_of([(30, 30)] * 6 + [(0, 0)])
    with capture_logs() as logs:
        _gather(card, search)
    (event,) = [entry for entry in logs if entry["event"] == LogEvent.PLAN_CANDIDATES_GATHERED]
    assert (event["linked"], event["meaning"], event["offered"]) == (120, 120, 120)
    assert event["steps_without"] == ["T2007"]


def test_a_steps_candidates_fit_the_it_ot_type_of_the_system_it_targets_and_ai_rows_only_for_an_ai_threat() -> None:
    """T0859 targets the SCADA server (OT): its link to the IT authentication control offers the OT copy, and by
    meaning the IT patching and the AI-domain backup are never offered. Mutation: drop the step's fit from the
    meaning rows and Server patching is offered."""
    card = _mitre_card({"T0859": ["M0932"]}, targeted={"T0859": "SCADA server"})
    rows = _gather(card, _PlanSearch(CONTROLS, {"T0859": [PATCH_IT, AI_BACKUP, FILTER, BACKUP_OT]}))
    assert _offered_for(rows) == [
        ("AC-7", [("T0859", "M0932")]), ("NW-3", [("T0859", "meaning")]), ("BC-1", [("T0859", "meaning")]),
    ]  # fmt: skip
    assert rows[0]["control_id"] == MFA_OT.control_id


def test_a_candidate_is_one_row_naming_each_step_never_a_twin_twice_nor_a_control_the_card_has() -> None:
    """Within a step a control's IT/OT copy is offered once; a control two steps find is one row naming both,
    taking one slot; a control the card's own done controls hold is never offered. Mutation: leave out the
    card's own controls and Zone filter is offered."""
    _link("M0953", (BACKUP_OT.control_id, 80.0))
    done = {"status": Status.DONE, "items": [{"control_id": FILTER.control_id}]}
    card = _mitre_card({"T0859": ["M0932"], "T0809": ["M0953"]}, targeted={"T0859": "SCADA server"}, controls=done)
    nearest = {"T0859": [MFA_IT, MFA_OT, FILTER, BACKUP_OT], "T0809": [FILTER]}
    assert _offered_for(_gather(card, _PlanSearch(CONTROLS, nearest))) == [
        ("AC-7", [("T0859", "M0932")]),
        ("BC-1", [("T0859", "meaning"), ("T0809", "M0953")]),
    ]


def test_each_steps_meaning_query_is_its_name_mitres_opening_words_and_the_systems_it_acts_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One search for the card over the whole library: each step's query names it, opens MITRE's description of
    it (WRITER_TECHNIQUE_DESCRIPTION_CHARACTERS) and names the card's systems it acts on, every system when MITRE
    targets none. Mutation: leave the systems out and the SCADA server is never searched."""
    described = [{"attack_id": "T0859", "description": "Adversaries may log in with valid accounts. " + "x" * 500}]
    found = SimpleNamespace(find_objects=lambda ids, keys: described)
    monkeypatch.setattr(attack_controls, "get_attack_repository", lambda: found)
    card = _mitre_card({"T0859": ["M0932"], "T0809": []}, targeted={"T0859": "SCADA server"})
    search = _PlanSearch(CONTROLS)
    _gather(card, search)
    assert search.searched == [
        (
            [
                "Step T0859: Adversaries may log in with valid accounts. Systems: SCADA server",
                "Step T0809: Systems: SCADA server, Historian",
            ],
            len(CONTROLS),
        )
    ]


def test_an_empty_library_gives_no_candidate_and_no_search_and_no_links_give_candidates_by_meaning() -> None:
    """Mutation: search an empty library and its search is called."""
    card = _mitre_card({"T0859": ["M0932"]})
    empty = _PlanSearch(())
    assert _gather(card, empty) == [] and empty.searched == []
    get_mongodb()[Collection.CONTROL_LINKS].delete_many({})
    assert _offered_for(_gather(card, _PlanSearch(CONTROLS, {"T0859": [FILTER]}))) == [("NW-3", [("T0859", "meaning")])]


def test_an_embedding_outage_while_gathering_is_raised_for_the_plan_job_to_retry() -> None:
    """Mutation: answer an outage with no candidate and the plan is written without them."""
    search = _PlanSearch(CONTROLS)
    search.down = True
    with pytest.raises(Unavailable):
        _gather(_mitre_card({"T0859": ["M0932"]}), search)


def _plan_controls_for(picker: Picking, scenario_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    """The plan job's own step that gives a plan its identified and offered controls."""
    scenario = scenario_crud.get_threat_scenario_repository().get(fields=PLANNED_SCENARIO_FIELDS, _id=scenario_id)
    lease = SimpleNamespace(task_id="plan-task-1")
    return plan_job._plan_controls(lease, scenario, _OT_CONTEXT, picker.snapshot, picker.rerank)  # type: ignore[arg-type]


def test_a_mitre_plan_never_claims_its_cards_controls_and_offers_its_candidates(
    run: dict[str, Any], picker: Picking, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Owner 2026-11-27: a MITRE card's plan reads its own done controls (an older card's) or none, and never
    claims or maps queued ones. Mutation: branch on is_attack_scenario and the queued card's controls are
    claimed and picked."""
    monkeypatch.setattr(plan_job, "publish_session_status", lambda *_: None)
    queued = _write(run, _mitre_card({"T0859": ["M0932"]}, targeted={"T0859": "SCADA server"})["content"])
    items, offered, most = _plan_controls_for(picker, queued)
    assert (items, most, picker.chat.calls) == ([], get_settings().plan_candidates_limit, [])
    assert _stored_controls(queued)["status"] == Status.QUEUED
    assert offered[0]["control_id"] == MFA_OT.control_id
    older = _write(run, _mitre_card({"T0859": ["M0932"]})["content"])
    item = {"control_id": FILTER.control_id, "code": "NW-3", "score": None, "match": ControlMatch.EXACT}
    get_mongodb()[Collection.SCENARIOS].update_one(
        {"_id": older}, {"$set": {"controls": {"status": Status.DONE, "attempts": 1, "items": [item]}}}
    )
    items, offered, _ = _plan_controls_for(picker, older)
    assert items == [item] and FILTER.control_id not in _ids(offered)


def test_a_create_session_cards_plan_still_claims_and_maps_its_controls_and_is_offered_20_alternatives(
    run: dict[str, Any], picker: Picking, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A POST /v1/create_session card is an ATT&CK card but no MITRE one: its plan maps its controls as before.
    Mutation: branch on is_attack_scenario and its controls are never mapped."""
    monkeypatch.setattr(plan_job, "publish_session_status", lambda *_: None)
    asked: list[int] = []
    monkeypatch.setattr(plan_job, "find_alternative_controls", lambda *args: asked.append(args[5]) or [(FILTER, 60.0)])
    scenario_id = _write(run, _scenario()["content"])
    picker.answer(("SC1", "S1", "Operator authentication", "prevent"))
    items, offered, most = _plan_controls_for(picker, scenario_id)
    assert _ids(items) == [MFA_OT.control_id] and _stored_controls(scenario_id)["status"] == Status.DONE
    assert asked == [most] == [get_settings().remediation_alternative_controls] == [20]
    assert offered == [{"control_id": FILTER.control_id, "code": "NW-3", "score": 60.0, "match": "alternative"}]


def test_a_mitre_plans_prompt_names_each_candidates_step_and_mitigation_with_mitres_words(
    run: dict[str, Any], picker: Picking, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The plan reads each step once (its ATT&CK ID, name and mitigations by ID with MITRE's words) and each
    candidate with the steps it is offered for (T... and M... IDs, or "meaning"), its description cut to
    PLAN_CANDIDATE_DESCRIPTION_CHARACTERS; an alternative's constant match and a candidate's empty score are left
    out. Mutation: skip the MITRE grounding and the prompt has no attack_steps."""
    monkeypatch.setattr(plan_job, "publish_session_status", lambda *_: None)
    wordy = LibraryControl(900777, "NW-9", None, "Network", "Zone filter plus", "Filter " + "traffic " * 100)
    picker.use_library(*CONTROLS, wordy)
    _link("M0932", (MFA_IT.control_id, 90.0), (wordy.control_id, 50.0))
    scenario_id = _write(run, _mitre_card({"T0859": ["M0932"]}, targeted={"T0859": "SCADA server"})["content"])
    scenario = scenario_crud.get_threat_scenario_repository().get(fields=PLANNED_SCENARIO_FIELDS, _id=scenario_id)
    _, offered, _ = _plan_controls_for(picker, scenario_id)
    register = {
        "supporting_systems_applicable_to_risk": [SCADA],
        "supporting_systems_applicable_to_existing_controls": [],
    }
    affected, library = list_affected_systems(_OT_CONTEXT, register), picker.snapshot.library.control_library
    alternatives = assess_controls(offered, register, library, affected, _OT_CONTEXT.system_categories())[0]
    snapshot = build_snapshot(scenario, _OT_CONTEXT, register, [], [], affected, alternatives)
    plan_job._add_mitre_grounding(snapshot, scenario)
    shown = json.loads(plan_prompt(snapshot)[1].split("CONTEXT:\n", 1)[1])
    assert shown["attack_steps"] == [
        {
            "technique": "T0859", "name": "Step T0859",
            "mitigations": [{"mitigation": "M0932", "name": "Mitigation M0932", "mitre_says": "MITRE: M0932"}],
        }
    ]  # fmt: skip
    first, second = shown["existing_controls"]["library_alternatives"][:2]
    assert first["offered_for"] == second["offered_for"] == [{"technique": "T0859", "found_by": "M0932"}]
    assert not {"match", "mapping_relevance", "control_id"} & set(first)
    limit = get_settings().plan_candidate_description_characters
    assert second["control_code"] == "NW-9" and len(second["control_description"]) == limit + len(
        Remediation.TRUNCATED_MARK
    )


def test_a_mitre_plans_attack_steps_cut_mitres_words_and_leave_them_out_on_an_older_card() -> None:
    """MITRE's words are cut at Remediation.TEXT_MAX_CHARS like every snapshot text; a card stored before
    2026-11-24 has none and sends no mitre_says. Mutation: send them as describe_attack_steps gives them and the
    long words reach the prompt whole; keep an empty one and the older card sends "mitre_says": ""."""
    card = _mitre_card({"T0859": ["M0932"]})
    card["content"]["mitre"]["mitigations"][0]["mitigations"][0]["text"] = "w" * (Remediation.TEXT_MAX_CHARS + 50)
    snapshot: dict[str, Any] = {"existing_controls": {"library_alternatives": []}}
    plan_job._add_mitre_grounding(snapshot, card)
    (said,) = snapshot["attack_steps"][0]["mitigations"]
    assert said["mitre_says"] == "w" * Remediation.TEXT_MAX_CHARS + Remediation.TRUNCATED_MARK
    card["content"]["mitre"]["mitigations"] = []
    plan_job._add_mitre_grounding(snapshot, card)
    assert "mitre_says" not in snapshot["attack_steps"][0]["mitigations"][0]


# --- MITRE generation picks no controls (owner 2026-11-27) ------------------------------------------------------


def test_a_mitre_card_an_older_pod_queued_is_never_claimed_nor_requeued(run: dict[str, Any], picker: Picking) -> None:
    """During a rolling deploy an older pod may still save a MITRE card with its controls queued: the new image never
    maps it, by the run's controls job, a plan's claim or the sweep. Mutation: drop NOT_MITRE from
    _controls_waiting and the job maps it; from claim_scenario_controls_by_id and the plan claims it; from
    requeue_stalled_controls and the sweep queues it again."""
    scenario_id = _write(run, _mitre_card({"T0859": ["M0932"]}, targeted={"T0859": "SCADA server"})["content"])
    scenarios = scenario_crud.get_threat_scenario_repository()
    assert scenarios.claim_scenario_controls(run["record_id"], "task-1") is None
    assert scenarios.claim_scenario_controls_by_id(scenario_id, "task-1:plan", remap=True) is None
    assert _deliver(run) == 0 and picker.chat.calls == []
    long_ago = datetime.now(UTC) - timedelta(days=1)
    get_mongodb()[Collection.SCENARIOS].update_one({"_id": scenario_id}, {"$set": {"controls.queued_at": long_ago}})
    assert run["record_id"] not in scenarios.requeue_stalled_controls(datetime.now(UTC))
    stored = _stored_controls(scenario_id)
    assert stored["status"] == Status.QUEUED and stored["queued_at"] < datetime.now(UTC) - timedelta(hours=1)


@pytest.fixture
def cleanup_store(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Any]]:
    """The clean-up's tsg_scenarios, tsg_sessions and tsg_audit as this test's own collections: it reads every
    MITRE card, so a parallel test's cards stay out of it."""
    database, tag = get_mongodb(), uuid.uuid4().hex[:8]
    names = {name: f"test_cleanup_{name}_{tag}" for name in ("scenarios", "sessions", "audit")}
    scenarios = scenario_crud.ThreatScenarioRepository(database[names["scenarios"]])
    runs = scenario_crud.ThreatScenarioSessionRepository(database[names["sessions"]], scenarios=scenarios)
    monkeypatch.setattr(work_control, "get_threat_scenario_repository", lambda: scenarios)
    monkeypatch.setattr(work_control, "get_threat_scenario_session_repository", lambda: runs)
    monkeypatch.setattr(work_control, "get_audit_repository", lambda: AuditRepository(database[names["audit"]]))
    yield {name: database[collection] for name, collection in names.items()} | {"runs": runs}
    for collection in names.values():
        database.drop_collection(collection)


def _mitre_cards_left(store: dict[str, Any], controls: dict[str, dict[str, Any] | None], session: str) -> None:
    content = _mitre_card({"T0859": ["M0932"]})["content"]
    for name, record in controls.items():
        card = {"_id": name, "session_id": session, "status": ScenarioStatus.DONE, "superseded_by": None}
        card |= {"decision": "pending", "content": content} | ({"controls": record} if record else {})
        store["scenarios"].insert_one(card)


def _controls_left(store: dict[str, Any]) -> dict[str, Any]:
    return {card["_id"]: (card.get("controls") or {}).get("status") for card in store["scenarios"].find()}


def test_the_clean_up_clears_mitre_cards_waiting_controls_once_and_recounts_their_runs(
    cleanup_store: dict[str, Any],
) -> None:
    """Owner 2026-11-27: once (a marker in tsg_audit), the controls an older image left waiting on MITRE cards
    (queued, cancelled, failed, running with an expired lease) are removed and the run recounted; a card with no
    record (a new one), done controls, a live lease and a POST /v1/create_session card are left alone; its counts
    are logged. Mutation: match `controls.status $ne done` and the new card is matched too; skip the marker and a
    card queued later is cleared at the next start."""
    store, now = cleanup_store, datetime.now(UTC)
    store["sessions"].insert_many(
        [{"_id": "mitre-run", "entity_id": 86, "pipeline": "mitre"}, {"_id": "other-run", "entity_id": 86}]
    )
    queued = {"status": Status.QUEUED, "attempts": 0, "queued_at": now}
    _mitre_cards_left(
        store,
        {
            "queued": queued,
            "cancelled": {"status": Status.CANCELLED, "attempts": 1},
            "failed": {"status": Status.FAILED, "attempts": Controls.MAX_ATTEMPTS},
            "expired": {"status": Status.RUNNING, "attempts": 1, "lease_until": now - timedelta(minutes=1)},
            "live": {"status": Status.RUNNING, "attempts": 1, "lease_until": now + timedelta(minutes=5)},
            "done": {"status": Status.DONE, "attempts": 1, "items": []},
            "new": None,
        },
        "mitre-run",
    )
    plain = {"_id": "plain", "session_id": "other-run", "status": ScenarioStatus.DONE, "superseded_by": None}
    plain |= {"decision": "pending", "content": _scenario()["content"], "controls": queued}
    store["scenarios"].insert_one(plain)
    assert store["runs"].update_scenario_session_counts("mitre-run")["controls_waiting"] == 3
    with capture_logs() as logs:
        work_control.clear_mitre_controls_once()
    assert _controls_left(store) == {
        **dict.fromkeys(("queued", "cancelled", "failed", "expired", "new"), None),
        "live": Status.RUNNING,
        "done": Status.DONE,
        "plain": Status.QUEUED,
    }
    marker = store["audit"].find_one({"_id": work_control.MITRE_CONTROLS_CLEARED_MARKER})
    assert (marker["matched"], marker["modified"], marker["recounted"]) == (4, 4, 1)
    (logged,) = [entry for entry in logs if entry["event"] == LogEvent.CONTROLS_MITRE_CLEARED]
    assert (logged["matched"], logged["modified"], logged["recounted"]) == (4, 4, 1)
    counts = store["sessions"].find_one({"_id": "mitre-run"})["counts"]
    assert (counts["controls_waiting"], counts["controls_failed"], counts["controls_cancelled"]) == (1, 0, 0)
    _mitre_cards_left(store, {"late": queued}, "mitre-run")  # saved by an older pod after the clean-up ran
    work_control.clear_mitre_controls_once()
    assert _controls_left(store)["late"] == Status.QUEUED


def test_the_clean_up_redone_after_a_crash_recounts_and_a_failure_never_stops_start_up(
    cleanup_store: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A start that died after clearing, before its recount and marker: the next start clears nothing more, yet
    recounts each MITRE run still counting waiting, failed or cancelled controls. A failure is logged, writes no
    marker and never raises. Mutation: recount only the runs of the cards cleared and the stale count stays."""
    store = cleanup_store
    stale = {"controls_waiting": 0, "controls_failed": 2, "controls_cancelled": 0}
    store["sessions"].insert_many(
        [
            {"_id": "mitre-run", "entity_id": 86, "pipeline": "mitre", "counts": stale},
            {"_id": "other-run", "entity_id": 86, "counts": stale},  # not a MITRE run: never recounted
        ]
    )
    _mitre_cards_left(store, {"cleared": None}, "mitre-run")
    assert work_control.clear_mitre_waiting_controls() == {"matched": 0, "modified": 0, "recounted": 1}
    assert store["sessions"].find_one({"_id": "mitre-run"})["counts"]["controls_failed"] == 0
    assert store["sessions"].find_one({"_id": "other-run"})["counts"] == stale

    def broken(*_: Any) -> dict[str, int]:
        raise Unavailable("MongoDB is down")

    monkeypatch.setattr(work_control, "clear_mitre_waiting_controls", broken)
    with capture_logs() as logs:
        work_control.clear_mitre_controls_once()  # no exception
    assert [entry["event"] for entry in logs] == [LogEvent.CONTROLS_MITRE_CLEAR_FAILED]
    assert store["audit"].find_one({"_id": work_control.MITRE_CONTROLS_CLEARED_MARKER}) is None


def test_the_sweep_clears_mitre_controls_an_older_pod_left_after_the_clean_up_so_the_run_settles(
    cleanup_store: dict[str, Any],
) -> None:
    """Owner 2026-11-27: controls an older pod saves on a MITRE card after the one-time clean-up (a rolling deploy,
    a killed pod's expired lease, a rollback and roll forward) are removed by the next sweep and the run
    recounted, so it never shows controls waiting forever nor refuses its delete; a live lease and done controls
    stay, and a POST /v1/create_session card is still queued for its send. Mutation: drop the sweep's clearing
    and the run keeps counting 3 waiting."""
    store, now = cleanup_store, datetime.now(UTC)
    store["sessions"].insert_many(
        [{"_id": "mitre-run", "entity_id": 86, "pipeline": "mitre"}, {"_id": "other-run", "entity_id": 86}]
    )
    store["audit"].insert_one({"_id": work_control.MITRE_CONTROLS_CLEARED_MARKER})  # the clean-up already ran
    long_ago = now - timedelta(days=1)
    _mitre_cards_left(
        store,
        {
            "late": {"status": Status.QUEUED, "attempts": 0, "queued_at": now},
            "expired": {"status": Status.RUNNING, "attempts": 1, "lease_until": now - timedelta(minutes=1)},
            "live": {"status": Status.RUNNING, "attempts": 1, "lease_until": now + timedelta(minutes=5)},
            "done": {"status": Status.DONE, "attempts": 1, "items": []},
        },
        "mitre-run",
    )
    plain = {"_id": "plain", "session_id": "other-run", "status": ScenarioStatus.DONE, "superseded_by": None}
    plain |= {"decision": "pending", "content": _scenario()["content"]}
    plain |= {"controls": {"status": Status.QUEUED, "attempts": 0, "queued_at": long_ago}}
    store["scenarios"].insert_one(plain)
    assert store["runs"].update_scenario_session_counts("mitre-run")["controls_waiting"] == 3
    assert work_control.sweep_stalled_controls() == ["other-run"]  # a MITRE run is never sent to be mapped
    assert _controls_left(store) == {
        "late": None,
        "expired": None,
        "live": Status.RUNNING,
        "done": Status.DONE,
        "plain": Status.QUEUED,
    }
    assert store["sessions"].find_one({"_id": "mitre-run"})["counts"]["controls_waiting"] == 1  # the live lease
