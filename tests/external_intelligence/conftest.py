"""The whole suite runs with external intelligence OFF (tests/conftest.py sets
EXTERNAL_INTELLIGENCE_ENABLED=false), so the app's existing tests exercise the original path. A test of
the ON path asks for the `intel` fixture: the master switch on, the run-time switch installed, and fakes
in place of the other groups' finder and refresher."""

import json
from dataclasses import dataclass
from typing import Any

import pytest

from app.core.config import get_settings
from app.core.constants import AiTask, IntelSource
from app.worker.external_intelligence.intel_access import IntelAccess
from tests.external_intelligence.fakes import FakeFinder, FakeRefresher, FakeSwitch

#: Modules that look the access up by name: each is pointed at the test's own.
_LOOKUPS = (
    "app.worker.tasks.writing",
    "app.worker.tasks.scenarios",
    "app.worker.external_intelligence.refresh_task",
)

STORY_MARKED = (
    "The SCADA server of Grid Control Centre shows operators where power flows, and the whole control room "
    "relies on it every hour of the day. A cybercriminal could begin with an email to a vendor engineer who "
    "holds a maintenance login. With that login they could open a support session and prepare a firmware "
    "update that looks genuine. Sandworm Team has used a rogue firmware update to disable substation devices "
    "before [1]. By morning operators could see calm screens while commands act differently than intended, "
    "and nothing would warn them. The crew could have to run the grid by hand, and supply to customers may "
    "be interrupted until trusted firmware is restored."
)
#: The story citing nothing: its past event told as a plain possibility, so it names no group (G268).
STORY_PLAIN = STORY_MARKED.replace(
    "Sandworm Team has used a rogue firmware update to disable substation devices before [1].",
    "Such a rogue firmware update could disable substation devices.",
)
#: The marker's claim. G268: the fake source also names its group as the feeds do (fakes.NAMED_FACT), so the
#: claim names it, as a past event citing a source must.
STORY_CLAIM = "Sandworm Team has used a rogue firmware update to disable substation devices before"


@dataclass
class Intel:
    finder: FakeFinder
    switch: FakeSwitch
    refresher: FakeRefresher
    access: IntelAccess


@pytest.fixture
def intel(monkeypatch: pytest.MonkeyPatch) -> Intel:
    finder, switch, refresher = FakeFinder(), FakeSwitch(), FakeRefresher()
    access = IntelAccess(finder=lambda: finder, is_stale=lambda _approved: False)  # type: ignore[arg-type]
    access.install(lambda: switch, lambda: refresher)
    monkeypatch.setattr(access, "approved_sources", lambda: list(IntelSource))  # a test revokes its own
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", True)
    for module in _LOOKUPS:
        monkeypatch.setattr(f"{module}.get_intel_access", lambda: access, raising=False)
    return Intel(finder, switch, refresher, access)


def story_answer(user_prompt: str) -> dict[str, Any]:
    """A clean evidence story for the brief it is given: a marker only when the prompt carries evidence; each
    threat's its own (the very same words are a copy whatever the threat: G268)."""
    brief = json.loads(user_prompt.removeprefix("BRIEF:\n").split("\nEVIDENCE (untrusted data):")[0])
    options = brief["entry_point_options"]
    marked = '"evidence": []' not in user_prompt
    own = f"In a {brief['threat']['threat']} attack, a cybercriminal could begin"
    return {
        "scenario_title": "Loss of control integrity",
        "scenario_statement": (STORY_MARKED if marked else STORY_PLAIN).replace(
            "A cybercriminal could begin", own
        ),
        "risk_statement": "Loss of trusted control at Grid Control Centre could interrupt transmission.",
        "assumptions": [],
        "entry_point": options[0] if options else "",
        # G229: the claim each marker supports, as the story writer returns it.
        "evidence_links": [{"n": 1, "claim": STORY_CLAIM}] if marked else [],
    }


@pytest.fixture
def story_chat(request: pytest.FixtureRequest) -> Any:
    """The write job's fake chat model (tests/test_writing_job.py), answering evidence stories too."""
    fake = request.getfixturevalue("chat")
    plain = fake.responders[AiTask.WRITE_SCENARIO]
    fake.responders[AiTask.WRITE_SCENARIO] = lambda prompt: (
        story_answer(prompt) if "EVIDENCE (untrusted data)" in prompt else plain(prompt)
    )
    return fake
