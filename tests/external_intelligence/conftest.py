"""The whole suite runs with external intelligence OFF (tests/conftest.py sets
EXTERNAL_INTELLIGENCE_ENABLED=false), so the app's existing tests exercise the original path. A test of
the ON path asks for the `intel` fixture: the master switch on, and the app's own switch, evidence finder
and feeds answering from fakes, with a fake refresher."""

from dataclasses import dataclass
from typing import Any

import pytest

from app import container
from app.core.config import get_settings
from app.core.constants import AiTask, IntelSource
from app.data_access.external_intelligence.intel_feed_repository import IntelFeedRepository
from tests.external_intelligence.fakes import FakeFinder, FakeRefresher, FakeSwitch
from tests.fakes import brief_of

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


@dataclass
class Intel:
    finder: FakeFinder
    switch: FakeSwitch
    refresher: FakeRefresher
    feeds: IntelFeedRepository


@pytest.fixture
def intel(monkeypatch: pytest.MonkeyPatch) -> Intel:
    """The app's own switch, finder and feeds answer from the fakes, so every job built with them (whenever it
    was built) sees the test's state; the refresher is asked for by the task each time it runs. The app's
    switch is fetched before the master switch turns on: built now, it keeps the suite's env value."""
    finder, switch, refresher = FakeFinder(), FakeSwitch(), FakeRefresher()
    monkeypatch.setattr(container.get_intelligence_switch(), "state", switch.state)
    monkeypatch.setattr(container.get_evidence_finder(), "find_evidence", finder.find_evidence)
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", True)
    feeds = container.get_intel_feed_repository()
    monkeypatch.setattr(feeds, "list_approved_sources", lambda: list(IntelSource))  # a test revokes its own
    monkeypatch.setattr(container, "get_source_refresher", lambda: refresher)
    return Intel(finder, switch, refresher, feeds)


def story_answer(user_prompt: str) -> dict[str, Any]:
    """A clean evidence story for the brief it is given, citing nothing (code adds the precedent); each
    threat's its own (the very same words are a copy whatever the threat: G268)."""
    brief = brief_of(user_prompt)
    options = brief["entry_point_options"]
    own = f"In a {brief['threat']['threat']} attack, a cybercriminal could begin"
    return {
        "scenario_title": "Loss of control integrity",
        "scenario_statement": STORY_PLAIN.replace("A cybercriminal could begin", own),
        "risk_statement": "Loss of trusted control at Grid Control Centre could interrupt transmission.",
        "assumptions": [],
        "entry_point": options[0] if options else "",
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
