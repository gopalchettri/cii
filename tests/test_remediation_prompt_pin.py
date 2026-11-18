"""Byte pins: the plan prompt and the re-ask texts the AI is sent stay exactly as approved."""

import hashlib
import json

import pytest

from app.domain.remediation.write import plan_prompt, write_plan
from tests.test_remediation_plan import EXTENDING, ON_SCADA_ONLY, _answer, _control, _item, _real_chat, _snapshot

_USER_PROMPT_SHA256 = "577920fa25a7c5240a1f2aa1d2f51e6354a5e8cb79d7b8c47b2d140fc8989fc7"
_GAP_REASK_SHA256 = "2198f5a4661b49ef7d9e18656c3be40a3cbe00ccf75966eaf945b31ec486d6e0"
_PROSE_REASK_SHA256 = "d7fe69e2d7f854c1378476e4ba2c14a6eb89ad4c6c6ec9ddbbd59ee83ec9de21"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_the_plan_user_prompt_is_byte_identical() -> None:
    assert _sha(plan_prompt(_snapshot())[1]) == _USER_PROMPT_SHA256


def test_the_gap_re_ask_is_byte_identical(monkeypatch: pytest.MonkeyPatch) -> None:
    answer = json.dumps(_answer("CII-CID-5", "CII-CID-1", implements=["CII-CID-5"]))
    chat, sent = _real_chat(monkeypatch, answer, answer)
    write_plan(chat, _snapshot())
    assert _sha(sent[1][-1]["content"]) == _GAP_REASK_SHA256


def test_the_prose_re_ask_is_byte_identical(monkeypatch: pytest.MonkeyPatch) -> None:
    wrong = _answer(_control("CII-CID-1"), _control("CII-CID-5", description="Extends approvals to the RTU."))
    right = _answer(_control("CII-CID-1", description=EXTENDING), "CII-CID-5")
    chat, sent = _real_chat(monkeypatch, json.dumps(wrong), json.dumps(right))
    write_plan(chat, _snapshot([_item(1), _item(5)], **ON_SCADA_ONLY))
    assert _sha(sent[1][-1]["content"]) == _PROSE_REASK_SHA256
