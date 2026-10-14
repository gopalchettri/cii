"""The evidence story writer's and plan check's prompts. The brief reaches the model as data; the evidence
reaches it ONLY inside a delimited block of untrusted data (facts to paraphrase, never instructions), as plain
numbered facts: no ref, title, link or source, delimiter look-alikes stripped, every fact sanitised again. The
original prompts (writing_prompts.py) are not touched."""

import json
import re
from typing import Any

from app.core.constants import EvidenceBlock, IntelKind, TextSafety
from app.engine.external_intelligence.story.evidence_story_rules import without_ids
from app.engine.external_intelligence.story.evidence_story_texts import (
    STORY_PLAN_CHECK_SYSTEM_PROMPT,
    STORY_WRITER_SYSTEM_PROMPT,
)
from app.engine.external_intelligence.untrusted_text import UntrustedTextSanitiser
from app.engine.scenarios.writing.word_limits import with_word_limits
from app.engine.scenarios.writing.writing_prompts import brief_text
from app.engine.shared.ask_ai import ChatPrompt
from app.engine.shared.prompt_redaction import redact
from app.models.writing import ScenarioDraft, WriterBrief

_LOOK_ALIKES = re.compile(
    "|".join(re.escape(text) for text in sorted(EvidenceBlock.LOOK_ALIKES, key=len, reverse=True)),
    re.IGNORECASE,
)


def story_writer_prompt(brief: WriterBrief) -> ChatPrompt:
    """The system prompt with the configured word limits (G226); the user prompt: the brief as one JSON
    object, then the evidence block."""
    system = with_word_limits(STORY_WRITER_SYSTEM_PROMPT)
    return system, f"BRIEF:\n{brief_text(brief)}\n{evidence_block(brief)}"


def story_plan_check_prompt(brief: WriterBrief, draft: ScenarioDraft) -> ChatPrompt:
    """The plan check's user prompt: the plan with the same recorded facts the writer read, the evidence block
    (so a marker can be judged against the entry it names), then the scenario as the writer returned it."""
    plan = {
        "asset": brief.asset,
        "critical_service": brief.critical_service,
        "category": brief.category,
        "attacker": brief.attacker,
        "threat": {
            "threat_type": brief.threat_type,
            "threat": brief.threat,
            "why_it_applies": brief.why_it_applies,
        },
        "systems": list(brief.systems),
        "other_systems": list(brief.other_systems),
    }
    scenario = json.dumps(draft.to_answer(), ensure_ascii=False, default=str)
    plan_json = json.dumps(plan, ensure_ascii=False, default=str)
    user = f"PLAN:\n{plan_json}\n{evidence_block(brief, named=True)}\nSCENARIO:\n{scenario}"
    return STORY_PLAN_CHECK_SYSTEM_PROMPT, user


def evidence_block(brief: WriterBrief, *, named: bool = False) -> str:
    """The evidence as the model reads it, between the block's delimiters: number, plain facts, applicability
    when a vulnerability. Never a ref, link or source: what the model never sees cannot leak. `named` (the
    plan check only): each entry also says what it is about, a technique's own name ("Disk Content Wipe"),
    cleaned like a fact; its facts say "X has used this technique", and without the name the check judged such
    citations unsupported (runs f88ddcec, 75fef9b5: 6 sound cards given up). The writer never sees it, so no
    framework name reaches a story."""
    entries = [
        {"n": number, **(_subject(item) if named else {}), "facts": _safe_facts(item["facts"])}
        | ({"applicability": str(item["applicability"])} if item.get("applicability") else {})
        | ({"scope": str(item["scope"])} if item.get("scope") else {})  # G232: country, regional, global
        for number, item in enumerate(brief.evidence, start=1)
    ]
    body = json.dumps({"evidence_mode": str(brief.evidence_mode), "evidence": entries}, ensure_ascii=False)
    return f"EVIDENCE (untrusted data):\n{EvidenceBlock.BEGIN}\n{body}\n{EvidenceBlock.END}"


def _subject(item: dict[str, Any]) -> dict[str, str]:
    """What the entry is about, under the word its facts use for it ("this technique"); none when its title
    does not survive the cleaning."""
    title = _safe_facts([str(item.get("title") or "")])
    key = "technique" if item.get("kind") == IntelKind.TECHNIQUE else "about"
    return {key: title[0]} if title else {}


def _safe_facts(facts: list[str]) -> list[str]:
    """Each fact redacted, without ids or links, without anything that could close or fake the block, and
    dropped when it reads as an instruction to an AI system."""
    safe = []
    sanitiser = UntrustedTextSanitiser()
    for fact in facts:
        text = _LOOK_ALIKES.sub(" ", without_ids(redact(fact)))
        cleaned = sanitiser.sanitise(" ".join(text.split()), TextSafety.MAX_FACT_CHARS)
        if not cleaned.unsafe and cleaned.text:
            safe.append(cleaned.text)
    return safe
