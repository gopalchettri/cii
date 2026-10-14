"""What one scenario's controls are searched and reranked by (spec v4.0 §7.5.1: its scenario AND risk
statements; owner 2026-10-11: every fact the asset procedure returns, none picked by name), within
Controls.QUERY_MAX_CHARS.

G227 (owner 2026-10-13): with 300-400-word scenarios and 150-200-word risks, a text built narrative first and
cut from the end lost every system's facts, so controls were matched to the story alone. Now a short head
comes first (category, threat, attacker, title, asset), then each system, the asset's facts, the scenario and
the risk, and the room left after the head is shared fairly: a part shorter than its equal share keeps all of
it and leaves the rest to the others, so the longest parts (in practice the scenario and the risk) are the
ones cut, one long system description never pushes the others out, and no part is ever dropped. The query
(about 1,000 tokens at 4,000 characters) fits both models whole: the reranker reads 8,192 tokens, the
embedding model 8,191."""

from typing import Any

from app.core.constants import Controls
from app.core.redaction import redact
from app.engine.scenarios.finding.asset_landscape import raw_system_facts
from app.engine.shared.names import shorten_text
from app.engine.shared.prompt_redaction import facts_safe_for_prompt
from app.models.asset_context import FrozenContext
from app.models.controls import ControlQuery


def control_query(
    content: dict[str, Any], context: FrozenContext, systems: list[dict[str, Any]]
) -> ControlQuery:
    """The query, and which of its parts had to be shortened to fit (their labels: no text). Redacted, as
    every prompt is."""
    threat = content.get("threat") or {}
    acting = next((a["name"] for a in content.get("actors") or [] if a.get("role") == "acting"), "")
    asset = _named_with_type(context.asset.get("name"), context.asset_context.get("asset_type"))
    head = redact(
        "\n".join(
            [
                f"Category: {content.get('category') or ''}",
                f"Threat: {threat.get('type') or ''}: {threat.get('name') or ''}",
                f"Attacker: {acting}",
                f"Title: {content.get('title') or ''}",
                f"Asset: {asset}",
            ]
        )
    )
    labelled = [
        *((f"system {s['id']}", f"System {s['name']}: {_facts_line(raw_system_facts(s))}") for s in systems),
        ("asset facts", f"Asset facts: {_facts_line(context.own_and_organisation_facts()[0])}"),
        ("scenario", f"Scenario: {content.get('statement') or ''}"),
        ("risk", f"Risk: {content.get('risk_statement') or ''}"),
    ]
    texts = [redact(text) for _, text in labelled]
    room = Controls.QUERY_MAX_CHARS - len(head) - len(texts)  # one line break before each part
    shares = _fair_shares([len(text) for text in texts], max(room, 0))
    fitted = [shorten_text(text, share) for text, share in zip(texts, shares, strict=True)]
    shortened = tuple(
        label for (label, _), text, share in zip(labelled, texts, shares, strict=True) if len(text) > share
    )
    query = "\n".join([shorten_text(head, Controls.QUERY_MAX_CHARS), *(text for text in fitted if text)])
    return ControlQuery(query, shortened)


def _fair_shares(lengths: list[int], room: int) -> list[int]:
    """Each part's room: shortest first, each takes what it needs up to an equal share of what is left, so
    short parts are whole and the longest are cut, none to nothing while room is left."""
    shares = [0] * len(lengths)
    for position, index in enumerate(sorted(range(len(lengths)), key=lambda i: (lengths[i], i))):
        shares[index] = min(lengths[index], room // (len(lengths) - position))
        room -= shares[index]
    return shares


def _facts_line(facts: dict[str, Any]) -> str:
    """Every recorded fact as `name: value` (a list joined by commas), as the AI would be shown it: no id, no
    placeholder, no unanswered value; the line itself says whose facts they are."""
    shown = facts_safe_for_prompt({key: value for key, value in facts.items() if key != "name"})
    return "; ".join(
        f"{key}: {', '.join(map(str, value)) if isinstance(value, list) else value}"
        for key, value in shown.items()
    )


def _named_with_type(name: str | None, asset_type: str | None) -> str:
    """The asset's name and type, e.g. "Grid Centre (Control system)", or the name alone when no type is
    recorded or it is excluded (G197): never empty brackets in the text the reranker scores."""
    recorded = facts_safe_for_prompt({"type": asset_type}).get("type")  # "N/A", blanks: not a type
    return f"{name or ''} ({recorded})" if recorded else name or ""
