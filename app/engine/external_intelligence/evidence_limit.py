"""Which of a threat's usable evidence records fit its limit: the best ones, but never one kind (an ATT&CK
technique, an advisory, a vulnerability) taking every place while another kind has a record that passed."""

from app.models.external_intelligence.evidence import Evidence


def choose_within_limit(usable: list[Evidence], limit: int) -> list[Evidence]:
    """`usable` is best first. The first `limit` are taken; then, best first, every kind still missing takes
    the place of the lowest-scored record whose kind is held more than once. Order and ties are fixed."""
    chosen = list(usable[:limit])
    for extra in usable[limit:]:
        if any(item.kind == extra.kind for item in chosen):
            continue
        shared = [i for i, item in enumerate(chosen) if sum(o.kind == item.kind for o in chosen) > 1]
        if shared:
            chosen[shared[-1]] = extra
    return sorted(chosen, key=usable.index)
