"""The routes the UI team already calls never change (owner, 2026-10-29: "no way to change anything"): every
path, method, parameter, request body and response of the API as it stood before AI usage tracking, and every
data shape it used, stays exactly as frozen in tests/contract/ui_api_frozen.json. New routes may be added.
Unlike the openapi pin, TSG_WRITE_CONTRACT=1 never rewrites this one."""

import json

from tests.checkout import REPO

FROZEN = json.loads((REPO / "tests" / "contract" / "ui_api_frozen.json").read_text(encoding="utf-8"))


def _current() -> dict:
    from app.main import create_app

    return create_app().openapi()


def test_every_existing_route_is_unchanged() -> None:
    paths = _current()["paths"]
    changed = [
        f"{method.upper()} {path}"
        for path, operations in FROZEN["paths"].items()
        for method, operation in operations.items()
        if paths.get(path, {}).get(method) != operation
    ]
    assert changed == [], f"existing routes changed: {changed}"


def test_every_existing_data_shape_is_unchanged() -> None:
    schemas = _current()["components"]["schemas"]
    changed = [name for name, schema in FROZEN["schemas"].items() if schemas.get(name) != schema]
    assert changed == [], f"existing request or response shapes changed: {changed}"


def test_the_ai_usage_routes_are_the_only_new_ones() -> None:
    added = sorted(set(_current()["paths"]) - set(FROZEN["paths"]))
    assert added == [
        "/v1/ai-usage",
        "/v1/ai-usage/calls",
        "/v1/ai-usage/requests",
        "/v1/ai-usage/requests/{request_id}",
    ]
