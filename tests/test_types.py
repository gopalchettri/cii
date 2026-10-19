"""The type check is part of the suite: a type error in app/ fails the tests, so none piles up unseen."""

from mypy import api

from tests.checkout import REPO


def test_app_has_no_type_errors() -> None:
    """mypy over app/ with the project's own settings (pyproject.toml) reports nothing."""
    report, errors, status = api.run(["--config-file", str(REPO / "pyproject.toml"), str(REPO / "app")])
    assert status == 0, f"{report}{errors}"
