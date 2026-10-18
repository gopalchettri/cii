"""Pins what TSG shows to the outside: the OpenAPI document, stored enum values, Redis keys and other tsg
names, Celery task routes and schedule, and MongoDB indexes and validators. A restructure must leave every
pin unchanged; an approved outside change rewrites them with TSG_WRITE_CONTRACT=1."""

import ast
import enum
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.checkout import REPO

CONTRACT = REPO / "tests" / "contract"
WRITE = os.environ.get("TSG_WRITE_CONTRACT") == "1"
#: Index set-up in a fresh process, so the pin covers the intelligence collections too (off in the suite).
INDEX_SETUP = (
    "from app.data_access.base import create_all_indexes\n"
    "from app.worker.jobs import JOB_COLLECTIONS\n"
    "create_all_indexes(JOB_COLLECTIONS)\n"
)


def _check(name: str, current: Any) -> None:
    """Compares `current` with its stored pin, or stores it when TSG_WRITE_CONTRACT=1."""
    path = CONTRACT / f"{name}.json"
    text = json.dumps(current, indent=1, sort_keys=True, default=str) + "\n"
    if WRITE:
        CONTRACT.mkdir(exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return
    assert path.exists(), f"no pin {path.name}: run once with TSG_WRITE_CONTRACT=1"
    assert json.loads(text) == json.loads(path.read_text(encoding="utf-8")), f"{name} changed"


def test_openapi_document_is_unchanged() -> None:
    from app.main import create_app

    _check("openapi", create_app().openapi())


def test_stored_values_and_tsg_names_are_unchanged() -> None:
    import app.core.constants as constants

    enums, names = {}, {}
    for class_name, value in sorted(vars(constants).items()):
        if not isinstance(value, type):
            continue
        if issubclass(value, enum.Enum):
            if not class_name.endswith("Message") and class_name != "LogEvent":  # text only, never stored
                enums[class_name] = {member.name: member.value for member in value}
            continue
        for attribute, constant in vars(value).items():
            if isinstance(constant, str) and "tsg" in constant.lower():
                names[f"{class_name}.{attribute}"] = constant
    _check("enums", enums)
    _check("tsg_names", names)


def test_celery_routes_and_schedule_are_unchanged() -> None:
    from app.worker.celery_app import celery_app

    conf = celery_app.conf
    _check(
        "celery",
        {
            "routes": {str(task): str(route["queue"]) for task, route in conf.task_routes.items()},
            "schedule": {
                str(name): [str(entry["task"]), entry["schedule"]]
                for name, entry in conf.beat_schedule.items()
            },
        },
    )


def test_mongodb_indexes_and_validators_are_unchanged() -> None:
    from pymongo import MongoClient

    from app.core.config import get_settings

    scratch = f"{os.environ['CII_MONGO_DB']}_contract"
    env = os.environ | {"CII_MONGO_DB": scratch, "EXTERNAL_INTELLIGENCE_ENABLED": "true"}
    subprocess.run([sys.executable, "-c", INDEX_SETUP], cwd=REPO, env=env, check=True, timeout=120)  # noqa: S603
    client: MongoClient = MongoClient(get_settings().mongo_url, serverSelectionTimeoutMS=10_000)
    try:
        database = client[scratch]
        found = {}
        for info in database.list_collections():
            indexes = {
                name: {key: value for key, value in spec.items() if key not in ("v", "ns")}
                for name, spec in database[info["name"]].index_information().items()
            }
            found[info["name"]] = {"indexes": indexes, "options": info.get("options", {})}
        _check("indexes", found)
    finally:
        client.drop_database(scratch)
        client.close()


@pytest.mark.parametrize("script", sorted((REPO / "scripts").glob("*.py")), ids=lambda path: path.name)
def test_script_imports_resolve(script: Path) -> None:
    for node in ast.walk(ast.parse(script.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] == "app":
            module = importlib.import_module(node.module)
            for alias in node.names:
                found = hasattr(module, alias.name) or importlib.util.find_spec(f"{node.module}.{alias.name}")
                assert found, f"{script.name}: {node.module}.{alias.name}"
