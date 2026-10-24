"""Guards for the owner's code rules: no inline text for log event names or exception messages; folders
follow the architecture layers (BLUEPRINT §5) and calls go one way; database code only in data_access/; every
data shape in models/; no god class, function or file."""

import ast
import importlib
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
APP = REPO / "app"  # not a relative path: run from another folder, every guard below passed on no files
APP_SOURCES = sorted(APP.rglob("*.py"))
#: The size rules also hold for the laptop scripts (no layers there).
SIZE_CHECKED_SOURCES = APP_SOURCES + sorted((REPO / "scripts").glob("*.py"))
#: The only modules outside a layer folder.
TOP_LEVEL_FILES = {"__init__.py", "main.py", "container.py", "probe.py"}
INLINE_LOG_EVENT = re.compile(r"\blog\.(debug|info|warning|error|exception)\(\s*[\"']")
INLINE_RAISE_MESSAGE = re.compile(r"\braise\s+\w+\(\s*[\"']")
#: The pod's own clock read directly: every "now" comes from app/core/clock.py, MongoDB's clock.
POD_CLOCK_READ = re.compile(r"\bdatetime\.(now|utcnow|today)\(|\btime\.time\(\)|\bdate\.today\(")

#: Which layers each layer may import (BLUEPRINT §5): the diagram's arrows. A layer always may import itself.
ALLOWED_IMPORTS: dict[str, set[str]] = {
    "core": set(),
    "models": {"core"},
    "data_access": {"core", "models"},
    "ai": {"core", "models", "data_access"},
    "search": {"core", "models", "data_access", "ai"},
    "domain": {"core", "models", "ai", "search"},
    "realtime": {"core", "models", "data_access"},
    "services": {"core", "models", "data_access", "ai", "search", "domain", "realtime"},
    "worker": {"core", "models", "data_access", "ai", "search", "domain", "realtime", "container"},
    "api": {"core", "models", "services", "realtime", "container"},
}
#: Calls that read or write MongoDB or SQL Server: only data_access/ (and the clients in core/database.py)
#: make them.
DATABASE_CALLS = {
    "find",
    "find_one",
    "insert_one",
    "insert_many",
    "update_one",
    "update_many",
    "find_one_and_update",
    "find_one_and_replace",
    "find_one_and_delete",
    "replace_one",
    "delete_one",
    "delete_many",
    "bulk_write",
    "aggregate",
    "count_documents",
    "estimated_document_count",
    "distinct",
    "create_index",
    "drop_index",
    "list_indexes",
    "drop_collection",
    "drop_database",
    "execute_procedure",
}
MAX_PUBLIC_METHODS, MAX_CLASS_LINES, MAX_FUNCTION_LINES, MAX_FILE_LINES = 7, 150, 40, 300
#: Owner decision of 2026-10-18: the scenario folders keep few files, and a module's one service file and its
#: repositories may be long, as may the one file that builds every long-lived object; only the file cap is
#: lifted there.
LONG_FILE_FOLDERS = (
    "app/domain/scenario/",
    "app/models/scenario/",
    "app/domain/remediation/",
    "app/models/remediation/",
    "app/services/",
    "app/data_access/",
    "app/container.py",
)
#: X14: a module's one service class and each repository may be wide.
WIDE_CLASS_FILES = ("_service.py", "_repository.py")


def _layer(source: pathlib.Path) -> str:
    parts = source.relative_to(APP).parts
    return parts[0] if len(parts) > 1 else "main"


def _name(source: pathlib.Path) -> str:
    return source.relative_to(REPO).as_posix()


def _imported_layers(node: ast.AST, source: pathlib.Path) -> list[str]:
    """The app layers an import statement reaches: 'import app.x', 'from app.x import y', 'from app import x'
    and relative imports ('from ..x import y') alike."""
    if isinstance(node, ast.Import):
        modules = [alias.name.split(".") for alias in node.names]
    elif isinstance(node, ast.ImportFrom):
        module = node.module.split(".") if node.module else []
        if node.level:  # relative: resolved from the importing module's package
            package = list(source.relative_to(REPO).with_suffix("").parts[:-1])
            module = package[: len(package) - node.level + 1] + module
        modules = [[*module, alias.name] if module == ["app"] else module for alias in node.names]
    else:
        return []
    return [parts[1] for parts in modules if parts[0] == "app" and len(parts) > 1]


def _tree(source: pathlib.Path) -> ast.Module:
    return ast.parse(source.read_text(encoding="utf-8"))


def _offending_lines(pattern: re.Pattern[str]) -> list[str]:
    offending = []
    for source in APP_SOURCES:
        text = source.read_text(encoding="utf-8")
        offending += [
            f"{_name(source)}:{text[: match.start()].count(chr(10)) + 1}" for match in pattern.finditer(text)
        ]
    return offending


def test_log_event_names_come_from_the_log_event_enum() -> None:
    assert _offending_lines(INLINE_LOG_EVENT) == [], "use app.constants.LogEvent"


def test_exception_messages_come_from_constants() -> None:
    assert _offending_lines(INLINE_RAISE_MESSAGE) == [], "use ErrorMessage or a domain message enum"


def test_every_now_comes_from_the_shared_clock() -> None:
    """UAT, 2026-10-24: the pods' clocks disagreed by up to 76 s, and a worker reading its own clock dropped
    every job as not due yet. Use app.core.clock.utc_now / epoch_seconds (time.monotonic for durations)."""
    assert _offending_lines(POD_CLOCK_READ) == [], "use app.core.clock.utc_now or epoch_seconds"


def test_the_guards_see_the_code() -> None:
    assert len(APP_SOURCES) > 50, f"found {len(APP_SOURCES)} modules under {APP}"


def test_every_module_lives_in_a_layer_folder() -> None:
    """A module beside main.py has no layer, so no import rule would apply to it."""
    folders = {_layer(source) for source in APP_SOURCES} - {"main"}
    assert folders <= set(ALLOWED_IMPORTS), (
        f"folders outside the layers: {sorted(folders - set(ALLOWED_IMPORTS))}"
    )
    top_level = {source.name for source in APP_SOURCES if _layer(source) == "main"}
    assert top_level <= TOP_LEVEL_FILES, f"outside a layer folder: {sorted(top_level - TOP_LEVEL_FILES)}"


def test_calls_go_one_way_between_layers() -> None:
    """A lower layer never imports a higher one, so the diagram stays true as the code grows."""
    offenders = []
    for source in APP_SOURCES:
        layer = _layer(source)
        if layer == "main":
            continue
        for node in ast.walk(_tree(source)):
            for target in _imported_layers(node, source):
                if target != layer and target not in ALLOWED_IMPORTS.get(layer, set()):
                    offenders.append(f"{_name(source)}:{node.lineno} {layer} -> {target}")
    assert offenders == [], "\n".join(offenders)


def _imported_modules(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    if isinstance(node, ast.ImportFrom) and node.module:
        return [node.module, *(f"{node.module}.{alias.name}" for alias in node.names)]
    return []


def test_shared_domain_steps_import_no_feature() -> None:
    """app/domain/shared/ serves scenarios and remediation alike, so it never imports either: a step one
    feature needs alone belongs in that feature's folder."""
    sources = sorted((APP / "domain" / "shared").glob("*.py"))
    assert sources, "the guard sees app/domain/shared"
    offenders = [
        f"{_name(source)}:{node.lineno} {module}"
        for source in sources
        for node in ast.walk(_tree(source))
        for module in _imported_modules(node)
        if module.startswith(("app.domain.scenario", "app.domain.remediation"))
    ]
    assert offenders == [], "\n".join(offenders)


def test_database_calls_live_only_in_data_access() -> None:
    offenders = []
    for source in APP_SOURCES:
        if _layer(source) == "data_access" or _name(source) == "app/core/database.py":
            continue
        for node in ast.walk(_tree(source)):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in DATABASE_CALLS
            ):
                offenders.append(f"{_name(source)}:{node.lineno} .{node.func.attr}()")
    assert offenders == [], "\n".join(offenders)


def _is_model(node: ast.ClassDef) -> bool:
    bases = {base.id if isinstance(base, ast.Name) else getattr(base, "attr", "") for base in node.bases}
    decorators = {(d.func if isinstance(d, ast.Call) else d) for d in node.decorator_list}
    is_dataclass = any(getattr(d, "id", getattr(d, "attr", "")) == "dataclass" for d in decorators)
    return "BaseModel" in bases or is_dataclass


def test_every_data_shape_lives_in_models() -> None:
    """Pydantic models and public dataclasses are found in one place; a private helper (_Run) may stay put."""
    offenders = [
        f"{_name(source)}:{node.lineno} {node.name}"
        for source in APP_SOURCES
        if _layer(source) != "models"
        for node in ast.walk(_tree(source))
        if isinstance(node, ast.ClassDef) and not node.name.startswith("_") and _is_model(node)
    ]
    assert offenders == [], "\n".join(offenders)


def test_no_god_class_function_or_file() -> None:
    offenders = []
    for source in SIZE_CHECKED_SOURCES:
        lines = len(source.read_text(encoding="utf-8").splitlines())
        if lines > MAX_FILE_LINES and not _name(source).startswith(LONG_FILE_FOLDERS):
            offenders.append(f"{_name(source)}: {lines} lines (max {MAX_FILE_LINES})")
        for node in ast.walk(_tree(source)):
            size = (node.end_lineno or node.lineno) - node.lineno + 1 if hasattr(node, "end_lineno") else 0
            if isinstance(node, ast.ClassDef):
                public = [
                    item.name
                    for item in node.body
                    if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef)
                    and not item.name.startswith("_")
                ]
                wide = node.name == "MongoRepository"  # owner rule: the base holds every plain verb
                owner = source.name.endswith(WIDE_CLASS_FILES)
                if not owner and ((len(public) > MAX_PUBLIC_METHODS and not wide) or size > MAX_CLASS_LINES):
                    offenders.append(
                        f"{_name(source)}:{node.lineno} class {node.name}: {len(public)} public, {size} lines"
                    )
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and size > MAX_FUNCTION_LINES:
                offenders.append(
                    f"{_name(source)}:{node.lineno} {node.name}(): {size} lines (max {MAX_FUNCTION_LINES})"
                )
    assert offenders == [], "\n".join(offenders)


def _uses_functools_cache(node: ast.AST) -> bool:
    """'from functools import lru_cache [as x]' or 'functools.cache' anywhere: as a decorator, called on a
    function ('lru_cache()(build)') or renamed, every form is caught where the name enters the module."""
    if isinstance(node, ast.ImportFrom) and node.module == "functools":
        return any(alias.name in {"lru_cache", "cache"} for alias in node.names)
    return (
        isinstance(node, ast.Attribute)
        and node.attr in {"lru_cache", "cache"}
        and isinstance(node.value, ast.Name)
        and node.value.id == "functools"
    )


def test_process_singletons_are_built_once() -> None:
    """functools.lru_cache / cache run the builder in every thread that races the first call; process-wide
    singletons use app.core.singletons.singleton, which builds once."""
    offenders = [
        f"{_name(source)}:{node.lineno}"
        for source in APP_SOURCES
        for node in ast.walk(_tree(source))
        if _uses_functools_cache(node)
    ]
    assert offenders == [], "use @singleton (app/core/singletons.py):\n" + "\n".join(offenders)


def test_singletons_live_only_in_the_container_and_core() -> None:
    """Only app/container.py (and core's clients and settings) builds long-lived objects."""
    offenders = [
        f"{_name(source)}:{node.lineno} {node.name}"
        for source in APP_SOURCES
        if _name(source) != "app/container.py" and _layer(source) != "core"
        for node in ast.walk(_tree(source))
        if isinstance(node, ast.FunctionDef)
        and any(getattr(d, "id", getattr(d, "attr", None)) == "singleton" for d in node.decorator_list)
    ]
    assert offenders == [], "\n".join(offenders)


def test_the_worker_imports_the_container_only_inside_a_function() -> None:
    """A worker module imports app.container only inside a function, so importing it builds nothing and makes
    no import cycle."""
    offenders = [
        f"{_name(source)}:{node.lineno}"
        for source in APP_SOURCES
        if _layer(source) == "worker"
        for node in _tree(source).body
        if "container" in _imported_layers(node, source)
    ]
    assert offenders == [], "\n".join(offenders)


def test_one_service_class_per_module() -> None:
    """app/services/ holds one folder per module, each with one service class, in its *_service.py."""
    services = APP / "services"
    assert [path.name for path in services.glob("*.py")] == ["__init__.py"]
    for folder in sorted(path for path in services.iterdir() if path.is_dir() and path.name != "__pycache__"):
        classes = [
            node.name
            for source in folder.glob("*.py")
            for node in _tree(source).body
            if isinstance(node, ast.ClassDef)
        ]
        assert len(classes) == 1 and next(folder.glob("*_service.py"), None), f"{folder.name}: {classes}"


def test_every_constant_is_imported_from_one_place_and_defined_once() -> None:
    """The topic files of app/core/constants/ are re-exported by the package, so every import reads
    `from app.core.constants import X`; a name defined in two topic files would silently shadow one."""
    package = importlib.import_module("app.core.constants")
    defined: dict[str, str] = {}
    for source in sorted((APP / "core" / "constants").glob("*.py")):
        if source.name == "__init__.py":
            continue
        module = importlib.import_module(f"app.core.constants.{source.stem}")
        for node in _tree(source).body:
            target = node.target if isinstance(node, ast.AnnAssign) else None
            name = node.name if isinstance(node, ast.ClassDef) else getattr(target, "id", None)
            if name is None:
                continue
            assert name not in defined, f"{name} in {defined[name]} and {source.stem}"
            defined[name] = source.stem
            assert getattr(package, name) is getattr(module, name), name
    assert len(defined) > 50  # the guard sees the declarations


def test_the_repo_passes_ruff_lint_and_format() -> None:
    """Before: nothing ran ruff with the tests, so docs/API_DEVELOPER_HANDBOOK.md's code examples drifted from
    ruff format unnoticed (2026-10-23). The project's own settings (pyproject.toml) decide what is checked."""
    for check in (["check", "."], ["format", "--check", "."]):
        ruff = [sys.executable, "-m", "ruff", *check]
        result = subprocess.run(ruff, cwd=REPO, capture_output=True, text=True, timeout=120, check=False)  # noqa: S603
        assert result.returncode == 0, result.stdout + result.stderr
