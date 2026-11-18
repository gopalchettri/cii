"""The admin web UI's shell (plan 5a): served at /ui with the browser security headers and outside the OpenAPI
document; its files hold nothing the page's content policy or the key rule forbids, and call only routes the
API has."""

import re
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.routing import iter_route_contexts
from fastapi.testclient import TestClient

from app.api.ui import UI_FOLDER, UI_HEADERS, UI_PATH
from app.core.constants import ApiTag
from app.main import create_app
from tests.checkout import REPO

PAGE_IDS = ["ingestion", "schedule", "control_links", "jobs", "vectors", "api_keys", "curation", "ai_usage", "system"]
#: What no file of the UI may hold: markup parsed from text, code built from text, anything kept in the browser.
FORBIDDEN_WORDS = (
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
    "localStorage",
    "sessionStorage",
    "indexedDB",
    "document.cookie",
    "eval(",
    "new Function",
)
UI_FILES = sorted(path for path in UI_FOLDER.rglob("*") if path.is_file())
SCRIPTS = [path for path in UI_FILES if path.suffix == ".js"]
#: An API path in a script: one string or template literal that starts with "/" and a letter.
PATH_LITERAL = re.compile(r"""["'`](/[A-Za-z][^"'`\s]*)["'`]""")
NODE = shutil.which("node")


@pytest.fixture(scope="module")
def ui_client() -> Iterator[TestClient]:
    """The app without its start-up: the UI's files read no store."""
    yield TestClient(create_app())


def _name(path: Path) -> str:
    return path.relative_to(REPO).as_posix()


def _text(name: str) -> str:
    return (UI_FOLDER / name).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("path", "media_type"),
    [
        ("/", "text/html"),
        ("/index.html", "text/html"),
        ("/app.js", "text/javascript"),
        ("/api.js", "text/javascript"),
        ("/poll.js", "text/javascript"),
        ("/dom.js", "text/javascript"),
        ("/styles.css", "text/css"),
    ],
)
def test_every_file_is_served_with_the_security_headers(ui_client: TestClient, path: str, media_type: str) -> None:
    response = ui_client.get(UI_PATH + path)
    assert response.status_code == 200
    assert response.headers["content-type"] == f"{media_type}; charset=utf-8"
    assert {name: response.headers.get(name) for name in UI_HEADERS} == UI_HEADERS
    assert UI_HEADERS == {
        "Cache-Control": "no-store",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }


def test_the_shell_is_what_ui_answers(ui_client: TestClient) -> None:
    shell = ui_client.get(f"{UI_PATH}/").text
    assert shell == _text("index.html")
    for part in ('id="nav"', 'id="admin-key"', 'type="password"', 'id="page"', 'src="./app.js"', "./styles.css"):
        assert part in shell, part


def test_no_link_of_the_shell_loads_the_document_again() -> None:
    """The admin key lives in the tab's memory: a link to "./" is a reload and the key is gone without a word."""
    links = re.findall(r'<a\b[^>]*\shref="([^"]*)"', _text("index.html"))
    assert links == ["#main", f"#/{PAGE_IDS[0]}", "/docs"]


def test_enter_in_the_name_field_does_not_submit_the_key_form() -> None:
    """Enter in any field of a form submits it; the key form's submit means "set this key": it holds the key alone."""
    shell = _text("index.html")
    key_form = re.search(r'<form id="access"[^>]*>(.*?)</form>', shell, re.S)
    assert key_form is not None
    assert re.findall(r'<input id="([\w-]+)"', key_form.group(1)) == ["admin-key"]
    assert re.findall(r'<input id="([\w-]+)"', shell) == ["user-id", "admin-key"]
    assert shell.count("<form") == 1


def test_a_script_is_javascript_whatever_the_machine_guesses(
    ui_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Windows registry can name .js text/plain; with nosniff the browser then runs no module."""
    monkeypatch.setattr("starlette.responses.guess_type", lambda *_: ("text/plain", None))
    assert ui_client.get(f"{UI_PATH}/app.js").headers["content-type"] == "text/javascript; charset=utf-8"


def test_the_shell_at_ui_is_html_whatever_the_machine_guesses(
    ui_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """/ui/ names a folder: the type is the served index.html's. Mutation: read the type from the path asked
    for and the shell is whatever the machine guesses for .html."""
    monkeypatch.setattr("starlette.responses.guess_type", lambda *_: ("text/plain", None))
    assert ui_client.get(f"{UI_PATH}/").headers["content-type"] == "text/html; charset=utf-8"


def test_a_missing_file_is_a_404_problem_with_the_same_headers(ui_client: TestClient) -> None:
    """A page file not written yet: the shell's import fails on this, and shows "not available"."""
    response = ui_client.get(f"{UI_PATH}/pages/no_such_page.js")
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"
    assert {name: response.headers.get(name) for name in UI_HEADERS} == UI_HEADERS


def test_no_file_outside_the_ui_folder_is_served(ui_client: TestClient) -> None:
    for path in ("/../main.py", "/%2e%2e/main.py", "/..%2fmain.py", "/../../pyproject.toml"):
        assert ui_client.get(UI_PATH + path).status_code == 404, path


def test_the_mount_adds_nothing_to_the_openapi_document() -> None:
    app = create_app()
    assert [path for path in app.openapi()["paths"] if path.startswith(UI_PATH)] == []
    assert [route.name for route in app.routes if getattr(route, "path", "") == UI_PATH] == ["ui"]


def test_the_intelligence_groups_swagger_text_names_this_page_and_only_routes_the_api_has() -> None:
    """The group's text named neither the schedule nor the control links nor this page."""
    document = create_app().openapi()
    text = next(tag["description"] for tag in document["tags"] if tag["name"] == ApiTag.INTELLIGENCE)
    named = set(re.findall(r"(/[a-z][a-z/-]*)`", text)) - {f"{UI_PATH}/"}
    assert f"`{UI_PATH}/`" in text and named >= {"/schedule", "/control-links", "/control-links/prepare"}
    assert [path for path in sorted(named) if f"/v1/tsg/intel{path}" not in document["paths"]] == []


def _find_forbidden(text: str, is_html: bool) -> list[str]:
    found = [word for word in FORBIDDEN_WORDS if word in text]
    found += re.findall(r"https?://[\w.-]+[^\s\"'`<>)]*", text)
    found += re.findall(r"\bstyle\s*=\s*[\"'`]", text)
    found += re.findall(r"setAttribute\(\s*[\"']style", text)
    if is_html:
        found += re.findall(r"<style\b", text, re.I)
        found += re.findall(r"\son\w+\s*=", text, re.I)
        for attributes, body in re.findall(r"<script\b([^>]*)>(.*?)</script>", text, re.I | re.S):
            if body.strip() or "src=" not in attributes:
                found.append(f"inline <script{attributes}>")
    return found


def test_no_ui_file_holds_what_the_page_policy_forbids() -> None:
    """The policy is default-src 'self': no inline script or style runs, nothing loads from another host. The
    admin key lives in a variable of the tab only, and text from the API is never parsed as markup."""
    assert {path.name for path in UI_FILES} >= {"index.html", "styles.css", "api.js", "poll.js", "dom.js", "app.js"}
    offenders = [
        f"{_name(path)}: {found}"
        for path in UI_FILES
        for found in _find_forbidden(path.read_text(encoding="utf-8"), path.suffix == ".html")
    ]
    assert offenders == [], "\n".join(offenders)


@pytest.mark.parametrize(
    ("text", "is_html"),
    [
        ("box.innerHTML = answer.name;", False),
        ("localStorage.setItem('key', admin_key);", False),
        ("sessionStorage.key = admin_key;", False),
        ("document.cookie = `key=${admin_key}`;", False),
        ("eval(answer.code);", False),
        ('import("https://cdn.example.org/lib.js");', False),
        ("@import url(http://fonts.example.org/a.css);", False),
        ('row.setAttribute("style", "color: red");', False),
        ('<p style="color: red">x</p>', True),
        ("<style>p { color: red }</style>", True),
        ("<script>start()</script>", True),
        ('<script type="module">start()</script>', True),
        ('<button onclick="start()">Go</button>', True),
    ],
)
def test_the_policy_guard_catches_each_forbidden_thing(text: str, is_html: bool) -> None:
    assert _find_forbidden(text, is_html) != []
    assert _find_forbidden('<script type="module" src="./app.js"></script>', True) == []


def _find_unknown_paths(script: str, routes: list[str]) -> list[str]:
    """The path literals of a script that match no route; a `${...}` stands for one path part."""
    patterns = [
        re.compile(
            "".join("[^/]+" if part.startswith("{") else re.escape(part) for part in re.split(r"(\{[^}]+\})", route))
        )
        for route in routes
    ]
    return [
        literal
        for literal in PATH_LITERAL.findall(script)
        if not any(pattern.fullmatch(re.sub(r"\$\{[^}]*\}", "x", literal.split("?")[0])) for pattern in patterns)
    ]


def test_every_api_path_a_script_calls_is_a_route() -> None:
    """A page that calls a path the API does not have fails here, not in the browser."""
    routes = [route.path for route in iter_route_contexts(create_app().routes) if route.path != UI_PATH]
    assert "/v1/tsg/intel/health" in routes, "the guard sees the app's routes"
    scripts = {_name(path): path.read_text(encoding="utf-8") for path in SCRIPTS}
    assert PATH_LITERAL.findall(scripts["app/ui/app.js"]), "the guard sees the scripts' paths"
    unknown = [
        f"{name}: {literal}" for name, script in scripts.items() for literal in _find_unknown_paths(script, routes)
    ]
    assert unknown == [], "\n".join(unknown)


def test_the_path_guard_reads_literals_and_templates() -> None:
    routes = ["/v1/admin/jobs", "/v1/admin/jobs/{job_id}/cancel", "/health"]
    script = """
        request("GET", "/v1/admin/jobs");
        request("GET", with_query('/v1/admin/jobs', { hours: 24 }));
        request("POST", `/v1/admin/jobs/${job.id}/cancel`);
        request("GET", `/v1/admin/jobs?hours=${hours}`);
        request("GET", "/health");
        request("GET", "/v1/admin/job");
        request("POST", `/v1/admin/jobs/${job.id}/stop`);
        request("GET", "/v2/anything");
        import("./pages/jobs.js");
    """
    assert _find_unknown_paths(script, routes) == ["/v1/admin/job", "/v1/admin/jobs/${job.id}/stop", "/v2/anything"]


def test_the_page_table_names_the_nine_pages_each_with_its_file() -> None:
    table = re.findall(
        r'\{ id: "(\w+)", title: "[^"]+", needs_admin_key: (?:true|false), load: [^}]*?pages/(\w+)\.js', _text("app.js")
    )
    assert [page_id for page_id, _ in table] == PAGE_IDS
    assert all(page_id == file_name for page_id, file_name in table)


@pytest.mark.skipif(NODE is None, reason="node is not installed")
@pytest.mark.parametrize("script", SCRIPTS, ids=_name)
def test_every_script_parses(script: Path) -> None:
    check = [str(NODE), "--check", str(script)]
    result = subprocess.run(check, capture_output=True, text=True, timeout=60, check=False)  # noqa: S603
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(NODE is None, reason="node is not installed")
@pytest.mark.parametrize("checks_file", ["admin_ui_checks.mjs", "admin_ui_shell_checks.mjs"])
def test_the_scripts_behave_under_node(checks_file: str) -> None:
    """admin_ui_checks.mjs: headers, the one error message, 401/403 clear the key and say why, never another
    origin; following pauses while hidden, ends at done, failed or cancelled, and gives up on a refusal.
    admin_ui_shell_checks.mjs: only "#/<page>" changes the page, a refusal is told in the API's words, a reload
    keeps the keyboard focus in the page, a source's claim never hides its status, a link stays on this origin."""
    checks = [str(NODE), str(REPO / "tests" / checks_file)]
    result = subprocess.run(checks, capture_output=True, text=True, timeout=120, check=False)  # noqa: S603
    assert result.returncode == 0, result.stdout + result.stderr
