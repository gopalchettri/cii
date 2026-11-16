"""The UAT gateway check (scripts/uat_gateway_check.py) on a fake LiteLLM gateway: each model's limit headers,
the key's pages, whether a rerank lowers the token budget, the many-at-once steps stopping at the first 429,
TSG's .env read as TSG reads it, the calls sent direct (never by a proxy), and the key never in the report.
Each test names the mutation it catches."""

import importlib
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
KEY = "uat-secret-key-1234567890"  # not sk- shaped: only the exact-key hiding can hide it
RERANKS_AT_ONCE = 3  # the fake reranker refuses a fourth call in flight
NAMES = [f"{prefix}_{part}" for _, prefix in [
    ("", "CII_SCENARIO_CHAT"), ("", "CII_REMEDIATION_CHAT"), ("", "CII_SERVICE_MAPPER_CHAT"),
    ("", "CII_EMBEDDING"), ("", "CII_RERANK")] for part in ("BASE_URL", "MODEL", "API_KEY")]  # fmt: skip


class FakeGateway(ThreadingHTTPServer):
    request_queue_size = 64
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), Handler)
        self.lock = threading.Lock()
        self.in_flight = 0
        self.remaining = 2_000_000
        self.seen: list[tuple[str, str, str]] = []  # (path, Authorization, x-litellm-api-key)


class Handler(BaseHTTPRequestHandler):
    server: FakeGateway

    def log_message(self, *args: object) -> None:
        pass

    def answer(self, status: int, body: object, headers: dict[str, str] | None = None) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        for name, value in {"Content-Type": "application/json", **(headers or {})}.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        self.server.seen.append((self.path, self.headers["Authorization"], self.headers["x-litellm-api-key"]))
        if self.path == "/key/info":
            self.answer(403, {"error": "not allowed"})
        elif self.path == "/model/info":
            self.answer(200, {"data": [
                {"model_name": "qwen3-reranker-8b", "litellm_params": {"rpm": 300, "api_key": KEY}},
                {"model_name": "someone-elses-model", "litellm_params": {"rpm": 1}},
                {"model_name": "qwen3-embedding-8b", "litellm_params": {"rpm": 600}}]})  # fmt: skip
        elif self.path == "/redirect":
            self.answer(302, {}, {"Location": "/leak"})
        else:
            self.answer(404, {})

    def do_POST(self) -> None:  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.seen.append((self.path, self.headers["Authorization"], self.headers["x-litellm-api-key"]))
        gate = self.server
        if self.path == "/v1/chat/completions":
            self.answer(200, {"usage": {"total_tokens": 9}}, {
                "x-ratelimit-team-limit-tokens": "2000000",
                "x-ratelimit-team-remaining-tokens": str(gate.remaining)})  # fmt: skip
        elif self.path == "/v1/embeddings":
            self.answer(200, {"data": [{"embedding": [0.1, 0.2]}], "usage": {"total_tokens": 30}})
        elif self.path == "/v1/rerank":
            with gate.lock:
                gate.in_flight += 1
                busy = gate.in_flight > RERANKS_AT_ONCE
            try:
                time.sleep(0.3)  # every call of a step is in flight at once
                if busy:
                    message = (  # LiteLLM v3's words: the limit comes after a 64-hex key hash
                        f"litellm.RateLimitError: Rate limit exceeded for model_per_key: {'a' * 64}:"
                        f"qwen3-reranker-8b. Limit type: requests. Current limit: 3, Remaining: 0. Key {KEY}"
                    )
                    self.answer(429, {"error": {"message": message}}, {"retry-after": "60"})
                    return
                counted = sum(len(d) for d in body["documents"]) // 4
                with gate.lock:
                    gate.remaining -= counted
                results = [{"index": i, "relevance_score": 0.5} for i in range(len(body["documents"]))]
                self.answer(
                    200,
                    {"results": results, "meta": {"billed_units": {"total_tokens": counted}}},
                    {
                        "x-ratelimit-limit-requests": "100",
                        "x-ratelimit-remaining-requests": "97",
                        "x-litellm-key-rpm-limit": "600",
                    },  # fmt: skip
                )
            finally:
                with gate.lock:
                    gate.in_flight -= 1


@pytest.fixture
def gateway():
    server = FakeGateway()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()


@pytest.fixture
def check(monkeypatch, tmp_path):
    """The script, imported with a dead proxy in the environment and none of TSG's own settings."""
    for name in [*NAMES, "CII_AI_KEY_HEADER"]:
        monkeypatch.delenv(name, raising=False)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")  # nothing listens: a call by the proxy fails
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    sys.path.insert(0, str(REPO / "scripts"))
    try:
        module = importlib.reload(importlib.import_module("uat_gateway_check"))
    finally:
        sys.path.remove(str(REPO / "scripts"))
    module.KEYS.clear()
    return module


def step_rows(text: str) -> list[list[str]]:
    """The numbers of each load step's row: its first two cells are whole numbers."""
    return [
        cells
        for cells in (line.split() for line in text.splitlines())
        if cells[:2] and all(c.isdigit() for c in cells[:2])
    ]


def write_env(folder: Path, base: str) -> Path:
    lines = ["# TSG's UAT settings", "CII_AI_KEY_HEADER=x-litellm-api-key"]
    for prefix, model in (("CII_SCENARIO_CHAT", "kimi-k2.5"), ("CII_REMEDIATION_CHAT", "glm-5.3"),
                          ("CII_SERVICE_MAPPER_CHAT", "glm-5.3"), ("CII_EMBEDDING", "qwen3-embedding-8b"),
                          ("CII_RERANK", "qwen3-reranker-8b")):  # fmt: skip
        lines += [
            f"{prefix}_BASE_URL={base}",
            f'{prefix}_MODEL="litellm_proxy/{model}"',
            f"{prefix}_API_KEY={KEY}",
        ]
    path = folder / ".env"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_report_reads_limits_steps_until_a_429_and_hides_the_key(check, gateway, tmp_path, capsys):
    """Catches: the key printed (hide() dropped), any step run after a 429 (the stop dropped, or stopping only
    that model), calls sent by the proxy (ProxyHandler({}) dropped), the key header not sent, glm checked
    twice, a page's other models shown or its models unnamed, LiteLLM's x-litellm-key-* headers missed, a
    429's limit cut off, the chats of the token check not shown."""
    env = write_env(tmp_path, f"http://127.0.0.1:{gateway.server_port}")
    assert check.main(["--env-file", str(env), "--steps", "1,5,2", "--pause", "0"]) == 0
    report = capsys.readouterr().out
    assert KEY not in report and KEY not in next(tmp_path.glob("gateway_check_*.txt")).read_text()
    assert report.count("glm-5.3 (chat)") == 2  # the models line and section 1: once each, not per module
    assert "x-ratelimit-team-limit-tokens 2000000" in report
    assert "/key/info                    HTTP 403: this key may not read it" in report
    assert "  /model/info, qwen3-reranker-8b: litellm_params.rpm 300\n" in report
    assert "  /model/info, qwen3-embedding-8b: litellm_params.rpm 600\n" in report
    assert "someone-elses-model" not in report and "rpm 1\n" not in report
    assert "x-litellm-key-rpm-limit 600" in report.split("3. Do reranks")[1].split("4. Many")[0]
    assert "tiny chat before (kimi-k2.5): HTTP 200" in report and "tiny chat after: HTTP 200" in report
    assert "x-ratelimit-team-remaining-tokens: 2,000,000 before" in report and "(down " in report
    rerank = report.split("qwen3-reranker-8b (40 documents a call)")[1].split("qwen3-embedding-8b")[0]
    assert [row[:3] for row in step_rows(rerank)] == [["1", "1", "0"], ["5", "3", "2"]]
    assert "429 retry-after 60" in rerank and "Current limit: 3, Remaining: 0" in rerank
    assert (
        "no more calls were sent" in rerank and "one query a call" not in report
    )  # the embedding not loaded
    assert {(auth, header) for _, auth, header in gateway.seen} == {(f"Bearer {KEY}", KEY)}


def test_both_models_step_through_when_no_limit_is_reached(check, gateway, tmp_path, capsys):
    """Catches: the load stopped after one model, or after a step without a 429."""
    env = write_env(tmp_path, f"http://127.0.0.1:{gateway.server_port}")
    assert check.main(["--env-file", str(env), "--steps", "1,3", "--pause", "0"]) == 0
    report = capsys.readouterr().out
    rerank = report.split("qwen3-reranker-8b (40 documents a call)")[1].split("qwen3-embedding-8b")[0]
    embedding = report.split("qwen3-embedding-8b (one query a call)")[1]
    assert [row[:3] for row in step_rows(rerank)] == [["1", "1", "0"], ["3", "3", "0"]]
    assert [row[:2] for row in step_rows(embedding)] == [["1", "1"], ["3", "3"]] and "stopped" not in report


def test_a_redirect_is_not_followed(check, gateway):
    """Catches: urllib's redirect handler kept, which sends the key headers on to the Location's host."""
    gate = check.Gateway(f"http://127.0.0.1:{gateway.server_port}", KEY, "x-litellm-api-key")
    assert check.send(gate, gate.page("/redirect")).status == 302
    assert [path for path, *_ in gateway.seen] == ["/redirect"]


def test_env_file_is_read_as_tsg_reads_it_and_the_environment_wins(
    check, gateway, tmp_path, monkeypatch, capsys
):
    """Catches: quotes kept, an inline comment kept, 'export' kept as part of the name, the file winning over
    the environment (the pods' settings are environment variables)."""
    path = tmp_path / "settings.env"
    path.write_text("export A=\"quoted # kept\"\nB=plain # a comment\n# C=no\nD='single'\nE=\n", "utf-8")
    assert check.read_env_file(str(path)) == {"A": "quoted # kept", "B": "plain", "D": "single", "E": ""}
    assert check.read_env_file(str(tmp_path / "none.env")) == {}
    env = write_env(tmp_path, f"http://127.0.0.1:{gateway.server_port}")
    monkeypatch.setenv("CII_RERANK_MODEL", "litellm_proxy/from-the-environment")
    assert check.main(["--env-file", str(env), "--no-load"]) == 0
    assert "from-the-environment (rerank)" in capsys.readouterr().out


def test_no_settings_is_a_plain_error(check, tmp_path, capsys):
    """Catches: a crash, or a report of nothing, when the folder has no TSG settings."""
    assert check.main(["--env-file", str(tmp_path / "missing.env")]) == 2
    assert "No AI settings" in capsys.readouterr().err


def test_no_answer_is_reported_not_raised(check):
    """Catches: send() raising on a refused connection, which would stop the whole report."""
    answer = check.send(
        check.Gateway("http://127.0.0.1:1", KEY, ""), "http://127.0.0.1:1/v1/rerank", {"a": 1}
    )
    assert answer.status == 0 and "Error" in answer.text
