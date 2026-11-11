"""The API key limits check (scripts/ai_limits_check.py) on fake gateways: UAT's own answers as one table of
what the key may use in one minute, a readable key with its team and organisation, a 429's budget, a gateway
that is not LiteLLM, the key read from the variable named and never printed, and nothing of this codebase in
the script. Each test names the mutation it catches."""

import importlib
import re
import sys
from pathlib import Path

import httpx
import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "ai_limits_check.py"
sys.path.insert(0, str(REPO / "scripts"))
try:
    check = importlib.import_module("ai_limits_check")
finally:
    sys.path.remove(str(REPO / "scripts"))

KEY, TEAM, ORG = "sk-secret-key", "team-efd5f7f8", "org-1234"
#: What UAT's gateway answered on 2026-10-30 (the owner's run): /key/info refused, these headers.
UAT_HEADERS = {
    "x-ratelimit-limit-requests": "600",
    "x-ratelimit-organization-limit-requests": "3780",
    "x-ratelimit-organization-limit-tokens": "25000",
    "x-ratelimit-organization-remaining-requests": "3779",
    "x-ratelimit-organization-remaining-tokens": "24994",
    "x-ratelimit-remaining-requests": "599",
    "x-ratelimit-team-limit-requests": "1000",
    "x-ratelimit-team-limit-tokens": "2000000",
    "x-ratelimit-team-remaining-requests": "999",
    "x-ratelimit-team-remaining-tokens": "1999994",
}
UAT_MODEL = {
    "model_name": "kimi-k2.5",
    "litellm_params": {"rpm": 600},
    "model_info": {"max_input_tokens": 114_688, "tpm": None, "rpm": None},
}


def _gateway(chat: httpx.Response, pages: dict[str, object]) -> httpx.Client:
    """A gateway answering `chat` to the question and `pages` by path (403 for an int); 404 otherwise."""

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/chat/completions":
            return chat
        answer = pages.get(request.url.path)
        if answer is None:
            return httpx.Response(404)
        return (
            httpx.Response(answer, json={}) if isinstance(answer, int) else httpx.Response(200, json=answer)
        )

    return httpx.Client(base_url="https://gw.test", transport=httpx.MockTransport(handle))


def _rows(lines: list[str]) -> str:
    """The report with each line's padding squeezed, so a table row reads '| a | b |'."""
    return "\n".join(" ".join(line.split()) for line in lines)


def test_uat_answers_make_one_table_of_what_the_key_may_use_in_a_minute() -> None:
    """The owner's UAT run: the organisation's 25,000 tokens and the model's 600 requests a minute are most;
    24,994 tokens and 599 requests were left. Mutation: the highest limit taken, the limit taken as what was
    left, or the model's 'tpm none set' read as a limit."""
    chat = httpx.Response(200, json={}, headers=UAT_HEADERS)
    text = _rows(check.model_report(_gateway(chat, {"/key/info": 403, "/model/info": {"data": [UAT_MODEL]}}),
                                    "kimi-k2.5"))  # fmt: skip
    assert "| The model's own capacity | none set | 600 | shared by every caller of the model |" in text
    assert (
        "| This key's own limit | not readable (HTTP 403) | not readable (HTTP 403) | for this key alone |"
        in text
    )
    assert "| The key's team | 2,000,000 | 1,000 | shared by every key of that team |" in text
    assert "| The key's organisation | 25,000 | 3,780 | shared by every key of that organisation |" in text
    assert (
        "| **Most this key can use in one minute** | **25,000** | **600** | the lowest above; tokens: the "
        "key's organisation; requests: the model's own capacity |"
    ) in text
    assert (
        "| Left of it in the minute of this check | 24,994 | 599 | after this check's own tiny request |"
        in text
    )
    assert "| Most tokens in one request: prompt / answer | 114,688 / not stated | - | per request |" in text
    assert "x-ratelimit-organization-limit-tokens 25000" in text


def test_uat_answers_in_plain_words_show_how_small_the_token_budget_is() -> None:
    """For a reader who is not technical: the 25,000 tokens a minute against one full-size question and the
    team's budget, each with its meaning. Mutation: the highest limit called the key's, the ratio inverted,
    or the team's budget left out."""
    chat = httpx.Response(200, json={}, headers=UAT_HEADERS)
    text = _rows(check.model_report(_gateway(chat, {"/key/info": 403, "/model/info": {"data": [UAT_MODEL]}}),
                                    "kimi-k2.5"))  # fmt: skip
    assert (
        "In short: this key may use at most 25,000 tokens a minute, shared with others; that is less than "
        "one full-size question (114,688 tokens), and a small part of the 2,000,000 its team is allowed."
        in text
    )
    assert "| Tokens this key may use in | 25,000 | AI text is counted in tokens" in text
    assert "| model accepts | | than this key is allowed to send" in text and "4.6 times" in text
    assert (
        "| Budget of the key's team | 2,000,000 | Allowed, but out of reach" in text and "1.25% of it" in text
    )
    assert "average only 41 tokens (about 30 words) each." in text


def test_a_gateway_not_reached_says_so_in_plain_words() -> None:
    """Mutation: an unreached gateway reported as one that sets no limit."""

    def handle(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("no route", request=request)

    client = httpx.Client(base_url="https://gw.test", transport=httpx.MockTransport(handle))
    text = _rows(check.model_report(client, "kimi-k2.5"))
    assert "no token limit could be read, because the gateway could not be reached from this machine." in text


def test_a_readable_key_its_team_and_its_organisations_own_budget() -> None:
    """The key's own 100 requests a minute and 4 at once, its organisation's 50,000 tokens; never its teams'
    limits, nor any id. Mutation: an organisation's teams' limits read as its own."""
    pages = {
        "/key/info": {"info": {"team_id": TEAM, "organization_id": ORG, "tpm_limit": None, "rpm_limit": 100,
                               "max_parallel_requests": 4}},
        "/team/info": {"team_info": {"team_id": TEAM, "tpm_limit": 200_000}},
        "/organization/info": {"organization_id": ORG, "litellm_budget_table": {"tpm_limit": 50_000},
                               "teams": [{"team_id": "other", "tpm_limit": 1}]},
    }  # fmt: skip
    text = _rows(check.model_report(_gateway(httpx.Response(200, json={}), pages), "kimi-k2.5"))
    assert "| This key's own limit | none set | 100 | for this key alone |" in text
    assert (
        "| The key's organisation | 50,000 | not stated | shared by every key of that organisation |" in text
    )
    assert "| **Most this key can use in one minute** | **50,000** | **100** |" in text
    assert "| Most requests at once (in parallel) | - | 4 | per key |" in text
    assert TEAM not in text and ORG not in text


def test_a_429_names_the_budget_that_refused_the_check() -> None:
    """Mutation: the 429's budget dropped, or whose budget it is printed."""
    message = (
        f"Rate limit exceeded for organization: {ORG}. Limit type: tokens. "
        "Current limit: 25000, Remaining: 0."
    )
    chat = httpx.Response(429, text=message, headers={"rate_limit_type": "tokens", "retry-after": "60"})
    text = _rows(check.model_report(_gateway(chat, {"/key/info": 403}), "kimi-k2.5"))
    assert "429 names organization: limit 25000, remaining 0, limit type tokens" in text
    assert "| **Most this key can use in one minute** | **25,000** | not stated |" in text
    assert "| Left of it in the minute of this check | 0 | not stated |" in text
    assert ORG not in text


def test_a_gateway_that_is_not_litellm_states_the_models_capacity_and_its_window() -> None:
    """Azure's own headers: the model's 100,000 tokens and 100 requests in a 60 s window. Mutation: the window
    dropped."""
    headers = {"x-ratelimit-limit-tokens": "100000", "x-ratelimit-remaining-tokens": "99980",
               "x-ratelimit-limit-requests": "100", "x-ratelimit-remaining-requests": "99",
               "x-ratelimit-renewalperiod-tokens": "60"}  # fmt: skip
    text = _rows(check.model_report(_gateway(httpx.Response(200, json={}, headers=headers), {}), "Kimi-K2.6"))
    assert "| The model's own capacity | 100,000 | 100 | shared by every caller of the model |" in text
    assert "| This key's own limit | not stated | not stated | for this key alone |" in text
    assert "| Left of it in the minute of this check | 99,980 | 99 |" in text
    assert "| How long 'one minute' is | - | - | 60 s, as the gateway states it |" in text


def test_the_key_is_read_from_the_variable_named_and_never_printed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Mutation: the key not sent, or printed."""
    sent = []

    def handle(request: httpx.Request) -> httpx.Response:
        sent.append(request.headers.get("authorization"))
        return httpx.Response(200, json={}, headers=UAT_HEADERS)

    real = httpx.Client
    monkeypatch.setattr(
        httpx, "Client", lambda **options: real(transport=httpx.MockTransport(handle), **options)
    )
    keys = tmp_path / "keys.env"
    keys.write_text(f"MY_KEY={KEY}\n")
    check.main(["--base-url", "https://gw.test", "--model", "kimi-k2.5", "--key-env", "MY_KEY", "--env-file",
                str(keys), "--out", str(tmp_path / "limits.txt")])  # fmt: skip
    out = capsys.readouterr().out
    assert "## kimi-k2.5 (chat model) @ gw.test" in out and KEY not in out and set(sent) == {f"Bearer {KEY}"}
    assert (tmp_path / "limits.txt").read_text(encoding="utf-8") in out  # the console's report, saved
    with pytest.raises(SystemExit, match="No key: set NO_SUCH_KEY"):
        check.main(["--base-url", "https://gw.test", "--model", "kimi-k2.5", "--key-env", "NO_SUCH_KEY"])


def test_an_embedding_and_a_rerank_model_are_each_asked_their_own_tiny_question(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A chat question to an embedding or rerank model would fail, and its limits would go unread. Mutation:
    a search model asked a chat question, or left out."""
    asked = []

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/chat/completions", "/embeddings", "/rerank"):
            asked.append((request.url.path, request.read().decode()))
            return httpx.Response(200, json={}, headers=UAT_HEADERS)
        return httpx.Response(404)

    real = httpx.Client
    monkeypatch.setattr(
        httpx, "Client", lambda **options: real(transport=httpx.MockTransport(handle), **options)
    )
    monkeypatch.setenv("AI_GATEWAY_KEY", KEY)
    check.main(["--base-url", "https://gw.test", "--embedding-model", "qwen3-embedding-8b", "--rerank-model",
                "qwen3-reranker-8b", "--out", str(tmp_path / "limits.txt")])  # fmt: skip
    assert asked == [
        ("/embeddings", '{"model":"qwen3-embedding-8b","input":"hi"}'),
        ("/rerank", '{"model":"qwen3-reranker-8b","query":"hi","documents":["hi"]}'),
    ]
    out = capsys.readouterr().out
    assert (
        "## qwen3-embedding-8b (embedding model) @ gw.test" in out
        and "## qwen3-reranker-8b (rerank model)" in out
    )
    with pytest.raises(SystemExit):
        check.main(["--base-url", "https://gw.test"])


def test_the_check_names_nothing_of_this_codebase() -> None:
    """The owner, 2026-10-30: it is shared as it is. Mutation: an import or a setting of this codebase."""
    source = SCRIPT.read_text(encoding="utf-8")
    assert not re.search(r"CII_|TSG|scenario|from app\b|import app\b|module", source, re.IGNORECASE)
