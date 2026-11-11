"""The token-limit proof (scripts/ai_limit_proof.py) on a fake gateway: the limit read from its headers, one
real request sent 5 times at the same moment and then once alone a minute later, a summary and every request
and response word for word, an honest result whatever the gateway answers, the key, whose budget and cookies
hidden, and the one-file UAT runner carrying both scripts. Each test names the mutation it catches."""

import hashlib
import importlib
import json
import re
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "ai_limit_proof.py"
sys.path.insert(0, str(REPO / "scripts"))
try:
    proof = importlib.import_module("ai_limit_proof")
finally:
    sys.path.remove(str(REPO / "scripts"))

KEY, ORG = "sk-secret-key-7f3a", "org-1234"
#: A Create scenario's relevance check, shaped like the one rebuilt on the laptop on 2026-10-30.
BODY = {
    "model": "kimi-k2.5",
    "messages": [
        {"role": "system", "content": "You judge threats."},
        {"role": "user", "content": "LANDSCAPE: ..."},
    ],
    "max_tokens": 10240,
    "temperature": 0.0,
}
#: What UAT's gateway answered on 2026-10-30 (the owner's run).
UAT_HEADERS = [
    ("x-ratelimit-limit-requests", "600"),
    ("x-ratelimit-organization-limit-tokens", "25000"),
    ("x-ratelimit-organization-remaining-tokens", "9233"),
    ("x-ratelimit-team-limit-tokens", "2000000"),
    ("set-cookie", "route=abc123; Path=/"),
]
SAID = (
    f"Rate limit exceeded for organization: {ORG}. Limit type: tokens. Current limit: 25000, Remaining: 9233."
)
REFUSED = (
    429,
    "Too Many Requests",
    [("retry-after", "60"), ("x-ratelimit-organization-remaining-tokens", "9233")],
    json.dumps({"error": {"message": SAID}}),
)
ANSWERED = (
    200,
    "OK",
    UAT_HEADERS,
    '{"choices": [{"message": {"content": "{}"}}], "usage": {"prompt_tokens": 5527}}',
)


def _gateway(monkeypatch: pytest.MonkeyPatch, *answers: tuple) -> tuple[list[dict], list[float]]:
    """The gateway gives `answers` in turn (status, reason, headers, body); what it was asked, and each wait,
    are returned."""
    asked, waits, queue, turn = [], [], list(answers), threading.Lock()

    def ask(base: str, key: str, body: dict) -> object:
        with turn:  # 5 threads ask at once: one answer each, in the order they asked
            asked.append(body)
            status, reason, headers, text = queue.pop(0)
            sent_at = datetime(2026, 10, 31, 9, 14, len(asked), tzinfo=UTC)
        sent = json.dumps(body).encode()
        return proof.Exchange(
            f"{base}/chat/completions", sent, sent_at, 0.25, status, reason, list(headers), text
        )

    monkeypatch.setattr(proof, "ask", ask)
    return asked, waits


def _run(monkeypatch: pytest.MonkeyPatch, *answers: tuple) -> tuple[str, int, list[dict], list[float]]:
    """The proof on `answers`: its screen as one line (every run of spaces and line breaks one space), its
    exit code, what the gateway was asked and each wait."""
    asked, waits = _gateway(monkeypatch, *answers)
    lines, code = proof.proof("https://gw.test", KEY, BODY, waits.append)
    return " ".join(" ".join(lines).split()), code, asked, waits


def test_five_at_once_one_is_answered_four_refused_then_alone_it_is_answered(monkeypatch) -> None:
    """UAT: the organisation's 25,000 is the lowest limit; one relevance check asks for 15,767 of it.
    Mutation: the highest limit taken, fewer than 5 sent, no wait before the one alone, a refusal not counted,
    the answer cap left out of a request's size."""
    text, code, asked, waits = _run(monkeypatch, ANSWERED, ANSWERED, *[REFUSED] * 4, ANSWERED)
    assert code == 0 and asked == [{"model": "kimi-k2.5", **proof.SMALL}, *[BODY] * 6] and waits == [61]
    assert "Limit read from the gateway: 25,000 tokens a minute (the organization limit, the lowest" in text
    assert (
        "the model counted 5,527 input tokens, and it asks for an answer of up to 10,240: 15,767 tokens, 63%"
        in text
    )
    assert "5 sent at once ask for 78,835, 3.2 times that limit." in text
    assert "1 09:14:02.000 at once HTTP 200 OK 5,527 9,233 0.25 s" in text
    assert "2 09:14:03.000 at once HTTP 429 Too Many Requests - 9,233 0.25 s" in text
    assert "6 09:14:07.000 alone HTTP 200 OK 5,527 9,233 0.25 s" in text
    assert (
        "RESULT ENFORCED. Of 5 requests sent at the same moment, the gateway answered 1 and refused 4 with "
        "HTTP 429. This key may use 25,000 tokens a minute (the organization limit). Sent alone a minute "
        "later, the "
        "same request was answered." in text
    )


def test_every_request_and_response_is_shown_word_for_word_with_the_key_whose_and_cookies_hidden(
    monkeypatch,
) -> None:
    """Mutation: the request body not shown as sent, a repeat not tied to it by its fingerprint, a response
    header or body dropped, whose budget, a cookie or the key printed."""
    _, waits = _gateway(monkeypatch, ANSWERED, ANSWERED, *[REFUSED] * 4, ANSWERED)
    lines, _ = proof.proof("https://gw.test", KEY, BODY, waits.append)
    text, sent = "\n".join(lines), json.dumps(BODY).encode()
    fingerprint = f"SHA-256 {hashlib.sha256(sent).hexdigest()}"
    assert (
        "REQUEST 1: REQUEST sent 2026-10-31 09:14:02.000 UTC\n    POST https://gw.test/chat/completions"
        in text
    )
    assert "    Authorization: Bearer <hidden, ends ...7f3a>" in text and KEY not in text
    assert f"Body, exactly as sent ({len(sent):,} bytes, {fingerprint}):\n    {sent.decode()}\n" in text
    assert text.count(f"Body: the same {len(sent):,} bytes as REQUEST 1 ({fingerprint})") == 5
    assert "REQUEST 2: RESPONSE after 0.25 s\n    HTTP 429 Too Many Requests\n    retry-after: 60" in text
    assert "    set-cookie: <value hidden>" in text and "abc123" not in text
    assert "Body, word for word (whose budget replaced with <id hidden>):" in text
    assert (
        "Rate limit exceeded for organization: <id hidden>. Limit type: tokens." in text and ORG not in text
    )
    assert text.count(": REQUEST sent") == 7 and '"prompt_tokens": 5527' in text


def test_a_gateway_that_refuses_none_is_said_plainly(monkeypatch) -> None:
    """The laptop's Azure gateway allows 100,000 a minute. Mutation: any answer read as a refusal."""
    text, code, _, _ = _run(monkeypatch, *[ANSWERED] * 7)
    assert code == 1 and "RESULT NOT SHOWN. The gateway refused none of the 6 requests" in text


@pytest.mark.parametrize(
    ("cap", "why"),
    [(10240, "others were using the budget"), (30000, "one request alone asks for more than the limit")],
)
def test_the_one_alone_refused_too_is_explained(monkeypatch, cap, why) -> None:
    """With nothing answered, a request's input is estimated from its size. Mutation: the reason not told by
    the request's size, or an estimate not labelled one."""
    monkeypatch.setitem(BODY, "max_tokens", cap)
    text, code, _, _ = _run(monkeypatch, ANSWERED, *[REFUSED] * 6)
    assert code == 0 and f"Sent alone a minute later, the same request was refused too ({why})." in text
    assert f"about (est.) {len(json.dumps(BODY)) // 4:,} input tokens" in text


def test_no_limit_stated_sends_nothing_more(monkeypatch) -> None:
    """Mutation: the request sent against no limit, or against a limit of 0."""
    asked, waits = _gateway(monkeypatch, (200, "OK", [("x-ratelimit-limit-tokens", "0")], "{}"))
    lines, code = proof.proof("https://gw.test", KEY, BODY, waits.append)
    assert code == 2 and len(asked) == 1 and "stated no tokens-a-minute limit" in "\n".join(lines)


def test_the_key_is_read_from_the_variable_named_and_never_printed(monkeypatch, capsys, tmp_path) -> None:
    """Mutation: the key printed, a non-http address or a body with no model accepted."""
    leak = (429, "Too Many Requests", [], f"refused for key {KEY}")
    _gateway(monkeypatch, ANSWERED, *[leak] * 6)
    monkeypatch.setattr(proof, "MINUTE_SECONDS", 0)  # main() waits with time.sleep
    monkeypatch.setenv("MY_KEY", KEY)
    body = tmp_path / "request.json"
    body.write_text(json.dumps(BODY), encoding="utf-8")
    options = ["--body", str(body), "--key-env", "MY_KEY"]
    assert proof.main(["--base-url", "https://gw.test", *options]) == 0
    out = capsys.readouterr().out
    assert KEY not in out and "<hidden, ends ...7f3a>" in out
    with pytest.raises(SystemExit, match="Not a gateway address"):
        proof.main(["--base-url", "file:///etc/passwd", *options])
    with pytest.raises(SystemExit, match="No key: set NO_SUCH_KEY"):
        proof.main(["--base-url", "https://gw.test", "--body", str(body), "--key-env", "NO_SUCH_KEY"])
    body.write_text(json.dumps({"messages": BODY["messages"]}), encoding="utf-8")
    with pytest.raises(SystemExit, match="Not a chat request body"):
        proof.main(["--base-url", "https://gw.test", *options])


def test_the_script_is_plain_ascii_and_names_nothing_of_this_codebase() -> None:
    """PowerShell 5.1 pipes text into the pod as ASCII, and the script is shared as it is."""
    source = SCRIPT.read_bytes()
    assert all(byte < 128 for byte in source)
    assert not re.search(rb"CII_|TSG|scenario|from app\b|import app\b", source, re.IGNORECASE)


@pytest.mark.parametrize(
    ("name", "script"), [("Request", "tsg_scenario_request.py"), ("Proof", "ai_limit_proof.py")]
)
def test_the_uat_runner_carries_each_script_word_for_word(name, script) -> None:
    """The owner copies one file to the UAT server: the runner holds both scripts inside it, in plain ASCII.
    Mutation: a script and its copy drifting apart (a fix made in one and not the other)."""
    runner = (REPO / "scripts" / "ai_limit_proof_uat.ps1").read_bytes()
    carried = runner.split(f"${name} = @'\r\n".encode(), 1)[1].split(b"\r\n'@", 1)[0].replace(b"\r\n", b"\n")
    source = (REPO / "scripts" / script).read_bytes()
    assert carried == source.replace(b"\r\n", b"\n").rstrip(b"\n")
    assert all(byte < 128 for byte in runner)
