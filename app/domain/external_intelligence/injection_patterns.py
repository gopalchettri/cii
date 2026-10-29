"""What reads as an instruction to an AI system: (reason code, pattern) pairs, compiled once. A matching text
is quarantined whole, never repaired; every wildcard is bounded, so no pattern backtracks badly."""

import re
from typing import Final

from app.core.constants import TextCleaning


def _compile(table: dict[str, str]) -> tuple[tuple[str, re.Pattern[str]], ...]:
    """The table's patterns compiled case-insensitively, each with its reason code."""
    return tuple((code, re.compile(pattern, re.IGNORECASE)) for code, pattern in table.items())


_OBJECT = r"(?:instructions?|prompts?|rules?|guidelines?|directions?|directives?|context|messages?|commands?)"
_PRIOR = r"(?:previous|prior|above|earlier|preceding|former|original|all|any|every|your|these|those|the|this)"
_ALL_CLEAR = (
    r"(?:safe|secure|not\s+vulnerable|no\s+risk|no\s+threat|not\s+affected|not\s+exploitable|low\s+risk"
    r"|benign|harmless)"
)
_AI = r"(?:ai|llm|language\s+model|assistant|model|chatgpt|gpt|claude|copilot|gemini|agent|bot|writer)"

#: The start of an order: a text or sentence start, or the comma / "please" / "you must" before the verb.
#: A verb that follows a subject ("An attacker could act as ...") is a description, not an order.
_ORDER = (
    r"(?:^|[.!?;:,\n]\s*|\bplease\s+|\byou\s+(?:must|should|will|can|may|need\s+to|have\s+to)\s+)"
    r"(?:(?:now|then|just)\s+)?"
)
_CLEAR_THING = r"(?:asset|assets|system|systems|device|devices|product|products|network|networks|it)"
_ROLE_SWITCH = (
    r"\byou\s+(?:are|will\s+be|must\s+be)\s+(?:now|no\s+longer)\s+"
    r"(?:an?|the|my|dan|free|unrestricted|acting|playing|going|called|named|in|bound|restricted|unlocked|jailbroken"
    r"|uncensored|unfiltered|root|admin|developer|evil|operating|without)\b"
    r"|\byour\s+(?:new\s+)?(?:task|role|job|goal|purpose|persona)\s+(?:is|are)\b"
    r"|\bnew\s+(?:instructions?|rules?|persona|role|task)\s*:"
    r"|\bswitch\s+(?:to|into)\s+(?:developer|dan|god|jailbreak|unrestricted|unfiltered|evil|sudo)\s+mode\b"
)
#: Naming the model's own prompt: "show the NOP instructions" (a CPU's) is not, "show your instructions" is.
_OF_THE_MODEL = (
    r"(?:your|its|my|our|above|previous|prior|preceding|hidden|secret|system|developer|initial|original"
    r"|full|entire|exact|given)"
)
#: "Operating system instructions" are a computer's, never the model's prompt (an injection story says it).
_PROMPT_REFERENCE = (
    r"(?<!operating\s)\b(?:system|developer|hidden|initial|original|secret)\s+(?:prompt|message|instructions?)\b"
    rf"|\b(?:reveal|repeat|print|show|leak|disclose|display)\b(?:\W+\w+){{0,4}}?\W+{_OF_THE_MODEL}\b"
    r"(?:\W+\w+){0,2}?\W+(?:prompt|instructions?|rules)\b"
    r"|\b(?:reveal|repeat|print|leak|disclose)\s+(?:me\s+)?(?:the\s+)?(?:prompt|rules)\b"
    r"|\b(?:reveal|repeat|print|show|leak|disclose)\b.{0,25}\b(?:prompt|instructions|rules)\s+"
    r"(?:that\s+)?(?:you|i)\s+(?:were|was|have|had|got|received)\b"
)
_ROLE_MARKER = r"(?:^|[.!?:;]\s|\n|[\[(<\"'])\s*(?:system|assistant|human|developer|ai|bot)\s*:"
_CHAT_TEMPLATE = (
    r"<\|[^|>\s]{1,30}\|>|\[/?(?:inst|sys)\]|<</?sys>>"
    r"|\#{2,}\s*(?:instruction|system|response|input|human|assistant|user)\b"
    r"|</?(?:s|system|assistant|user|human|prompt|instructions?|tool_call|function_call)>"
)
_TOOL_MARKERS = r"\b(?:function_call|tool_calls?|tool_use|tool_result|tool_name)\b"
_ADDRESSES_AI = (
    r"\bas\s+an?\s+(?:ai|llm|language\s+model|assistant|chatbot)\b"
    rf"|\b(?:dear|attention|note\s+to|instructions?\s+for|hey|hello|hi)\s+{_AI}\b"
    r"|\bfor\s+(?:the\s+)?(?:ai|llm|language\s+model|assistant|scenario\s+writer)\b"
)
_OTHER_LANGUAGE = (
    r"\bignor\w{1,6}\s+(?:\w+\s+){0,3}(?:instrucciones|instructions|anweisungen|istruzioni)\b"
    r"|\boubli\w+\s+(?:\w+\s+){0,3}instructions\b|\bvergiss\s+(?:\w+\s+){0,3}anweisungen\b"
)

#: The text with and without its markup: phrases, markers and delimiters.
TEXT_PATTERNS: Final = _compile(
    {
        "override_instructions": r"\b(?:ignore|disregard|forget|override|bypass|overrule|skip|discard)\b"
        rf"(?:\W+\w+){{0,3}}?\W+{_PRIOR}\b(?:\W+\w+){{0,2}}?\W+{_OBJECT}\b",
        "ignore_above": r"\b(?:ignore|disregard|forget)\b.{0,25}"
        r"\b(?:previous|prior|above|preceding|earlier)\b",
        "disregard": r"\bdisregard\b\W+(?:this|the|all|any|everything|previous|above|prior|your|these)\b",
        "ignore_attention": r"\bpay\s+no\s+(?:attention|heed)\b|\b(?:stop|cease)\s+(?:following|obeying)\b"
        r"|\bdo\s+not\s+(?:follow|obey)\s+(?:the|your|any|these)\b"
        r"|\b(?:overlook|neglect|dismiss|abandon)\s+(?:all\s+|any\s+|the\s+)?"
        r"(?:previous|prior|earlier|above|preceding)\b",
        "role_switch": _ROLE_SWITCH,
        "role_play": rf"{_ORDER}(?:(?:act|behave|respond|answer)\s+as\s+(?:an?|the|if|though)\b"
        r"|pretend\s+to\s+be\b|simulate\s+being\b)"
        r"|\bpretend\s+(?:that|you)\b|\bfrom\s+now\s+on\b",
        "prompt_reference": _PROMPT_REFERENCE,
        "role_marker": _ROLE_MARKER,
        "chat_template": _CHAT_TEMPLATE,
        # A markdown heading ("### Browser-based Exploitation") is formatting; a bare run of marks is a fence.
        "delimiter": r"[=\-~*_#<>]{5,}|\#{3,}(?!#)(?!\s+[A-Za-z])|`{3,}|~{3,}|\"{3,}|'{3,}"
        r"|\b(?:begin|start|end)\s+of\s+(?:the\s+)?(?:system|prompt|instructions?|context|input|text"
        r"|document|description)\b"
        r"|\b(?:begin|start|end)\s+(?:the\s+)?(?:system\s+(?:prompt|message|instructions?)|prompt|instructions?)\b"
        r"|(?-i:\b(?:BEGIN|START|END)\s+(?:THE\s+)?(?:SYSTEM|PROMPT|INSTRUCTIONS?|CONTEXT|INPUT|TEXT|DOCUMENT"
        r"|DESCRIPTION)\b)",
        "tool_injection": rf"{_TOOL_MARKERS}"
        r"|[\"']?\b(?:role|tool|function|tool_name|recipient_name)\b[\"']?\s*:\s*[\"']?"
        r"(?:system|assistant|user|tool|function)\b"
        r"|\{\s*[\"'](?:role|tool|function|name|content|arguments)[\"']\s*:"
        rf"|{_ORDER}(?:call|invoke)\s+(?:the\s+)?(?:function|tool)\b"
        r"|\byou\s+(?:must|should|need\s+to|have\s+to)\s+(?:call|invoke|run|execute)\s+(?:the\s+)?"
        r"(?:function|tool|command|shell)\b"
        r"|\bexecute\s+(?:the\s+following|this)\s+(?:tool|function|code|prompt|instructions?)\b",
        "output_steering": r"\b(?:write|say|state|report|respond|reply|answer|output|conclude|tell)\s+"
        rf"(?:that\s+|only\s+|exactly\s+).{{0,40}}\b{_ALL_CLEAR}\b"
        rf"|{_ORDER}(?:write|say|state|report|respond|reply|answer|output|conclude|tell)\s+with\s+"
        rf".{{0,40}}\b{_ALL_CLEAR}\b"
        rf"|\b(?:mark|rate|classify|label|score|rank|treat|consider)\b.{{0,40}}\bas\s+(?:\w+\s+){{0,2}}"
        rf"{_ALL_CLEAR}\b"
        rf"|\b(?:call|deem|declare)\s+(?:this|that|the|these|each|every|all)\s+(?:\w+\s+)?{_CLEAR_THING}"
        rf"\s+(?:to\s+be\s+)?{_ALL_CLEAR}\b"
        r"|\b(?:describe|portray|depict|present|characteri[sz]e)\s+(?:\w+\s+){0,4}?"
        rf"(?:as|to\s+be)\s+(?:\w+\s+){{0,2}}(?:{_ALL_CLEAR}|patched|positive\w*|fine)\b"
        r"|\b(?:describe|portray|depict|present|characteri[sz]e)\s+(?:\w+\s+){0,3}"
        r"(?:positively|favou?rably|optimistically)\b"
        r"|\b(?:always|never)\s+(?:describe|say|write|state|mention|report|respond|answer|treat|rate|mark"
        r"|classify)\b"
        r"|\b(?:include|insert|add|append|put|repeat|say|write)\s+(?:the\s+)?(?:word|phrase)s?\b"
        r"|\b(?:include|insert|add|append|put|repeat|say|write)\b.{0,30}"
        r"\b(?:every|each)\s+(?:sentence|paragraph|line|response|answer|output)\b"
        rf"|(?:{_ORDER}(?:do\s+not|don'?t)|\bnever)\s+(?:mention|reveal|disclose|tell|say|report|flag|include)\b"
        r"|\b(?:asset|system|device|product|network)\s+is\s+(?:safe|secure|not\s+vulnerable)\b"
        r"|\b(?:respond|reply|answer|output)\s+(?:only|exactly|just)\s+with\b"
        rf"|{_ORDER}(?:respond|reply|answer|output)\s+(?:with|exactly)\b"
        r"|\b(?:respond|reply|answer|output)\s+with\s+(?:[\"']|the\s+(?:word|phrase|string|text|exact)\b"
        r"|a\s+single\b|one\s+word\b|nothing\b|(?:ok|yes|no|approved|safe|secure|true|false|pass|fine"
        r"|confirmed)\b)",
        "off_task": r"\b(?:write|compose|tell|generate|produce)\s+(?:me\s+)?(?:the|a|an|your|this)\s+"
        r"(?:\w+\s+){0,2}(?:story|poem|essay|haiku|song|joke)\b",
        "addresses_ai": _ADDRESSES_AI,
        "other_language": _OTHER_LANGUAGE,
        "encoded_escape": r"(?:\\u[0-9a-f]{4}){3,}|(?:\\x[0-9a-f]{2}){4,}|(?:%[0-9a-f]{2}){6,}"
        r"|(?:&\#x?[0-9a-f]{2,6};){4,}"
        # An ORDER to decode ("Decode the following base64 string"); "Base64-encoded commands" only describes.
        rf"|(?:{_ORDER}|\b(?:and|then)\s+)(?:(?:base64|rot13|hex)[\s-]+)?(?:decode|decrypt|decipher)\b"
        r".{0,25}\b(?:following|this|string|text|below)\b",
    }
)

#: Live markup. Checked apart from TEXT_PATTERNS because a description may QUOTE it (a `<script>` tag in
#: backticks, a `<code>` example with "javascript:"): the sanitiser drops a quoted span that holds markup
#: (after every other pattern has read it) and checks what is left.
MARKUP_PATTERNS: Final = _compile(
    {
        "active_markup": r"<\s*(?:script|iframe|object|embed|style|link|meta|svg|form)\b"
        r"|\bon\w{3,15}\s*=\s*[\"'\w]|\bjavascript\s*:|\bdata\s*:\s*[\w.+-]+/[\w.+-]+\s*[;,]",
    }
)

#: What the scenario WRITER's own draft is checked for: only phrases that mark an instruction echoed from the
#: evidence it was fed, never ordinary prose ("operators ignore earlier alarms", "an attacker could act as").
ECHO_PATTERNS: Final = _compile(
    {
        "override_instructions": r"\b(?:ignore|disregard|forget)\b(?:\W+\w+){0,3}?\W+"
        r"(?:previous|prior|above|earlier|preceding)\b(?:\W+\w+){0,2}?\W+"
        r"(?:instructions?|prompts?|directions?|directives?|guidelines)\b",
        "role_switch": _ROLE_SWITCH,
        "prompt_reference": _PROMPT_REFERENCE,
        "role_marker": _ROLE_MARKER,
        "chat_template": _CHAT_TEMPLATE,
        "tool_injection": _TOOL_MARKERS,
        "addresses_ai": _ADDRESSES_AI,
        "other_language": _OTHER_LANGUAGE,
    }
)

#: The skeleton with every non-letter removed: key phrases that must not hide behind spacing or punctuation.
SQUASHED_PATTERNS: Final = _compile(
    {
        "override_instructions": r"(?:ignore|disregard|forget|override)(?:all|any|the|your|every)?"
        r"(?:previous|prior|above|earlier|preceding)?(?:instructions|prompts|rules|directives|context)",
        "role_switch": r"youarenow(?:dan|free|unrestricted|jailbroken|anai|anassistant)"
        r"|younolongerbound|fromnowon",
        "prompt_reference": r"systemprompt|developermessage|hiddenprompt|initialinstructions",
        "chat_template": r"imstart|imend|endoftext|beginsystem",
    }
)

#: A long run of base64 or hex digits is an encoded payload, not a word or a sentence.
BLOB_PATTERNS: Final = _compile(
    {
        "encoded_blob": rf"(?<![\w+/=])[A-Za-z0-9+/_-]{{{TextCleaning.ENCODED_BLOB_MIN},}}"
        r"={0,2}(?![\w+/=])",
        "mixed_blob": r"(?<![\w+/=])(?=[A-Za-z0-9+/]*\d)(?=[A-Za-z0-9+/]*[a-z])(?=[A-Za-z0-9+/]*[A-Z])"
        rf"[A-Za-z0-9+/]{{{TextCleaning.MIXED_BLOB_MIN},}}={{0,2}}"
        r"(?![\w+/=])",
        "hex_blob": rf"(?<![0-9a-f])[0-9a-f]{{{TextCleaning.HEX_BLOB_MIN},}}(?![0-9a-f])",
    }
)

#: Cyrillic, Greek and other letters that read as Latin ones: mapped for CHECKING only (the stored text
#: drops them, see untrusted_text.py).
CONFUSABLES: Final = str.maketrans(
    {
        **dict(zip("аеорсхуіјѕԁԍһⅰⅼ", "aeopcxyijsdghil", strict=True)),
        **dict(zip("οαρνυɑɡ", "oapvuag", strict=True)),
        **dict(
            zip("ıɪʟᴀʙᴄᴅᴇꜰɢʜᴊᴋᴍɴᴏᴘʀꜱᴛᴜᴠᴡʏᴢ", "iilabcdefghjkmnoprstuvwyz", strict=True)
        ),  # dotless i, small capitals
    }
)
