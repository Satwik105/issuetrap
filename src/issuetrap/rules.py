"""Detection rules.

Each regex rule matches against normalised text (NFKC, invisible characters removed,
lower-cased). Weights: low = 1, medium = 3, high = 5. A single high finding is enough
to flag a document at the default threshold of 5.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

LOW, MEDIUM, HIGH = 1, 3, 5
SEVERITY_NAMES = {LOW: "low", MEDIUM: "medium", HIGH: "high"}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    weight: int
    description: str
    pattern: re.Pattern[str] | None = None
    # Skip a match when the words just before it negate it ("never print your token").
    negatable: bool = False

    @property
    def severity(self) -> str:
        return SEVERITY_NAMES[self.weight]


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


# Words that tell us a sentence is talking to an AI system.
_AI = r"(?:ai|a\.i\.|llm|language model|agent|assistant|bot|copilot|claude|chatgpt|gpt(?:-\d)?|gemini|cursor|devin|codex)"

REGEX_RULES: list[Rule] = [
    Rule(
        "IT001",
        "instruction-override",
        HIGH,
        "Tells the reader to ignore or replace its earlier instructions.",
        _rx(
            r"\b(?:ignore|disregard|forget|override|bypass|skip)\b[^.\n]{0,40}?"
            r"\b(?:previous|prior|above|earlier|preceding|original|initial|all|your|system)\b[^.\n]{0,20}?"
            r"\b(?:instructions?|prompts?|rules|directions|guidelines|context|guardrails|policies)\b"
        ),
    ),
    Rule(
        "IT002",
        "role-impersonation",
        HIGH,
        "Fake system, developer or chat-template markers that try to start a new conversation turn.",
        _rx(
            r"(?:^\s*(?:system|assistant|developer)\s*:\s*\S"
            r"|<\|im_start\|>|<\|im_end\|>|<\|system\|>|\[/?inst\]|<</?sys>>"
            r"|</?system(?:[-_ ]prompt)?>|\bnew (?:system )?instructions\s*:"
            r"|\byou are now (?:a|an|in)\b|\b(?:developer|god|dan|jailbreak) mode\b)"
        ),
    ),
    Rule(
        "IT003",
        "agent-addressing",
        MEDIUM,
        "Speaks directly to an AI agent reading the text.",
        _rx(
            rf"(?:\b(?:if|when) you are an? {_AI}\b"
            rf"|\b(?:note|message|attention|instructions?) (?:to|for) (?:any |all |the )?{_AI}s?\b"
            rf"|\b(?:dear|hey|hi|attention)\s+{_AI}s?\b"
            rf"|\b{_AI}s? (?:reading|processing|triaging|reviewing) this\b)"
        ),
    ),
    Rule(
        "IT004",
        "secret-exfiltration",
        HIGH,
        "Asks for secrets, tokens or environment variables to be printed or sent somewhere.",
        _rx(
            r"\b(?:print|reveal|output|echo|send|post|leak|exfiltrate|upload|dump|cat|expose)\b"
            r"[^.\n]{0,60}?"
            r"(?:\bsecrets?\b|\btokens?\b|\bapi[ _-]?keys?\b|\bcredentials?\b|\bpasswords?\b"
            r"|\benv(?:ironment)? var(?:iable)?s?\b|\.env\b|github_token|\bssh keys?\b|id_rsa|\bprivate keys?\b)"
        ),
        negatable=True,
    ),
    Rule(
        "IT005",
        "dangerous-command",
        HIGH,
        "Shell commands that download and run code, or destroy data.",
        _rx(
            r"(?:\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"
            r"|\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(?:/|~|\$home)(?:\s|$)"
            r"|\bbase64\s+(?:-d|--decode)\b[^\n]{0,80}\|\s*(?:ba)?sh\b"
            r"|\bpowershell(?:\.exe)?\b[^\n]{0,40}-(?:e|enc|encodedcommand)\s"
            r"|\bnc\s+(?:-e|-c)\b"
            r"|\bchmod\s+\+x\b[^\n]{0,80}&&\s*\./)"
        ),
    ),
    Rule(
        "IT008",
        "markdown-exfil-link",
        MEDIUM,
        "Image or link whose URL is built to carry data out (template variables or secret-like parameters).",
        _rx(
            r"!?\[[^\]]{0,100}\]\(\s*https?://[^)\s]*"
            r"(?:\{\{?|\$\{|%7b|[?&](?:data|q|secret|token|key|env|payload|leak)=)"
        ),
    ),
    Rule(
        "IT012",
        "secret-in-url",
        HIGH,
        "A URL that references secrets, Actions expressions or environment variables, so loading it leaks them.",
        _rx(
            r"https?://[^\s)\"'>]*(?:secrets\.|\$\{\{|\{\{\s*(?:secrets|env)|github_token|process\.env"
            r"|\$env:|%24%7b%7b|\$\(\s*(?:cat|env|printenv))"
        ),
    ),
    Rule(
        "IT010",
        "repo-tampering",
        MEDIUM,
        "Asks an agent to change CI, approve, merge or alter permissions.",
        _rx(
            r"(?:\b(?:modify|edit|update|change|add|delete|disable|remove)\b[^.\n]{0,40}"
            r"(?:\.github/workflows|\bworkflow files?\b|\bbranch protection\b|codeowners)"
            r"|\b(?:approve|merge)\b[^.\n]{0,20}\b(?:this|the) (?:pr|pull request)\b[^.\n]{0,40}\b(?:immediately|without|now|automatically)\b"
            r"|\b(?:grant|give|add)\b[^.\n]{0,30}\b(?:admin|write|maintain(?:er)?) (?:access|permissions?|rights)\b)"
        ),
        negatable=True,
    ),
    Rule(
        "IT011",
        "conceal-from-user",
        HIGH,
        "Tells the agent to hide what it is doing from the human.",
        _rx(
            r"(?:\b(?:do not|don't|never)\s+(?:tell|mention|inform|alert|notify|reveal (?:this )?to|show)\b[^.\n]{0,20}"
            r"\b(?:the )?(?:user|human|maintainers?|owner|reviewer)s?\b"
            r"|\bwithout (?:telling|informing|alerting|notifying) (?:the )?(?:user|human|maintainers?|owner)s?\b"
            r"|\bkeep this (?:secret|hidden|between us)\b|\bdo not (?:mention|reveal) (?:these|this|the) instructions\b)"
        ),
    ),
]

# Rules implemented in code rather than a single regex (see scanner.py).
HIDDEN_UNICODE = Rule(
    "IT006",
    "hidden-unicode",
    MEDIUM,
    "Zero-width, bidirectional-override or Unicode tag characters that hide text from humans.",
)
HIDDEN_COMMENT = Rule(
    "IT007",
    "hidden-html-comment",
    HIGH,
    "An HTML comment (invisible when rendered on GitHub) that contains instructions.",
)
ENCODED_PAYLOAD = Rule(
    "IT009",
    "encoded-payload",
    HIGH,
    "A base64 blob that decodes to text matching another rule.",
)

ALL_RULES: list[Rule] = sorted(
    [*REGEX_RULES, HIDDEN_UNICODE, HIDDEN_COMMENT, ENCODED_PAYLOAD], key=lambda r: r.id
)

# Characters that render as nothing (or reorder text) in most viewers.
INVISIBLE_CODEPOINTS: set[int] = {
    0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x180E,  # zero-width / soft hyphen
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # bidi embeddings and overrides
    0x2066, 0x2067, 0x2068, 0x2069,  # bidi isolates
}


def is_invisible(ch: str) -> bool:
    cp = ord(ch)
    return cp in INVISIBLE_CODEPOINTS or 0xE0000 <= cp <= 0xE007F  # Unicode tag block


# Words that make an HTML comment look like instructions rather than a normal template note.
COMMENT_TRIGGER = _rx(
    rf"\b(?:ignore|disregard|instructions?|you must|you should|you are|{_AI}|system prompt|do not tell|secret|token)\b"
)

NEGATION_BEFORE = _rx(r"\b(?:don'?t|do not|never|must not|should not|shouldn'?t|not to|avoid)\s+(?:\w+\s+){0,2}$")
