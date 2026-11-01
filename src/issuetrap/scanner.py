"""Core scanner: turns a piece of text into findings and a risk score."""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import asdict, dataclass, field

from . import rules as R

DEFAULT_THRESHOLD = 5
MAX_FINDINGS_PER_RULE = 5
MAX_DEPTH = 2  # how many layers of encoding / hidden text to unwrap

_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


@dataclass
class Finding:
    rule_id: str
    rule: str
    severity: str
    weight: int
    line: int
    snippet: str
    source: str = "text"  # where it was found: text, hidden-unicode, base64, etc.
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    label: str
    findings: list[Finding] = field(default_factory=list)
    threshold: int = DEFAULT_THRESHOLD

    @property
    def score(self) -> int:
        """Sum of weights of the distinct rules that fired (repeats of one rule don't stack)."""
        best: dict[str, int] = {}
        for f in self.findings:
            best[f.rule_id] = max(best.get(f.rule_id, 0), f.weight)
        return sum(best.values())

    @property
    def flagged(self) -> bool:
        return self.score >= self.threshold

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "flagged": self.flagged,
            "score": self.score,
            "threshold": self.threshold,
            "findings": [f.to_dict() for f in self.findings],
        }


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _invisible_marker(m: re.Match[str]) -> str:
    run = m.group(0)
    if len(run) == 1:
        return f"<U+{ord(run):04X}>"
    return f"<{len(run)} hidden chars>"


def _snippet(text: str, start: int, end: int, width: int = 40) -> str:
    lo, hi = max(0, start - width), min(len(text), end + width)
    s = re.sub(
        "[" + "".join(map(chr, sorted(R.INVISIBLE_CODEPOINTS))) + "\U000E0000-\U000E007F]+",
        _invisible_marker,
        text[lo:hi],
    )
    s = " ".join(s.split())
    return ("…" if lo > 0 else "") + s + ("…" if hi < len(text) else "")


def normalise(text: str) -> str:
    """NFKC-normalise (folds full-width and other look-alike forms) and drop invisible characters."""
    text = unicodedata.normalize("NFKC", text)
    return "".join(c for c in text if not R.is_invisible(c))


def _decode_tag_chars(text: str) -> str:
    """Unicode 'tag' characters (U+E0020–U+E007E) mirror ASCII and render as nothing.
    Attackers use them to smuggle whole sentences. Recover that text."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def _try_base64(blob: str) -> str | None:
    padded = blob + "=" * (-len(blob) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(c.isprintable() or c.isspace() for c in decoded)
    if not decoded or printable / len(decoded) < 0.9 or not re.search(r"[a-zA-Z]{3,}\s", decoded):
        return None
    return decoded


def _scan(text: str, source: str, depth: int) -> list[Finding]:
    findings: list[Finding] = []

    # IT006: invisible characters in the raw text.
    hidden = [(i, c) for i, c in enumerate(text) if R.is_invisible(c)]
    # A lone BOM at the very start is harmless (common in files saved on Windows).
    hidden = [(i, c) for i, c in hidden if not (i == 0 and c == "﻿")]
    if hidden:
        first = hidden[0][0]
        kinds = sorted({f"U+{ord(c):04X}" for _, c in hidden})[:6]
        weight = R.HIGH if len(hidden) >= 10 else R.HIDDEN_UNICODE.weight
        findings.append(
            Finding(
                R.HIDDEN_UNICODE.id, R.HIDDEN_UNICODE.name, R.SEVERITY_NAMES[weight], weight,
                _line_of(text, first), _snippet(text, first, first + 1), source,
                f"{len(hidden)} invisible character(s): {', '.join(kinds)}",
            )
        )
        smuggled = _decode_tag_chars(text)
        if smuggled.strip() and depth < MAX_DEPTH:
            for inner in _scan(smuggled, "hidden-unicode-tags", depth + 1):
                inner.line = _line_of(text, first)
                findings.append(inner)

    clean = normalise(text)

    # Regex rules.
    for rule in R.REGEX_RULES:
        assert rule.pattern is not None
        seen_lines: set[int] = set()
        for m in rule.pattern.finditer(clean):
            if rule.negatable:
                before = clean[max(0, m.start() - 40):m.start()].rsplit("\n", 1)[-1]
                if R.NEGATION_BEFORE.search(before):
                    continue
            line = _line_of(clean, m.start())
            if line in seen_lines:  # one finding per rule per line keeps reports readable
                continue
            seen_lines.add(line)
            findings.append(
                Finding(rule.id, rule.name, rule.severity, rule.weight,
                        line, _snippet(clean, m.start(), m.end()), source)
            )
            if len(seen_lines) >= MAX_FINDINGS_PER_RULE:
                break

    # IT007: instructions hidden in HTML comments.
    for m in _COMMENT_RE.finditer(clean):
        body = m.group(1)
        if R.COMMENT_TRIGGER.search(body):
            r = R.HIDDEN_COMMENT
            findings.append(
                Finding(r.id, r.name, r.severity, r.weight, _line_of(clean, m.start()),
                        _snippet(clean, m.start(), m.end(), width=0)[:200], source,
                        "invisible when GitHub renders the Markdown")
            )

    # IT009: base64 blobs that decode to something malicious.
    if depth < MAX_DEPTH:
        for m in _BASE64_RE.finditer(clean):
            decoded = _try_base64(m.group(0))
            if decoded is None:
                continue
            inner = _scan(decoded, "base64", depth + 1)
            if inner:
                r = R.ENCODED_PAYLOAD
                ids = sorted({f.rule_id for f in inner})
                findings.append(
                    Finding(r.id, r.name, r.severity, r.weight, _line_of(clean, m.start()),
                            _snippet(clean, m.start(), m.end(), width=0)[:120], source,
                            f"decodes to text matching {', '.join(ids)}: {' '.join(decoded.split())[:100]!r}")
                )
                for f in inner:
                    f.line = _line_of(clean, m.start())
                    findings.append(f)

    return findings


def scan_text(text: str, label: str = "<text>", threshold: int = DEFAULT_THRESHOLD) -> ScanResult:
    """Scan a piece of text and return its findings and risk score."""
    findings = _scan(text or "", "text", 0)
    findings.sort(key=lambda f: (f.line, -f.weight, f.rule_id))
    return ScanResult(label=label, findings=findings, threshold=threshold)
