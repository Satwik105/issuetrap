"""Helpers for running inside GitHub Actions: reading the event payload and writing outputs."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from .scanner import ScanResult


@dataclass
class Item:
    label: str  # e.g. "issue #12" or "comment on PR #7"
    text: str
    number: int | None = None


def items_from_event(event: dict, event_name: str | None = None) -> list[Item]:
    """Pull every piece of user-written text out of a GitHub webhook payload."""
    items: list[Item] = []

    def add(label: str, *parts: str | None, number: int | None = None) -> None:
        text = "\n\n".join(p for p in parts if p)
        if text.strip():
            items.append(Item(label, text, number))

    issue = event.get("issue") or {}
    pr = event.get("pull_request") or {}
    is_pr_issue = "pull_request" in issue
    number = issue.get("number") or pr.get("number")
    kind = "PR" if (pr or is_pr_issue) else "issue"

    if "comment" in event:
        add(f"comment on {kind} #{number}", event["comment"].get("body"), number=number)
    elif "review" in event:
        add(f"review on PR #{number}", event["review"].get("body"), number=number)
    elif pr:
        add(f"PR #{number}", pr.get("title"), pr.get("body"), number=number)
    elif issue:
        add(f"issue #{number}", issue.get("title"), issue.get("body"), number=number)
    elif "discussion" in event:
        d = event["discussion"]
        add(f"discussion #{d.get('number')}", d.get("title"), d.get("body"), number=d.get("number"))

    return items


def load_event(path: str | os.PathLike[str]) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _escape(value: str) -> str:
    """Escape a value for a GitHub workflow command."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def annotations(result: ScanResult) -> list[str]:
    """Workflow-command lines that show up as warnings or errors on the run page."""
    lines = []
    for f in result.findings:
        level = "error" if f.weight >= 5 else "warning"
        title = f"IssueTrap {f.rule_id} {f.rule}"
        msg = f"{result.label}, line {f.line}: {f.snippet}"
        if f.detail:
            msg += f" ({f.detail})"
        lines.append(f"::{level} title={_escape(title)}::{_escape(msg)}")
    return lines


def markdown_summary(results: list[ScanResult]) -> str:
    out = ["## IssueTrap scan", ""]
    for r in results:
        status = "🚩 **Flagged**" if r.flagged else "✅ Clean"
        out.append(f"### {r.label}: {status} (score {r.score}, threshold {r.threshold})")
        out.append("")
        if r.findings:
            out.append("| Rule | Severity | Line | Evidence |")
            out.append("|---|---|---|---|")
            for f in r.findings:
                ev = f.snippet.replace("|", "\\|").replace("`", "'")
                extra = f" ({f.detail})" if f.detail else ""
                src = "" if f.source == "text" else f" [{f.source}]"
                out.append(f"| {f.rule_id} {f.rule} | {f.severity} | {f.line} | `{ev}`{extra}{src} |")
            out.append("")
    return "\n".join(out) + "\n"


def write_step_outputs(results: list[ScanResult]) -> None:
    """Set step outputs and the job summary when running in Actions."""
    flagged = any(r.flagged for r in results)
    score = max((r.score for r in results), default=0)
    if path := os.environ.get("GITHUB_OUTPUT"):
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"flagged={'true' if flagged else 'false'}\n")
            fh.write(f"score={score}\n")
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(markdown_summary(results))
