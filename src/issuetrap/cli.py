"""Command-line interface.

    issuetrap scan FILE [FILE ...]      scan files ("-" reads stdin)
    issuetrap scan --text "..."         scan a string
    issuetrap event [EVENT.json]        scan a GitHub webhook payload (defaults to $GITHUB_EVENT_PATH)
    issuetrap rules                     list the detection rules

Exit codes: 0 clean, 1 something was flagged, 2 usage or input error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from . import github as gh
from .rules import ALL_RULES
from .scanner import DEFAULT_THRESHOLD, ScanResult, scan_text

_COLOURS = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "ok": "\033[32m", "end": "\033[0m"}


def _c(name: str, text: str, enabled: bool) -> str:
    return f"{_COLOURS[name]}{text}{_COLOURS['end']}" if enabled else text


def render_text(results: list[ScanResult], colour: bool) -> str:
    out = []
    for r in results:
        if r.flagged:
            head = _c("high", f"FLAGGED  {r.label}", colour)
        else:
            head = _c("ok", f"clean    {r.label}", colour)
        out.append(f"{head}  (score {r.score}, threshold {r.threshold})")
        for f in r.findings:
            sev = _c(f.severity, f"{f.severity:<6}", colour)
            src = "" if f.source == "text" else f" [{f.source}]"
            out.append(f"  {sev} {f.rule_id} {f.rule:<22} line {f.line:<4} {f.snippet}{src}")
            if f.detail:
                out.append(f"         {f.detail}")
    return "\n".join(out)


def emit(results: list[ScanResult], fmt: str) -> None:
    if fmt == "json":
        payload = [r.to_dict() for r in results]
        print(json.dumps(payload if len(payload) != 1 else payload[0], indent=2, ensure_ascii=False))
    elif fmt == "github":
        for r in results:
            for line in gh.annotations(r):
                print(line)
        print(render_text(results, colour=False))
        gh.write_step_outputs(results)
    else:
        colour = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        print(render_text(results, colour))


def _cmd_scan(args: argparse.Namespace) -> list[ScanResult]:
    results = []
    if args.text is not None:
        results.append(scan_text(args.text, "<text>", args.threshold))
    for path in args.paths:
        if path == "-":
            results.append(scan_text(sys.stdin.read(), "<stdin>", args.threshold))
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                results.append(scan_text(fh.read(), path, args.threshold))
        except OSError as exc:
            raise SystemExit(f"issuetrap: cannot read {path}: {exc.strerror}") from exc
    if not results:
        raise SystemExit("issuetrap: nothing to scan (give file paths, '-' for stdin, or --text)")
    return results


def _cmd_event(args: argparse.Namespace) -> list[ScanResult]:
    path = args.path or os.environ.get("GITHUB_EVENT_PATH")
    if not path:
        raise SystemExit("issuetrap: no event file given and $GITHUB_EVENT_PATH is not set")
    try:
        event = gh.load_event(path)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"issuetrap: cannot read event file {path}: {exc}") from exc
    items = gh.items_from_event(event)
    if not items:
        print("issuetrap: event has no user-written text to scan")
        return []
    return [scan_text(i.text, i.label, args.threshold) for i in items]


def _cmd_rules(_: argparse.Namespace) -> None:
    for r in ALL_RULES:
        print(f"{r.id}  {r.name:<22} {r.severity:<6}  {r.description}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="issuetrap",
        description="Flag prompt-injection payloads aimed at AI agents in issues, PRs and comments.",
    )
    p.add_argument("--version", action="version", version=f"issuetrap {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--format", choices=["text", "json", "github"], default="text")
    common.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD,
                        help=f"risk score at which text is flagged (default {DEFAULT_THRESHOLD})")
    common.add_argument("--no-fail", action="store_true", help="exit 0 even when something is flagged")

    s = sub.add_parser("scan", parents=[common], help="scan files, stdin or a string")
    s.add_argument("paths", nargs="*", help="files to scan; '-' reads stdin")
    s.add_argument("--text", help="scan this string")
    s.set_defaults(func=_cmd_scan)

    e = sub.add_parser("event", parents=[common], help="scan a GitHub Actions event payload")
    e.add_argument("path", nargs="?", help="event JSON (default: $GITHUB_EVENT_PATH)")
    e.set_defaults(func=_cmd_event)

    r = sub.add_parser("rules", help="list detection rules")
    r.set_defaults(func=_cmd_rules)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "rules":
        _cmd_rules(args)
        return 0
    try:
        results = args.func(args)
    except SystemExit as exc:
        if isinstance(exc.code, str):
            print(exc.code, file=sys.stderr)
            return 2
        raise
    emit(results, args.format)
    flagged = any(r.flagged for r in results)
    return 1 if flagged and not args.no_fail else 0


if __name__ == "__main__":
    sys.exit(main())
