"""IssueTrap: flag prompt-injection payloads aimed at AI agents in GitHub issues, PRs and comments."""

from .scanner import Finding, ScanResult, scan_text

__all__ = ["Finding", "ScanResult", "scan_text"]
__version__ = "0.1.0"
