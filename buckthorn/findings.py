"""The finding record and the verdict it rolls up to.

Same shape and verdict names as Hayward, so a tool that reads one can read the
other. Kept local for now rather than depending on `hayward`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """One statement about one file inside a package."""

    rule_id: str
    message: str
    severity: Severity
    file_path: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "severity": self.severity.value,
            "file": self.file_path,
            "metadata": self.metadata,
        }


# Rules that mean "this was not fully read". Never a clean verdict.
COVERAGE_RULE_IDS = frozenset(
    {
        "BKT-SKIP-001",  # archive would not open
        "BKT-SKIP-002",  # an archive limit was hit
        "BKT-SKIP-003",  # a metadata or Python file could not be parsed
        "BKT-SKIP-004",  # a link inside an archive or an environment, not followed
        "BKT-SKIP-005",  # an installed distribution with no RECORD
        "BKT-SKIP-006",  # a model repo's config or remote code could not be read or fetched
        "BKT-LOCK-002",  # a pinned artifact could not be found, fetched or named safely
        "BKT-MCP-001",  # what an MCP server runs could not be checked
        "BKT-MCP-005",  # an MCP server's dependencies could not be checked
    }
)


def verdict(findings: list[Finding]) -> str:
    """clean, flagged or not_verified. A detection wins over a coverage gap."""
    if any(f.severity != Severity.INFO and f.rule_id not in COVERAGE_RULE_IDS for f in findings):
        return "flagged"
    if any(f.rule_id in COVERAGE_RULE_IDS for f in findings):
        return "not_verified"
    return "clean"


@dataclass
class Result:
    """The findings for one artifact, named by its path or file name."""

    path: str
    sha256: str
    findings: list[Finding]
    allowed: list[tuple[Finding, str]] = field(default_factory=list)  # (finding, reason)
    source: str = ""  # the file in the repository it came from (a lockfile), if any

    @property
    def verdict(self) -> str:
        return verdict(self.findings)


def new_findings(
    old: list[Finding], new: list[Finding], old_version: str, new_version: str
) -> list[Finding]:
    """Findings in new that old does not have: what an upgrade adds.

    Paths and messages are compared with each side's version taken out, so
    pkg-1.0/setup.py and pkg-1.1/setup.py are the same file. The hashes of the
    lines a finding was seen on are compared too. A finding whose message or lines
    changed (another call of a kind already reported) counts as new; one that
    only moved does not. Without line hashes, the number of lines is compared.
    Coverage gaps are always kept: what was not read in the old version says
    nothing about the new one.
    """

    def key(finding: Finding, version: str) -> tuple[object, ...]:
        first, sep, rest = finding.file_path.partition("/")
        path = first.replace(f"-{version}", "") + sep + rest
        hashes = sorted(finding.metadata.get("line_hashes") or ())
        count = len(finding.metadata.get("lines") or ())
        return finding.rule_id, path, finding.message.replace(version, ""), str(hashes), count

    seen = {key(f, old_version) for f in old}
    return [f for f in new if f.rule_id in COVERAGE_RULE_IDS or key(f, new_version) not in seen]
