"""Data models for analysis findings, execution statistics, and verification results."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence

from errataguard.config import CPUInfo


@dataclass(frozen=True)
class Finding:
    """A detected erratum trigger instance backed by static evidence."""
    erratum_id: str
    title: str
    address: int
    function: Optional[str]
    source_file: Optional[str]
    source_line: Optional[int]
    matched_conditions: tuple[str, ...]
    cpu: CPUInfo
    workaround: str
    references: tuple[str, ...]
    confidence: str

    @property
    def source_display(self) -> str:
        if self.source_file and self.source_line is not None:
            return f"{self.source_file}:{self.source_line}"
        return "unavailable"


@dataclass
class AnalysisStatistics:
    """Execution metrics and stage timings."""
    instructions_scanned: int = 0
    candidates_found: int = 0
    detailed_checks: int = 0
    duration_seconds: float = 0.0
    stage_durations: dict[str, float] = field(default_factory=dict)


@dataclass
class AnalysisReport:
    """Complete summary of an analysis run."""
    binary_path: Path
    binary_sha256: str
    target_cpu: CPUInfo
    rules_loaded: int
    statistics: AnalysisStatistics
    findings: list[Finding]
    result: str  # "PASS", "FAIL", or "INCOMPLETE"

    @property
    def is_pass(self) -> bool:
        return len(self.findings) == 0 and self.result == "PASS"

    @property
    def exit_code(self) -> int:
        if self.result == "FAIL":
            return 1
        elif self.result == "INCOMPLETE":
            return 2
        return 0


@dataclass
class VerificationComparison:
    """Before vs After comparison results."""
    before_report: AnalysisReport
    after_report: AnalysisReport
    resolved_findings: list[Finding]
    remaining_findings: list[Finding]
    new_findings: list[Finding]
    result: str  # "PASS" or "FAIL"

    @property
    def exit_code(self) -> int:
        return 0 if self.result == "PASS" else 1
