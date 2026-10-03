"""Reporting package for ErrataGuard."""

from errataguard.reporting.models import (
    Finding,
    AnalysisStatistics,
    AnalysisReport,
    VerificationComparison,
)
from errataguard.reporting.terminal import (
    render_terminal_report,
    render_verification_report,
)
from errataguard.reporting.json import (
    format_json_report,
    format_json_comparison,
    to_dict_report,
)
from errataguard.reporting.sarif import format_sarif_report

__all__ = [
    "Finding",
    "AnalysisStatistics",
    "AnalysisReport",
    "VerificationComparison",
    "render_terminal_report",
    "render_verification_report",
    "format_json_report",
    "format_json_comparison",
    "to_dict_report",
    "format_sarif_report",
]
