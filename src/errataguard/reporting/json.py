"""Machine-readable JSON formatter for ErrataGuard reports."""

import json
from typing import Any

from errataguard import __version__
from errataguard.reporting.models import AnalysisReport, VerificationComparison


def to_dict_report(report: AnalysisReport) -> dict[str, Any]:
    """Convert AnalysisReport to JSON-serializable dictionary."""
    findings_data = []
    for f in report.findings:
        findings_data.append({
            "erratum_id": f.erratum_id,
            "title": f.title,
            "address": f"0x{f.address:08X}",
            "function": f.function,
            "source": {
                "file": f.source_file,
                "line": f.source_line,
            },
            "matched_conditions": list(f.matched_conditions),
            "cpu": {
                "architecture": f.cpu.architecture,
                "model": f.cpu.model,
                "revision": f.cpu.revision,
            },
            "workaround": f.workaround,
            "references": list(f.references),
            "confidence": f.confidence,
            "matched_instructions": list(f.matched_instructions),
        })

    return {
        "tool": {
            "name": "ErrataGuard",
            "version": __version__,
        },
        "audit": {
            "binary_sha256": report.binary_sha256,
            "rules_hash": report.rules_hash,
            "timestamp": report.timestamp,
        },
        "binary": {
            "path": str(report.binary_path),
            "sha256": report.binary_sha256,
        },
        "target": {
            "architecture": report.target_cpu.architecture,
            "cpu": report.target_cpu.model,
            "revision": report.target_cpu.revision,
        },
        "statistics": {
            "instructions": report.statistics.instructions_scanned,
            "candidates": report.statistics.candidates_found,
            "detailed_checks": report.statistics.detailed_checks,
            "duration_seconds": round(report.statistics.duration_seconds, 6),
            "stage_durations": {k: round(v, 6) for k, v in report.statistics.stage_durations.items()},
        },
        "result": report.result,
        "exit_code": report.exit_code,
        "note": "Static analysis only: does not establish runtime triggering.",
        "findings": findings_data,
    }



def to_dict_comparison(comp: VerificationComparison) -> dict[str, Any]:
    """Convert VerificationComparison to JSON-serializable dictionary."""
    return {
        "tool": {
            "name": "ErrataGuard",
            "version": __version__,
        },
        "before": to_dict_report(comp.before_report),
        "after": to_dict_report(comp.after_report),
        "resolved_errata": sorted(list({f.erratum_id for f in comp.resolved_findings})),
        "remaining_errata": sorted(list({f.erratum_id for f in comp.remaining_findings})),
        "new_errata": sorted(list({f.erratum_id for f in comp.new_findings})),
        "result": comp.result,
    }


def format_json_report(report: AnalysisReport, indent: int = 2) -> str:
    """Format AnalysisReport as indented JSON string."""
    return json.dumps(to_dict_report(report), indent=indent)


def format_json_comparison(comp: VerificationComparison, indent: int = 2) -> str:
    """Format VerificationComparison as indented JSON string."""
    return json.dumps(to_dict_comparison(comp), indent=indent)
