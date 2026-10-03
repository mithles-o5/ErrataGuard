"""Terminal text formatter for ErrataGuard reports."""

import sys
from typing import TextIO

from errataguard import __version__
from errataguard.reporting.models import AnalysisReport, VerificationComparison


def render_terminal_report(report: AnalysisReport, stream: TextIO = sys.stdout) -> None:
    """Format and write human-readable analysis report to stream."""
    lines: list[str] = [
        f"ErrataGuard v{__version__}",
        "==================",
        "Binary:",
        f"    {report.binary_path.name}",
        "Architecture:",
        f"    {report.target_cpu.architecture}",
        "CPU:",
        f"    {report.target_cpu.model} {report.target_cpu.revision or '(revision unspecified)'}",
        "Audit:",
        f"    Binary SHA-256: {report.binary_sha256}",
        f"    Rule set hash:  {report.rules_hash}",
        f"    Timestamp:      {report.timestamp}",
        "Rules:",
        f"    {report.rules_loaded} loaded",
        "Analysis:",
        f"    Instructions scanned: {report.statistics.instructions_scanned:,}",
        f"    Candidates: {report.statistics.candidates_found:,}",
        f"    Detailed checks: {report.statistics.detailed_checks:,}",
        f"    Duration: {report.statistics.duration_seconds:.4f}s",
        "Result:",
        f"    {report.result} (exit code: {report.exit_code})",
    ]

    if report.result == "PASS":
        lines.extend([
            "",
            "No statically detectable supported trigger conditions were found in the analyzed binary.",
        ])
    elif report.result == "INCOMPLETE":
        lines.extend([
            "",
            "Notice: CPU revision required for complete verification. Specify with --revision <rev>.",
        ])

    if report.findings:
        lines.append("")
        lines.append("Findings:")
        lines.append("-" * 50)
        for finding in report.findings:
            func_str = f"{finding.function}()" if finding.function else "<unknown>"
            lines.append(f"[{finding.erratum_id}] {finding.title}")
            lines.append("Address:")
            lines.append(f"    0x{finding.address:08X}")
            lines.append("Function:")
            lines.append(f"    {func_str}")
            lines.append("Source:")
            lines.append(f"    {finding.source_display}")
            lines.append("Matched conditions:")
            for cond in finding.matched_conditions:
                lines.append(f"    ✓ {cond}")
            if finding.matched_instructions:
                lines.append("Matched instructions:")
                for insn_str in finding.matched_instructions:
                    lines.append(f"    {insn_str}")
            lines.append("Workaround:")
            lines.append(f"    {finding.workaround}")
            if finding.references:
                lines.append("References:")
                for ref in finding.references:
                    lines.append(f"    - {ref}")
            lines.append("Confidence:")
            lines.append(f"    {finding.confidence}")
            lines.append("-" * 50)

    lines.extend([
        "",
        "Static analysis only: does not establish runtime triggering.",
    ])

    stream.write("\n".join(lines) + "\n")



def render_verification_report(comparison: VerificationComparison, stream: TextIO = sys.stdout) -> None:
    """Format and write before/after verification report."""
    resolved_ids = sorted(list({f.erratum_id for f in comparison.resolved_findings}))
    remaining_ids = sorted(list({f.erratum_id for f in comparison.remaining_findings}))

    lines: list[str] = [
        "ErrataGuard Verification",
        "========================",
        "Before findings:",
        f"    {len(comparison.before_report.findings)}",
        "After findings:",
        f"    {len(comparison.after_report.findings)}",
        "Resolved:",
        f"    {', '.join(resolved_ids) if resolved_ids else 'None'}",
    ]

    if remaining_ids:
        lines.extend([
            "Remaining:",
            f"    {', '.join(remaining_ids)}",
        ])

    lines.extend([
        "Result:",
        f"    {comparison.result}",
        "Interpretation:",
    ])

    if comparison.result == "PASS":
        lines.append("    The documented statically detectable trigger condition is no longer present in the analyzed binary.")
    else:
        lines.append("    One or more documented trigger conditions remain present in the analyzed binary.")

    stream.write("\n".join(lines) + "\n")
