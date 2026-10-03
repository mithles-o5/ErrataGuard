"""Unit tests for reporting formats (Terminal, JSON, SARIF)."""

import io
import json
from pathlib import Path

from errataguard.config import CPUInfo
from errataguard.reporting.models import Finding, AnalysisReport, AnalysisStatistics
from errataguard.reporting.terminal import render_terminal_report
from errataguard.reporting.json import format_json_report
from errataguard.reporting.sarif import format_sarif_report


def create_dummy_report(has_findings: bool = True) -> AnalysisReport:
    cpu = CPUInfo(architecture="AArch64", model="cortex-a53", revision="r0p2")
    stats = AnalysisStatistics(
        instructions_scanned=100,
        candidates_found=1 if has_findings else 0,
        detailed_checks=1 if has_findings else 0,
        duration_seconds=0.0123,
    )
    findings = []
    if has_findings:
        findings.append(
            Finding(
                erratum_id="A53-DEMO-001",
                title="Demo vulnerability",
                address=0x40082C,
                function="process_data",
                source_file="demo.c",
                source_line=7,
                matched_conditions=("candidate instruction 'adrp'", "CPU revision affected (r0p2)"),
                cpu=cpu,
                workaround="Insert NOP",
                references=("DEMO REF",),
                confidence="Static match",
            )
        )

    return AnalysisReport(
        binary_path=Path("dummy.elf"),
        binary_sha256="abc123456789",
        target_cpu=cpu,
        rules_loaded=2,
        statistics=stats,
        findings=findings,
        result="FAIL" if has_findings else "PASS",
    )


def test_terminal_report_output():
    report = create_dummy_report(has_findings=True)
    buf = io.StringIO()
    render_terminal_report(report, buf)
    output = buf.getvalue()
    assert "ErrataGuard v" in output
    assert "Result:\n    FAIL" in output
    assert "[A53-DEMO-001]" in output
    assert "0x0040082C" in output
    assert "demo.c:7" in output


def test_terminal_report_pass_output():
    report = create_dummy_report(has_findings=False)
    buf = io.StringIO()
    render_terminal_report(report, buf)
    output = buf.getvalue()
    assert "Result:\n    PASS" in output
    assert "No statically detectable supported trigger conditions were found" in output


def test_json_report_structure():
    report = create_dummy_report(has_findings=True)
    raw_json = format_json_report(report)
    data = json.loads(raw_json)

    assert data["tool"]["name"] == "ErrataGuard"
    assert data["result"] == "FAIL"
    assert data["binary"]["sha256"] == "abc123456789"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["erratum_id"] == "A53-DEMO-001"
    assert data["findings"][0]["source"]["file"] == "demo.c"
    assert data["findings"][0]["source"]["line"] == 7


def test_sarif_report_structure():
    report = create_dummy_report(has_findings=True)
    raw_sarif = format_sarif_report(report)
    data = json.loads(raw_sarif)

    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "ErrataGuard"
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleId"] == "A53-DEMO-001"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 7
