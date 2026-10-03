"""End-to-end integration tests validating the full analysis pipeline."""

from pathlib import Path
import pytest

from errataguard.config import CPUInfo
from errataguard.elf.parser import parse_elf
from errataguard.rules.loader import load_rules
from errataguard.analysis.verifier import StaticVerifier, compare_reports
from tests.fixtures.elf_generator import (
    create_vulnerable_fixture,
    create_fixed_fixture,
    create_negative_fixture,
)


@pytest.fixture(scope="module")
def rules():
    rules_dir = Path("rules/demo")
    return load_rules(rules_dir)


@pytest.fixture(scope="module")
def vulnerable_elf(tmp_path_factory):
    p = tmp_path_factory.mktemp("bins") / "vulnerable.elf"
    return create_vulnerable_fixture(p)


@pytest.fixture(scope="module")
def fixed_elf(tmp_path_factory):
    p = tmp_path_factory.mktemp("bins") / "fixed.elf"
    return create_fixed_fixture(p)


@pytest.fixture(scope="module")
def negative_elf(tmp_path_factory):
    p = tmp_path_factory.mktemp("bins") / "negative.elf"
    return create_negative_fixture(p)


def test_pipeline_positive_vulnerable(rules, vulnerable_elf):
    cpu = CPUInfo(architecture="AArch64", model="cortex-a53", revision="r0p2")
    elf = parse_elf(vulnerable_elf)
    verifier = StaticVerifier(rules=rules, cpu=cpu)

    report = verifier.analyze(elf)
    assert report.result == "FAIL"
    assert report.exit_code == 1
    assert len(report.findings) == 1

    finding = report.findings[0]
    assert finding.erratum_id == "A53-DEMO-001"
    assert finding.address == 0x40082C
    assert finding.source_file == "demo.c"
    assert finding.source_line == 7
    assert finding.function == "process_data"
    assert finding.confidence == "Static match"


def test_pipeline_fixed_binary(rules, fixed_elf):
    cpu = CPUInfo(architecture="AArch64", model="cortex-a53", revision="r0p2")
    elf = parse_elf(fixed_elf)
    verifier = StaticVerifier(rules=rules, cpu=cpu)

    report = verifier.analyze(elf)
    assert report.result == "PASS"
    assert report.exit_code == 0
    assert len(report.findings) == 0


def test_pipeline_negative_binary(rules, negative_elf):
    cpu = CPUInfo(architecture="AArch64", model="cortex-a53", revision="r0p2")
    elf = parse_elf(negative_elf)
    verifier = StaticVerifier(rules=rules, cpu=cpu)

    report = verifier.analyze(elf)
    assert report.result == "PASS"
    assert report.exit_code == 0
    assert len(report.findings) == 0


def test_pipeline_unaffected_revision(rules, vulnerable_elf):
    # r0p4 is unaffected by A53-DEMO-001
    cpu = CPUInfo(architecture="AArch64", model="cortex-a53", revision="r0p4")
    elf = parse_elf(vulnerable_elf)
    verifier = StaticVerifier(rules=rules, cpu=cpu)

    report = verifier.analyze(elf)
    assert report.result == "PASS"
    assert report.exit_code == 0
    assert len(report.findings) == 0


def test_pipeline_missing_cpu_revision(rules, vulnerable_elf):
    cpu = CPUInfo(architecture="AArch64", model="cortex-a53", revision=None)
    elf = parse_elf(vulnerable_elf)
    verifier = StaticVerifier(rules=rules, cpu=cpu)

    report = verifier.analyze(elf)
    # When sequence matches but revision is unknown, confidence indicates incomplete check
    assert len(report.findings) == 1
    assert "Incomplete CPU verification" in report.findings[0].confidence


def test_before_after_verification_comparison(rules, vulnerable_elf, fixed_elf):
    cpu = CPUInfo(architecture="AArch64", model="cortex-a53", revision="r0p2")
    verifier = StaticVerifier(rules=rules, cpu=cpu)

    report_before = verifier.analyze(parse_elf(vulnerable_elf))
    report_after = verifier.analyze(parse_elf(fixed_elf))

    comparison = compare_reports(report_before, report_after)
    assert comparison.result == "PASS"
    assert comparison.exit_code == 0
    assert len(comparison.resolved_findings) == 1
    assert comparison.resolved_findings[0].erratum_id == "A53-DEMO-001"
    assert len(comparison.remaining_findings) == 0
