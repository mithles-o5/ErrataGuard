"""Static analysis verification engine running baseline and optimized pipelines."""

import logging
import time
from pathlib import Path
from typing import Sequence, Optional

from errataguard.config import CPUInfo
from errataguard.elf.parser import ELFImage, parse_elf
from errataguard.disasm.aarch64 import AArch64Decoder, Instruction
from errataguard.analysis.candidate_filter import CandidateFilter
from errataguard.analysis.context import ContextBuilder
from errataguard.rules.schema import Rule
from errataguard.rules.evaluator import RuleEvaluator
from errataguard.reporting.models import Finding, AnalysisReport, AnalysisStatistics

logger = logging.getLogger(__name__)


class StaticVerifier:
    """Orchestrates instruction scanning, candidate filtering, and condition verification."""

    def __init__(
        self,
        rules: Sequence[Rule],
        cpu: CPUInfo,
        decoder: Optional[AArch64Decoder] = None,
        candidate_filter: Optional[CandidateFilter] = None,
        evaluator: Optional[RuleEvaluator] = None,
    ):
        self.rules = list(rules)
        self.cpu = cpu
        self.decoder = decoder or AArch64Decoder()
        self.candidate_filter = candidate_filter or CandidateFilter()
        self.evaluator = evaluator or RuleEvaluator()
        self.context_builder = ContextBuilder()

    def analyze(
        self,
        elf: ELFImage,
        baseline: bool = False,
    ) -> AnalysisReport:
        """
        Analyze an ELF binary.
        If baseline=True, evaluates every instruction directly without candidate pre-filtering.
        If baseline=False (default), applies fast candidate filtering first.
        """
        start_total = time.perf_counter()
        stats = AnalysisStatistics()

        # Step 1: Disassemble executable sections
        t0 = time.perf_counter()
        all_instructions: list[Instruction] = []
        for region in elf.executable_sections:
            sec_insns = self.decoder.decode_region(region, elf.symbol_table)
            all_instructions.extend(sec_insns)
        stats.stage_durations["disassembly"] = time.perf_counter() - t0
        stats.instructions_scanned = len(all_instructions)

        findings: list[Finding] = []
        has_incomplete_revision = False

        if baseline:
            # Baseline mode: Evaluate all rules on every single instruction
            t0 = time.perf_counter()
            stats.detailed_checks = len(all_instructions)
            stats.candidates_found = len(all_instructions)

            for idx, insn in enumerate(all_instructions):
                # Build context for this instruction
                context = self.context_builder.build_context(
                    all_instructions,
                    idx,
                    self.cpu,
                )
                for rule in self.rules:
                    match_result = self.evaluator.evaluate(rule, context)
                    if match_result and match_result.matched:
                        if match_result.incomplete_cpu_revision:
                            has_incomplete_revision = True
                        finding = self._create_finding(insn, rule, match_result, elf)
                        findings.append(finding)
            stats.stage_durations["evaluation"] = time.perf_counter() - t0

        else:
            # Optimized mode: Cheap candidate filter -> expensive contextual evaluation
            t0 = time.perf_counter()
            candidate_pairs: list[tuple[int, Instruction, Rule]] = []

            for idx, insn in enumerate(all_instructions):
                matching_rules = self.candidate_filter.candidate_rules(insn, self.rules)
                for r in matching_rules:
                    candidate_pairs.append((idx, insn, r))

            stats.stage_durations["candidate_filtering"] = time.perf_counter() - t0
            stats.candidates_found = len(candidate_pairs)
            stats.detailed_checks = len(candidate_pairs)

            t0 = time.perf_counter()
            for idx, insn, rule in candidate_pairs:
                context = self.context_builder.build_context(
                    all_instructions,
                    idx,
                    self.cpu,
                )
                match_result = self.evaluator.evaluate(rule, context)
                if match_result and match_result.matched:
                    if match_result.incomplete_cpu_revision:
                        has_incomplete_revision = True
                    finding = self._create_finding(insn, rule, match_result, elf)
                    findings.append(finding)
            stats.stage_durations["evaluation"] = time.perf_counter() - t0

        stats.duration_seconds = time.perf_counter() - start_total

        if findings:
            result = "FAIL"
        elif has_incomplete_revision:
            result = "INCOMPLETE"
        else:
            result = "PASS"

        return AnalysisReport(
            binary_path=elf.path,
            binary_sha256=elf.sha256,
            target_cpu=self.cpu,
            rules_loaded=len(self.rules),
            statistics=stats,
            findings=findings,
            result=result,
        )

    def _create_finding(
        self,
        instruction: Instruction,
        rule: Rule,
        match_result: "MatchResult",
        elf: ELFImage,
    ) -> Finding:
        """Map instruction address to DWARF debug info and assemble Finding."""
        src_loc = elf.dwarf_mapper.find_source_location(instruction.address)
        src_file = src_loc.file if src_loc else None
        src_line = src_loc.line if src_loc else None

        func_name = instruction.function
        if not func_name and elf.symbol_table:
            sym = elf.symbol_table.find_function_at(instruction.address)
            if sym:
                func_name = sym.name

        return Finding(
            erratum_id=rule.erratum_id,
            title=rule.title,
            address=instruction.address,
            function=func_name,
            source_file=src_file,
            source_line=src_line,
            matched_conditions=match_result.matched_conditions,
            cpu=self.cpu,
            workaround=rule.workaround.description,
            references=rule.references,
            confidence=match_result.confidence,
        )


def compare_reports(before: AnalysisReport, after: AnalysisReport) -> "VerificationComparison":
    """Compare before/after analysis reports to verify erratum mitigation."""
    from errataguard.reporting.models import VerificationComparison

    before_errata = {f.erratum_id for f in before.findings}
    after_errata = {f.erratum_id for f in after.findings}

    resolved = [f for f in before.findings if f.erratum_id not in after_errata]
    remaining = [f for f in after.findings if f.erratum_id in before_errata]
    new_findings = [f for f in after.findings if f.erratum_id not in before_errata]

    result = "PASS" if len(after.findings) == 0 else "FAIL"

    return VerificationComparison(
        before_report=before,
        after_report=after,
        resolved_findings=resolved,
        remaining_findings=remaining,
        new_findings=new_findings,
        result=result,
    )
