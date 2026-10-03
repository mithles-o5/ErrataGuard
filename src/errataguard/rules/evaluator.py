"""Contextual rule evaluator testing candidate instructions against condition specifications."""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
from typing import Optional, Sequence, TYPE_CHECKING, Any

if TYPE_CHECKING:
    from errataguard.analysis.context import AnalysisContext

from errataguard.rules.schema import Rule, ConditionSpec

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MatchResult:
    """Result of evaluating a rule against an AnalysisContext."""
    matched: bool
    matched_conditions: tuple[str, ...] = ()
    confidence: str = "Static match"
    incomplete_cpu_revision: bool = False
    details: str = ""


class RuleEvaluator:
    """Evaluates contextual conditions for a candidate instruction."""

    def evaluate(self, rule: Rule, context: AnalysisContext) -> Optional[MatchResult]:
        """
        Evaluate a rule against an AnalysisContext.
        Returns MatchResult if the erratum condition triggers, else None.
        """
        # 1. Verify CPU architecture and model
        if not rule.is_cpu_applicable(context.cpu.architecture, context.cpu.model):
            return None

        matched_conditions: list[str] = [f"candidate instruction '{context.candidate.mnemonic}'"]
        incomplete_revision = False

        # 2. Verify CPU revision
        rev_status = rule.is_revision_affected(context.cpu.revision)
        if rev_status is False:
            # Explicitly unaffected CPU revision
            return None
        elif rev_status is None:
            # CPU revision required but not provided
            incomplete_revision = True
            matched_conditions.append(
                f"CPU revision unspecified (affected revisions: {', '.join(rule.affected_revisions)})"
            )
        else:
            rev_str = context.cpu.revision or "all"
            matched_conditions.append(f"CPU revision affected ({rev_str})")

        # 3. Evaluate each condition
        for cond in rule.conditions:
            cond_result = self._evaluate_condition(cond, context)
            if not cond_result[0]:
                return None
            matched_conditions.append(cond_result[1])

        return MatchResult(
            matched=True,
            matched_conditions=tuple(matched_conditions),
            confidence="Static match" if not incomplete_revision else "Incomplete CPU verification",
            incomplete_cpu_revision=incomplete_revision,
        )

    def _evaluate_condition(
        self,
        cond: ConditionSpec,
        context: AnalysisContext,
    ) -> tuple[bool, str]:
        """Evaluate a single ConditionSpec against the context."""
        cond_type = cond.type.lower()
        params = cond.params

        if cond_type == "instruction_sequence":
            return self._eval_instruction_sequence(cond, context)
        elif cond_type in ("register_dependency", "register_relationship"):
            return self._eval_register_dependency(cond, context)
        elif cond_type in ("boundary_check", "page_boundary"):
            return self._eval_boundary_check(cond, context)
        elif cond_type == "control_flow":
            return self._eval_control_flow(cond, context)
        elif cond_type == "cpu_revision":
            return True, cond.description or "CPU revision checked"
        else:
            logger.warning("Unknown condition type '%s', skipping condition", cond_type)
            return True, f"Condition {cond_type} (ignored)"

    def _eval_instruction_sequence(
        self,
        cond: ConditionSpec,
        context: AnalysisContext,
    ) -> tuple[bool, str]:
        """Check sequence of instructions around candidate."""
        pattern = cond.params.get("pattern", [])
        if not pattern:
            return True, cond.description or "Sequence satisfied"

        window = context.instructions
        cand_idx = context.candidate_index

        # If pattern is a list of strings (mnemonics)
        # Check if following instructions match pattern
        for step_idx, expected_mnem in enumerate(pattern):
            target_idx = cand_idx + step_idx + 1
            if target_idx >= len(window):
                return False, "Sequence truncated at boundary"
            target_insn = window[target_idx]
            if target_insn.mnemonic.lower() != str(expected_mnem).lower():
                return False, f"Expected {expected_mnem}, found {target_insn.mnemonic}"

        desc = cond.description or f"sequence [{', '.join(str(p) for p in pattern)}] matched"
        return True, desc

    def _eval_register_dependency(
        self,
        cond: ConditionSpec,
        context: AnalysisContext,
    ) -> tuple[bool, str]:
        """Verify register data dependencies between candidate and adjacent instruction."""
        target_offset = int(cond.params.get("offset", 1))
        cand_idx = context.candidate_index
        target_idx = cand_idx + target_offset

        if target_idx < 0 or target_idx >= len(context.instructions):
            return False, "Target instruction outside window"

        cand_insn = context.instructions[cand_idx]
        target_insn = context.instructions[target_idx]

        dep_type = cond.params.get("dependency", "destination_to_source")
        if dep_type == "destination_to_source":
            # Check if any register written by candidate is read by target
            written = set(cand_insn.registers_written)
            read = set(target_insn.registers_read)
            overlap = written.intersection(read)
            if not overlap:
                # Also check operands string as fallback if Capstone registers are empty
                # e.g. if cand is 'adrp x0, ...' and target is 'ldr x1, [x0]'
                cand_dest = cand_insn.op_str.split(",")[0].strip().lower() if cand_insn.op_str else ""
                if cand_dest and cand_dest in target_insn.op_str.lower():
                    desc = cond.description or f"register dependency {cand_dest} confirmed"
                    return True, desc
                return False, "No data dependency between candidate and target instruction"
            desc = cond.description or f"register dependency {', '.join(overlap)} confirmed"
            return True, desc

        return True, "Register dependency checked"

    def _eval_boundary_check(
        self,
        cond: ConditionSpec,
        context: AnalysisContext,
    ) -> tuple[bool, str]:
        """Check address boundary conditions (e.g. 4KB page boundary offset)."""
        offset_mask = int(cond.params.get("mask", 0xFFF))
        min_offset = int(cond.params.get("min_offset", 0xFF8))
        cand_addr = context.candidate.address
        page_off = cand_addr & offset_mask

        if page_off >= min_offset:
            desc = cond.description or f"address 0x{cand_addr:x} matches boundary offset 0x{page_off:x}"
            return True, desc
        return False, f"Address 0x{cand_addr:x} offset 0x{page_off:x} below threshold 0x{min_offset:x}"

    def _eval_control_flow(
        self,
        cond: ConditionSpec,
        context: AnalysisContext,
    ) -> tuple[bool, str]:
        """Check CFG or basic block boundary properties."""
        cfg = context.get_cfg()
        if not cfg:
            return True, "CFG unconstrained"

        block = cfg.find_block_for_address(context.candidate.address)
        if not block:
            return True, "Block not found"

        # E.g. candidate must be at end of block
        if cond.params.get("require_block_end", False):
            if block.instructions and block.instructions[-1].address == context.candidate.address:
                return True, "Candidate terminates basic block"
            return False, "Candidate does not terminate basic block"

        return True, "CFG condition satisfied"
