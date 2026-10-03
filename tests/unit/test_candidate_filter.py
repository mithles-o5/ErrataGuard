"""Unit tests for candidate filtering stage."""

import pytest

from errataguard.analysis.candidate_filter import CandidateFilter
from errataguard.disasm.aarch64 import Instruction
from errataguard.rules.schema import Rule, CandidateSpec, WorkaroundSpec


def make_test_rule(erratum_id: str, candidate_mnemonics: tuple[str, ...]) -> Rule:
    return Rule(
        erratum_id=erratum_id,
        title=f"Test Rule {erratum_id}",
        architecture="AArch64",
        cpu="Cortex-A53",
        affected_revisions=("r0p0", "r0p1"),
        candidate=CandidateSpec(mnemonics=candidate_mnemonics),
        conditions=(),
        workaround=WorkaroundSpec(description="Test workaround"),
        references=(),
        authoritative=False,
    )


def test_candidate_filter_matches():
    cfilter = CandidateFilter()
    rule1 = make_test_rule("RULE-1", ("adrp",))
    rule2 = make_test_rule("RULE-2", ("mrs",))
    rules = [rule1, rule2]

    insn_adrp = Instruction(
        address=0x40082C, mnemonic="adrp", op_str="x0, #0", bytes=b"", size=4, function="foo"
    )
    insn_mrs = Instruction(
        address=0x400830, mnemonic="mrs", op_str="x1, vbar_el1", bytes=b"", size=4, function="foo"
    )
    insn_add = Instruction(
        address=0x400834, mnemonic="add", op_str="x0, x0, 1", bytes=b"", size=4, function="foo"
    )

    matches_adrp = cfilter.candidate_rules(insn_adrp, rules)
    assert matches_adrp == [rule1]

    matches_mrs = cfilter.candidate_rules(insn_mrs, rules)
    assert matches_mrs == [rule2]

    # Irrelevant instruction is rejected
    matches_add = cfilter.candidate_rules(insn_add, rules)
    assert matches_add == []


def test_candidate_filter_conservative():
    # Guarantee: False negatives are unacceptable
    cfilter = CandidateFilter()
    rule_all = Rule(
        erratum_id="RULE-ALL",
        title="Catch all",
        architecture="AArch64",
        cpu="Cortex-A53",
        affected_revisions=(),
        candidate=CandidateSpec(mnemonics=()),  # Empty matches all
        conditions=(),
        workaround=WorkaroundSpec(description=""),
        references=(),
        authoritative=False,
    )
    insn = Instruction(address=0x400000, mnemonic="sub", op_str="", bytes=b"", size=4, function=None)
    matches = cfilter.candidate_rules(insn, [rule_all])
    assert matches == [rule_all]
