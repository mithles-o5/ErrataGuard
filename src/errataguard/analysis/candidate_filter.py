"""Fast, conservative candidate filtering stage."""

from typing import Sequence

from errataguard.disasm.aarch64 import Instruction
from errataguard.rules.schema import Rule


class CandidateFilter:
    """Fast pre-filter to discard irrelevant instructions before expensive verification."""

    # Fast instruction class mappings for AArch64 mnemonics
    BRANCH_MNEMONICS = {
        "b", "bl", "blr", "br", "ret", "cbz", "cbnz", "tbz", "tbnz",
        "b.eq", "b.ne", "b.cs", "b.cc", "b.mi", "b.pl", "b.vs", "b.vc",
        "b.hi", "b.ls", "b.ge", "b.lt", "b.gt", "b.le", "b.al", "b.nv",
    }
    LOAD_MNEMONICS = {
        "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw", "ldur", "ldurb",
        "ldurh", "ldursb", "ldursh", "ldursw", "ldp", "ldnp", "ldar", "ldaxr",
    }
    STORE_MNEMONICS = {
        "str", "strb", "strh", "stur", "sturb", "sturh", "stp", "stnp",
        "stlr", "stlxr",
    }
    SYSTEM_MNEMONICS = {
        "mrs", "msr", "sys", "sysl", "isb", "dsb", "dmb", "wfi", "wfe", "smc", "hvc", "svc",
    }

    def candidate_rules(
        self,
        instruction: Instruction,
        rules: Sequence[Rule],
    ) -> list[Rule]:
        """
        Identify which rules consider this instruction a potential trigger candidate.
        Conservative guarantee: Never produce false negatives.
        """
        matches: list[Rule] = []
        mnem = instruction.mnemonic.lower()

        for rule in rules:
            cand = rule.candidate

            # 1. Check mnemonic match
            if not cand.matches_mnemonic(mnem):
                continue

            # 2. Check instruction classes if specified
            if cand.instruction_classes:
                class_matched = False
                for cls in cand.instruction_classes:
                    if cls == "branch" and mnem in self.BRANCH_MNEMONICS:
                        class_matched = True
                        break
                    elif cls == "load" and mnem in self.LOAD_MNEMONICS:
                        class_matched = True
                        break
                    elif cls == "store" and mnem in self.STORE_MNEMONICS:
                        class_matched = True
                        break
                    elif cls == "system" and mnem in self.SYSTEM_MNEMONICS:
                        class_matched = True
                        break
                if not class_matched:
                    continue

            # 3. Check destination register requirement if specified
            if cand.require_destination_register and not instruction.registers_written:
                continue

            matches.append(rule)

        return matches
