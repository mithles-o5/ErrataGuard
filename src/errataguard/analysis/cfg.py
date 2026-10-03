"""Control Flow Graph (CFG) representation and lazy construction."""

from dataclasses import dataclass, field
from typing import Sequence, Optional

from errataguard.disasm.aarch64 import Instruction


@dataclass
class BasicBlock:
    """Basic block of contiguous instructions ending in a branch/terminal."""
    start_address: int
    end_address: int
    instructions: list[Instruction]
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)


class ControlFlowGraph:
    """CFG representing basic blocks and branch edges."""

    def __init__(self, blocks: dict[int, BasicBlock]):
        self.blocks = blocks

    @classmethod
    def build(cls, instructions: Sequence[Instruction]) -> "ControlFlowGraph":
        """Construct CFG lazily from an instruction stream."""
        if not instructions:
            return cls({})

        # Find block leaders
        leaders = {instructions[0].address}
        branch_mnemonics = {
            "b", "bl", "blr", "br", "ret", "cbz", "cbnz", "tbz", "tbnz",
            "b.eq", "b.ne", "b.cs", "b.cc", "b.mi", "b.pl", "b.vs", "b.vc",
            "b.hi", "b.ls", "b.ge", "b.lt", "b.gt", "b.le", "b.al", "b.nv",
        }

        for idx, insn in enumerate(instructions):
            if insn.mnemonic in branch_mnemonics:
                # Instruction following a branch is a leader
                if idx + 1 < len(instructions):
                    leaders.add(instructions[idx + 1].address)
                # If branch target is a direct immediate address, add it as leader
                # Simple extraction from op_str (e.g. "#0x40082c" or "0x40082c")
                target_str = insn.op_str.split(",")[-1].strip().lstrip("#")
                if target_str.startswith("0x") or target_str.startswith("-0x"):
                    try:
                        target_addr = int(target_str, 16)
                        leaders.add(target_addr)
                    except ValueError:
                        pass

        # Split into blocks
        blocks: dict[int, BasicBlock] = {}
        curr_insns: list[Instruction] = []
        curr_start = instructions[0].address

        for insn in instructions:
            if insn.address in leaders and curr_insns and insn.address != curr_start:
                block = BasicBlock(
                    start_address=curr_start,
                    end_address=curr_insns[-1].address + curr_insns[-1].size,
                    instructions=curr_insns,
                )
                blocks[curr_start] = block
                curr_insns = [insn]
                curr_start = insn.address
            else:
                curr_insns.append(insn)

        if curr_insns:
            block = BasicBlock(
                start_address=curr_start,
                end_address=curr_insns[-1].address + curr_insns[-1].size,
                instructions=curr_insns,
            )
            blocks[curr_start] = block

        return cls(blocks)

    def find_block_for_address(self, address: int) -> Optional[BasicBlock]:
        """Find basic block containing given address."""
        for start, block in self.blocks.items():
            if block.start_address <= address < block.end_address:
                return block
        return None
