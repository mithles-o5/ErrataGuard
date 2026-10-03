"""AArch64 instruction decoding using Capstone."""

from dataclasses import dataclass
import logging
from typing import Optional, Sequence

import capstone
from capstone import CS_ARCH_ARM64, CS_MODE_ARM

from errataguard.elf.sections import CodeRegion
from errataguard.elf.symbols import SymbolTable
from errataguard.errors import DisassemblyError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Instruction:
    """Disassembled AArch64 instruction."""
    address: int
    mnemonic: str
    op_str: str
    bytes: bytes
    size: int
    function: Optional[str]
    registers_read: tuple[str, ...] = ()
    registers_written: tuple[str, ...] = ()

    @property
    def display(self) -> str:
        if self.op_str:
            return f"0x{self.address:08x}: {self.mnemonic:8s} {self.op_str}"
        return f"0x{self.address:08x}: {self.mnemonic}"

    def __str__(self) -> str:
        return self.display


@dataclass
class Function:
    """Logical function grouping instructions."""
    name: str
    start_address: int
    end_address: int
    instructions: list[Instruction]


class AArch64Decoder:
    """Decoder for AArch64 machine code using Capstone."""

    def __init__(self):
        try:
            self._cs = capstone.Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            self._cs.detail = True
        except Exception as ex:
            raise DisassemblyError(f"Failed to initialize Capstone AArch64 decoder: {ex}") from ex

    def decode_region(
        self,
        region: CodeRegion,
        symbol_table: Optional[SymbolTable] = None,
    ) -> list[Instruction]:
        """Decode all instructions in an executable CodeRegion."""
        instructions: list[Instruction] = []
        data = region.data
        base_addr = region.virtual_address

        try:
            disasm_iter = self._cs.disasm(data, base_addr)
            for insn in disasm_iter:
                func_name: Optional[str] = None
                if symbol_table:
                    func_sym = symbol_table.find_function_at(insn.address)
                    if func_sym:
                        func_name = func_sym.name

                # Extract register names if available from Capstone details
                regs_read: list[str] = []
                regs_written: list[str] = []
                try:
                    regs_read = [self._cs.reg_name(r).lower() for r in insn.regs_read]
                    regs_written = [self._cs.reg_name(r).lower() for r in insn.regs_write]
                except Exception:
                    pass

                instructions.append(
                    Instruction(
                        address=insn.address,
                        mnemonic=insn.mnemonic.lower(),
                        op_str=insn.op_str.strip(),
                        bytes=bytes(insn.bytes),
                        size=insn.size,
                        function=func_name,
                        registers_read=tuple(regs_read),
                        registers_written=tuple(regs_written),
                    )
                )
        except Exception as ex:
            raise DisassemblyError(
                f"Disassembly failed in section {region.name} at 0x{base_addr:x}: {ex}"
            ) from ex

        logger.debug(
            "Decoded %d instructions from section %s (0x%x - 0x%x)",
            len(instructions),
            region.name,
            base_addr,
            base_addr + region.size,
        )
        return instructions

    def group_functions(
        self,
        instructions: Sequence[Instruction],
        symbol_table: Optional[SymbolTable] = None,
    ) -> list[Function]:
        """Group instructions into logical functions based on symbols."""
        if not symbol_table:
            # Stripped binary: return unknown function or basic group
            if not instructions:
                return []
            return [
                Function(
                    name="<unknown>",
                    start_address=instructions[0].address,
                    end_address=instructions[-1].address + instructions[-1].size,
                    instructions=list(instructions),
                )
            ]

        # Group by function symbol
        func_map: dict[str, list[Instruction]] = {}
        for insn in instructions:
            name = insn.function or "<unknown>"
            func_map.setdefault(name, []).append(insn)

        functions: list[Function] = []
        for name, insns in func_map.items():
            if insns:
                functions.append(
                    Function(
                        name=name,
                        start_address=insns[0].address,
                        end_address=insns[-1].address + insns[-1].size,
                        instructions=insns,
                    )
                )

        return functions
