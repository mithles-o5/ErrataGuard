"""Localized contextual analysis window for candidate instructions."""

from dataclasses import dataclass
from typing import Optional, Sequence, Callable

from errataguard.config import CPUInfo
from errataguard.disasm.aarch64 import Instruction, Function
from errataguard.analysis.cfg import BasicBlock, ControlFlowGraph


@dataclass
class AnalysisContext:
    """Localized window and execution context around a candidate instruction."""
    instructions: list[Instruction]
    candidate_index: int
    function: Optional[Function]
    basic_block: Optional[BasicBlock]
    cpu: CPUInfo
    _all_function_instructions: Optional[Sequence[Instruction]] = None
    _cfg_cache: Optional[ControlFlowGraph] = None

    @property
    def candidate(self) -> Instruction:
        return self.instructions[self.candidate_index]

    def get_cfg(self) -> Optional[ControlFlowGraph]:
        """Lazy construction of CFG only if required by a rule condition."""
        if self._cfg_cache is not None:
            return self._cfg_cache
        if self._all_function_instructions:
            self._cfg_cache = ControlFlowGraph.build(self._all_function_instructions)
            return self._cfg_cache
        if self.function and self.function.instructions:
            self._cfg_cache = ControlFlowGraph.build(self.function.instructions)
            return self._cfg_cache
        # Fall back to current window
        self._cfg_cache = ControlFlowGraph.build(self.instructions)
        return self._cfg_cache


class ContextBuilder:
    """Constructs localized AnalysisContext around candidates without scanning entire binary."""

    def __init__(self, window_before: int = 5, window_after: int = 5):
        self.window_before = window_before
        self.window_after = window_after

    def build_context(
        self,
        instructions: Sequence[Instruction],
        global_index: int,
        cpu: CPUInfo,
        function: Optional[Function] = None,
    ) -> AnalysisContext:
        """Create a localized window context around instructions[global_index]."""
        start_idx = max(0, global_index - self.window_before)
        end_idx = min(len(instructions), global_index + self.window_after + 1)

        window = list(instructions[start_idx:end_idx])
        local_cand_idx = global_index - start_idx

        return AnalysisContext(
            instructions=window,
            candidate_index=local_cand_idx,
            function=function,
            basic_block=None,
            cpu=cpu,
            _all_function_instructions=function.instructions if function else instructions,
        )
