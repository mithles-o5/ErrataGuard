"""Symbol management and address-to-symbol resolution."""

from dataclasses import dataclass
from typing import Optional, Sequence


@dataclass(frozen=True)
class Symbol:
    """ELF symbol metadata."""
    name: str
    address: int
    size: int
    sym_type: str
    binding: str
    section_index: Optional[int] = None

    @property
    def is_function(self) -> bool:
        return self.sym_type in ("STT_FUNC", "FUNC", "2")


class SymbolTable:
    """Indexed table for fast address to symbol lookup."""

    def __init__(self, symbols: Sequence[Symbol]):
        self._symbols = list(symbols)
        # Sort function symbols by start address for range lookups
        self._functions = sorted(
            [s for s in self._symbols if s.is_function and s.size > 0],
            key=lambda s: s.address
        )

    @property
    def symbols(self) -> list[Symbol]:
        return list(self._symbols)

    def find_function_at(self, address: int) -> Optional[Symbol]:
        """Find the function symbol enclosing the given virtual address."""
        # Binary search or scan
        for sym in self._functions:
            if sym.address <= address < sym.address + sym.size:
                return sym
        return None
