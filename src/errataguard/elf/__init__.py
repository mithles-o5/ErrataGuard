"""ELF parsing module."""

from errataguard.elf.parser import ELFImage, parse_elf, compute_sha256
from errataguard.elf.sections import Section, CodeRegion
from errataguard.elf.symbols import Symbol, SymbolTable
from errataguard.elf.dwarf import DWARFSourceMapper, SourceLocation

__all__ = [
    "ELFImage",
    "parse_elf",
    "compute_sha256",
    "Section",
    "CodeRegion",
    "Symbol",
    "SymbolTable",
    "DWARFSourceMapper",
    "SourceLocation",
]
