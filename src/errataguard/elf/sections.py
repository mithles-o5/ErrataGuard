"""Representation of ELF sections and executable code regions."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Section:
    """General ELF section representation."""
    name: str
    virtual_address: int
    file_offset: int
    size: int
    flags: int
    is_executable: bool


@dataclass(frozen=True)
class CodeRegion:
    """Executable code region ready for disassembly and verification."""
    name: str
    virtual_address: int
    file_offset: int
    size: int
    data: bytes
