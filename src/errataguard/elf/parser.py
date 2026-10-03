"""ELF parsing and validation engine for AArch64 binaries."""

import hashlib
import logging
from pathlib import Path
from typing import Optional

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.constants import SH_FLAGS

from errataguard.elf.sections import Section, CodeRegion
from errataguard.elf.symbols import Symbol, SymbolTable
from errataguard.elf.dwarf import DWARFSourceMapper
from errataguard.errors import (
    ELFError,
    InvalidELFError,
    UnsupportedArchitectureError,
    MissingExecutableSectionError,
)

logger = logging.getLogger(__name__)

SUPPORTED_ARCH = "AArch64"


class ELFImage:
    """Parsed in-memory view of an AArch64 ELF binary."""

    def __init__(
        self,
        path: Path,
        architecture: str,
        bits: int,
        endianness: str,
        sections: list[Section],
        executable_sections: list[CodeRegion],
        symbols: list[Symbol],
        symbol_table: SymbolTable,
        dwarf_mapper: DWARFSourceMapper,
        sha256: str,
    ):
        self.path = path
        self.architecture = architecture
        self.bits = bits
        self.endianness = endianness
        self.sections = sections
        self.executable_sections = executable_sections
        self.symbols = symbols
        self.symbol_table = symbol_table
        self.dwarf_mapper = dwarf_mapper
        self.sha256 = sha256

    @property
    def debug_info(self) -> DWARFSourceMapper:
        return self.dwarf_mapper

    def __repr__(self) -> str:
        return (
            f"<ELFImage path={self.path.name} arch={self.architecture} "
            f"exec_sections={len(self.executable_sections)}>"
        )


def compute_sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def parse_elf(file_path: Path | str) -> ELFImage:
    """Parse and validate an AArch64 ELF binary."""
    path = Path(file_path).resolve()

    if not path.exists():
        raise ELFError(f"Target binary not found: {path}")
    if not path.is_file():
        raise ELFError(f"Target path is not a file: {path}")

    # Check ELF Magic bytes
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            if magic != b"\x7fELF":
                raise InvalidELFError(f"File is not a valid ELF binary: {path}")
    except OSError as ex:
        raise ELFError(f"Unable to read file {path}: {ex}") from ex

    sha256_hash = compute_sha256(path)

    with open(path, "rb") as f:
        try:
            elf = ELFFile(f)
        except Exception as ex:
            raise InvalidELFError(f"Failed to parse ELF headers for {path}: {ex}") from ex

        # Check architecture
        machine = elf.header.get("e_machine")
        arch_name = "AArch64" if machine in ("EM_AARCH64", 183) else str(machine)
        if arch_name != SUPPORTED_ARCH:
            raise UnsupportedArchitectureError(
                f"Unsupported architecture: {arch_name}. "
                f"ErrataGuard currently supports: {SUPPORTED_ARCH}"
            )

        bits = elf.elfclass
        endianness = "little" if elf.little_endian else "big"

        sections: list[Section] = []
        executable_sections: list[CodeRegion] = []

        for sec in elf.iter_sections():
            sec_name = sec.name
            flags = sec["sh_flags"]
            is_exec = bool(flags & SH_FLAGS.SHF_EXECINSTR)
            sh_addr = sec["sh_addr"]
            sh_offset = sec["sh_offset"]
            sh_size = sec["sh_size"]

            sections.append(
                Section(
                    name=sec_name,
                    virtual_address=sh_addr,
                    file_offset=sh_offset,
                    size=sh_size,
                    flags=flags,
                    is_executable=is_exec,
                )
            )

            # Only analyze executable sections that contain actual bytes (size > 0)
            if is_exec and sh_size > 0 and sec["sh_type"] != "SHT_NOBITS":
                data = sec.data()
                executable_sections.append(
                    CodeRegion(
                        name=sec_name,
                        virtual_address=sh_addr,
                        file_offset=sh_offset,
                        size=sh_size,
                        data=data,
                    )
                )

        if not executable_sections:
            raise MissingExecutableSectionError(
                f"ELF binary contains no executable sections: {path}"
            )

        # Extract symbols
        symbols: list[Symbol] = []
        for sec in elf.iter_sections():
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    symbols.append(
                        Symbol(
                            name=sym.name,
                            address=sym["st_value"],
                            size=sym["st_size"],
                            sym_type=sym["st_info"]["type"],
                            binding=sym["st_info"]["bind"],
                            section_index=sym["st_shndx"] if isinstance(sym["st_shndx"], int) else None,
                        )
                    )

        sym_table = SymbolTable(symbols)

        # Parse DWARF info
        dwarf_mapper = DWARFSourceMapper(elf)

        logger.debug(
            "Parsed %s: %d sections (%d executable), %d symbols, DWARF=%s",
            path.name,
            len(sections),
            len(executable_sections),
            len(symbols),
            dwarf_mapper.has_debug_info,
        )

        return ELFImage(
            path=path,
            architecture=arch_name,
            bits=bits,
            endianness=endianness,
            sections=sections,
            executable_sections=executable_sections,
            symbols=symbols,
            symbol_table=sym_table,
            dwarf_mapper=dwarf_mapper,
            sha256=sha256_hash,
        )
