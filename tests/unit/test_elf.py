"""Unit tests for ELF parser, architecture validation, and section extraction."""

import pytest
from pathlib import Path

from errataguard.elf.parser import parse_elf
from errataguard.errors import (
    ELFError,
    InvalidELFError,
    UnsupportedArchitectureError,
    MissingExecutableSectionError,
)
from tests.fixtures.elf_generator import build_aarch64_elf


def test_valid_aarch64_elf(tmp_path: Path):
    code = b"\x00\x00\x00\x90\xc0\x03\x5f\xd6"
    elf_bytes = build_aarch64_elf(code, base_address=0x400000)
    elf_file = tmp_path / "valid.elf"
    elf_file.write_bytes(elf_bytes)

    image = parse_elf(elf_file)
    assert image.architecture == "AArch64"
    assert len(image.executable_sections) == 1
    assert image.executable_sections[0].name == ".text"
    assert image.executable_sections[0].size == len(code)
    assert len(image.sha256) == 64


def test_file_not_found():
    with pytest.raises(ELFError, match="Target binary not found"):
        parse_elf("non_existent_firmware.elf")


def test_invalid_elf_magic(tmp_path: Path):
    bad_file = tmp_path / "corrupt.elf"
    bad_file.write_bytes(b"NOT_AN_ELF_FILE_FOR_SURE")
    with pytest.raises(InvalidELFError, match="not a valid ELF binary"):
        parse_elf(bad_file)


def test_unsupported_architecture(tmp_path: Path):
    # Construct an x86_64 ELF (e_machine = 62 / 0x3E)
    code = b"\x90\xc3"
    # Build minimal valid ELF header with x86_64 machine
    ident = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    import struct
    # e_machine = 62 (EM_X86_64)
    ehdr = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 62, 1, 0x400000, 0, 64, 0, 64, 0, 0, 64, 2, 0)
    # 2 sections: NULL and .text
    shdrs = bytearray(2 * 64)
    struct.pack_into("<IIQQQQIIQQ", shdrs, 64, 0, 1, 6, 0x400000, 64 + 128, len(code), 0, 0, 16, 0)
    x86_file = tmp_path / "x86.elf"
    x86_file.write_bytes(ehdr + shdrs + code)

    with pytest.raises(UnsupportedArchitectureError, match="Unsupported architecture.*ErrataGuard currently supports: AArch64"):
        parse_elf(x86_file)


def test_missing_executable_sections(tmp_path: Path):
    # Build an ELF where sections have no SHF_EXECINSTR
    ident = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    import struct
    ehdr = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 183, 1, 0x400000, 0, 64, 0, 64, 0, 0, 64, 2, 0)
    shdrs = bytearray(2 * 64)
    # flags = 2 (SHF_ALLOC only, not SHF_EXECINSTR)
    struct.pack_into("<IIQQQQIIQQ", shdrs, 64, 0, 1, 2, 0x400000, 64 + 128, 16, 0, 0, 16, 0)
    data = b"\x00" * 16
    no_exec_file = tmp_path / "no_exec.elf"
    no_exec_file.write_bytes(ehdr + shdrs + data)

    with pytest.raises(MissingExecutableSectionError, match="contains no executable sections"):
        parse_elf(no_exec_file)
