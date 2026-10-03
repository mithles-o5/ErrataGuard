"""Unit tests for DWARF line table parsing and source location resolution."""

from pathlib import Path
from errataguard.elf.parser import parse_elf
from tests.fixtures.elf_generator import create_vulnerable_fixture, create_negative_fixture


def test_dwarf_mapping_resolution(tmp_path: Path):
    elf_path = tmp_path / "dwarf_test.elf"
    create_vulnerable_fixture(elf_path)

    image = parse_elf(elf_path)
    assert image.dwarf_mapper.has_debug_info is True

    # 0x40082C was mapped to demo.c:7
    loc = image.dwarf_mapper.find_source_location(0x40082C)
    assert loc is not None
    assert loc.file == "demo.c"
    assert loc.line == 7
    assert str(loc) == "demo.c:7"


def test_dwarf_missing_info(tmp_path: Path):
    from tests.fixtures.elf_generator import build_aarch64_elf
    code = b"\x00\x00\x00\x90\xc0\x03\x5f\xd6"
    raw = build_aarch64_elf(code, base_address=0x400000, dwarf_mappings=None)
    elf_file = tmp_path / "stripped.elf"
    elf_file.write_bytes(raw)

    image = parse_elf(elf_file)
    assert image.dwarf_mapper.has_debug_info is False
    assert image.dwarf_mapper.find_source_location(0x400000) is None
