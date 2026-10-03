"""Unit tests for AArch64 decoding using Capstone."""

import pytest

from errataguard.disasm.aarch64 import AArch64Decoder, Instruction
from errataguard.elf.sections import CodeRegion
from errataguard.elf.symbols import SymbolTable, Symbol


def test_decode_region_instructions():
    decoder = AArch64Decoder()
    # adrp x0, #0; ldr x1, [x0]; ret
    code = b"\x00\x00\x00\x90\x01\x00\x40\xf9\xc0\x03\x5f\xd6"
    region = CodeRegion(
        name=".text",
        virtual_address=0x40082C,
        file_offset=0x100,
        size=len(code),
        data=code,
    )

    insns = decoder.decode_region(region)
    assert len(insns) == 3
    assert insns[0].address == 0x40082C
    assert insns[0].mnemonic == "adrp"
    assert "x0" in insns[0].op_str

    assert insns[1].address == 0x400830
    assert insns[1].mnemonic == "ldr"

    assert insns[2].address == 0x400834
    assert insns[2].mnemonic == "ret"


def test_decode_with_symbols():
    decoder = AArch64Decoder()
    code = b"\x00\x04\x00\x91\xc0\x03\x5f\xd6"  # add x0, x0, 1; ret
    region = CodeRegion(
        name=".text",
        virtual_address=0x400000,
        file_offset=0x40,
        size=len(code),
        data=code,
    )
    syms = [
        Symbol(name="my_func", address=0x400000, size=8, sym_type="STT_FUNC", binding="STB_GLOBAL")
    ]
    sym_table = SymbolTable(syms)

    insns = decoder.decode_region(region, symbol_table=sym_table)
    assert len(insns) == 2
    assert insns[0].function == "my_func"
    assert insns[1].function == "my_func"


def test_group_functions_stripped():
    decoder = AArch64Decoder()
    insns = [
        Instruction(address=0x400000, mnemonic="nop", op_str="", bytes=b"", size=4, function=None),
        Instruction(address=0x400004, mnemonic="ret", op_str="", bytes=b"", size=4, function=None),
    ]
    funcs = decoder.group_functions(insns, symbol_table=None)
    assert len(funcs) == 1
    assert funcs[0].name == "<unknown>"
    assert len(funcs[0].instructions) == 2
