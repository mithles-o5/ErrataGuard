"""Synthetic AArch64 ELF binary generator for deterministic testing and benchmarking."""

import struct
from pathlib import Path
from typing import Sequence, Optional, Tuple


def uleb128(val: int) -> bytes:
    """Encode unsigned integer as ULEB128."""
    res = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        if val != 0:
            b |= 0x80
        res.append(b)
        if val == 0:
            break
    return bytes(res)


def sleb128(val: int) -> bytes:
    """Encode signed integer as SLEB128."""
    res = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        sign_bit = (b & 0x40) != 0
        if (val == 0 and not sign_bit) or (val == -1 and sign_bit):
            res.append(b)
            break
        else:
            res.append(b | 0x80)
    return bytes(res)


def build_aarch64_elf(
    code_bytes: bytes,
    base_address: int = 0x400000,
    symbols: Optional[Sequence[Tuple[str, int, int, bool]]] = None,
    dwarf_mappings: Optional[Sequence[Tuple[str, int, int]]] = None,
) -> bytes:
    """
    Build a completely valid 64-bit Little-Endian AArch64 ELF binary.
    
    symbols: list of (symbol_name, address, size, is_function)
    dwarf_mappings: list of (source_file, address, line_number)
    """
    # 1. Build DWARF sections if requested
    debug_line_sec = b""
    debug_abbrev_sec = b""
    debug_info_sec = b""

    if dwarf_mappings:
        # Group by file
        files = sorted(list({m[0] for m in dwarf_mappings}))
        file_to_idx = {f: idx + 1 for idx, f in enumerate(files)}

        file_entries_bytes = bytearray()
        for f in files:
            file_entries_bytes.extend(f.encode("utf-8") + b"\x00" + uleb128(0) + uleb128(0) + uleb128(0))
        file_entries_bytes.append(0)  # end of files list

        line_header_body = (
            struct.pack("<H", 2)  # version 2
            + b"HLEN"  # header length placeholder
            + struct.pack("B", 1)  # min insn len
            + struct.pack("B", 1)  # default is stmt
            + struct.pack("b", -5)  # line base
            + struct.pack("B", 14)  # line range
            + struct.pack("B", 10)  # opcode base
            + bytes([0, 1, 1, 1, 1, 0, 0, 0, 1])  # standard op lengths
            + b"\x00"  # directories (empty)
            + bytes(file_entries_bytes)
        )
        hdr_len = len(line_header_body) - 6
        line_header = line_header_body[:2] + struct.pack("<I", hdr_len) + line_header_body[6:]

        # Opcode generation
        insns = bytearray()
        curr_line = 1
        for fname, addr, line in dwarf_mappings:
            fidx = file_to_idx[fname]
            # set file
            insns.extend(b"\x04" + uleb128(fidx))
            # set address (extended opcode 2)
            insns.extend(b"\x00" + uleb128(9) + b"\x02" + struct.pack("<Q", addr))
            # advance line
            line_diff = line - curr_line
            insns.extend(b"\x03" + sleb128(line_diff))
            curr_line = line
            # copy
            insns.append(1)

        # end sequence
        insns.extend(b"\x00" + uleb128(1) + b"\x01")

        unit_len = len(line_header) + len(insns)
        debug_line_sec = struct.pack("<I", unit_len) + line_header + bytes(insns)

        # .debug_abbrev (1 abbrev code for compile_unit with stmt_list)
        debug_abbrev_sec = (
            uleb128(1)
            + uleb128(0x11)
            + b"\x00"
            + uleb128(0x10)
            + uleb128(0x06)
            + b"\x00\x00\x00"
        )

        # .debug_info
        cu_body = (
            struct.pack("<H", 2)
            + struct.pack("<I", 0)
            + struct.pack("B", 8)
            + uleb128(1)
            + struct.pack("<I", 0)
        )
        debug_info_sec = struct.pack("<I", len(cu_body)) + cu_body

    # 2. Section definition list
    # (name, type, flags, addr, data)
    sec_specs = [
        ("", 0, 0, 0, b""),
        (".text", 1, 6, base_address, code_bytes),  # SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR
    ]

    if dwarf_mappings:
        sec_specs.extend([
            (".debug_info", 1, 0, 0, debug_info_sec),
            (".debug_abbrev", 1, 0, 0, debug_abbrev_sec),
            (".debug_line", 1, 0, 0, debug_line_sec),
        ])

    # Symbols table
    symtab_data = bytearray(24)  # symbol 0: null symbol
    strtab_data = bytearray(b"\x00")

    if symbols:
        for name, addr, sz, is_func in symbols:
            name_offset = len(strtab_data)
            strtab_data.extend(name.encode("utf-8") + b"\x00")
            # STB_GLOBAL = 1, STT_FUNC = 2
            st_info = (1 << 4) | (2 if is_func else 0)
            st_shndx = 1  # .text section index
            symtab_data.extend(struct.pack("<IBBHQQ", name_offset, st_info, 0, st_shndx, addr, sz))

    sec_specs.extend([
        (".shstrtab", 3, 0, 0, b""),  # SHT_STRTAB (will build)
        (".symtab", 2, 0, 0, bytes(symtab_data)),  # SHT_SYMTAB
        (".strtab", 3, 0, 0, bytes(strtab_data)),  # SHT_STRTAB
    ])

    # Build .shstrtab
    shstrtab = bytearray(b"\x00")
    sec_name_offsets = []
    for sname, _, _, _, _ in sec_specs:
        if sname == "":
            sec_name_offsets.append(0)
        else:
            sec_name_offsets.append(len(shstrtab))
            shstrtab.extend(sname.encode("utf-8") + b"\x00")

    # Put actual shstrtab data in sec_specs
    for idx, (sname, stype, sflags, saddr, sdata) in enumerate(sec_specs):
        if sname == ".shstrtab":
            sec_specs[idx] = (sname, stype, sflags, saddr, bytes(shstrtab))

    num_sections = len(sec_specs)
    strtab_idx = num_sections - 1
    shstrtab_idx = num_sections - 3

    # Layout calculation
    offset = 64  # ELF Header
    offsets = []
    for _, _, _, _, d in sec_specs:
        pad = (8 - (offset % 8)) % 8
        offset += pad
        offsets.append(offset)
        offset += len(d)

    pad = (8 - (offset % 8)) % 8
    offset += pad
    sh_offset = offset

    # Section Headers
    shdrs = bytearray(num_sections * 64)
    for i in range(num_sections):
        sname, stype, sflags, saddr, sdata = sec_specs[i]
        soff = offsets[i]
        ssz = len(sdata)
        slink = strtab_idx if sname == ".symtab" else 0
        sinfo = 1 if sname == ".symtab" else 0
        sentsz = 24 if sname == ".symtab" else 0
        struct.pack_into(
            "<IIQQQQIIQQ",
            shdrs,
            i * 64,
            sec_name_offsets[i],
            stype,
            sflags,
            saddr,
            soff,
            ssz,
            slink,
            sinfo,
            8,
            sentsz,
        )

    # ELF64 Header
    ident = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        2,  # ET_EXEC
        183,  # EM_AARCH64
        1,  # EV_CURRENT
        base_address,
        0,  # e_phoff
        sh_offset,  # e_shoff
        0,  # e_flags
        64,  # e_ehsize
        0,  # e_phentsize
        0,  # e_phnum
        64,  # e_shentsize
        num_sections,  # e_shnum
        shstrtab_idx,  # e_shstrndx
    )

    out = bytearray(ehdr)
    for i in range(num_sections):
        pad = offsets[i] - len(out)
        if pad > 0:
            out.extend(b"\x00" * pad)
        out.extend(sec_specs[i][4])

    pad = sh_offset - len(out)
    if pad > 0:
        out.extend(b"\x00" * pad)
    out.extend(shdrs)

    return bytes(out)


def create_vulnerable_fixture(output_path: Path) -> Path:
    """Create vulnerable AArch64 ELF triggering A53-DEMO-001."""
    # Instructions:
    # 0x40082c: adrp x0, 0x400000
    # 0x400830: ldr  x1, [x0]
    # 0x400834: add  x0, x0, #1
    # 0x400838: ret
    code = (
        b"\x00\x00\x00\x90"  # adrp x0, 0
        b"\x01\x00\x40\xf9"  # ldr x1, [x0]
        b"\x00\x04\x00\x91"  # add x0, x0, 1
        b"\xc0\x03\x5f\xd6"  # ret
    )
    raw = build_aarch64_elf(
        code_bytes=code,
        base_address=0x40082C,
        symbols=[("process_data", 0x40082C, len(code), True)],
        dwarf_mappings=[("demo.c", 0x40082C, 7)],
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(raw)
    return output_path


def create_fixed_fixture(output_path: Path) -> Path:
    """Create mitigated AArch64 ELF with NOP inserted."""
    # Instructions:
    # 0x40082c: adrp x0, 0x400000
    # 0x400830: nop
    # 0x400834: ldr  x1, [x0]
    # 0x400838: add  x0, x0, #1
    # 0x40083c: ret
    code = (
        b"\x00\x00\x00\x90"  # adrp x0, 0
        b"\x1f\x20\x03\xd5"  # nop (mitigation workaround)
        b"\x01\x00\x40\xf9"  # ldr x1, [x0]
        b"\x00\x04\x00\x91"  # add x0, x0, 1
        b"\xc0\x03\x5f\xd6"  # ret
    )
    raw = build_aarch64_elf(
        code_bytes=code,
        base_address=0x40082C,
        symbols=[("process_data", 0x40082C, len(code), True)],
        dwarf_mappings=[("demo.c", 0x40082C, 7)],
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(raw)
    return output_path


def create_negative_fixture(output_path: Path) -> Path:
    """Create benign AArch64 ELF with no erratum sequences."""
    code = (
        b"\x00\x04\x00\x91"  # add x0, x0, 1
        b"\x21\x04\x00\x91"  # add x1, x1, 1
        b"\xc0\x03\x5f\xd6"  # ret
    )
    raw = build_aarch64_elf(
        code_bytes=code,
        base_address=0x400000,
        symbols=[("safe_calc", 0x400000, len(code), True)],
        dwarf_mappings=[("safe.c", 0x400000, 10)],
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(raw)
    return output_path


def create_synthetic_benchmark_elf(
    output_path: Path,
    total_instructions: int = 100_000,
) -> Path:
    """Create a large ELF (100,000+ instructions) to demonstrate candidate filter speedup."""
    # NOP = b"\x1f\x20\x03\xd5"
    nop = b"\x1f\x20\x03\xd5"
    chunk_nops = nop * 1000

    # Put a trigger near the middle
    midpoint = total_instructions // 2
    part1_count = midpoint
    part2_count = total_instructions - midpoint - 3

    code_parts = [
        nop * part1_count,
        b"\x00\x00\x00\x90",  # adrp x0, 0
        b"\x01\x00\x40\xf9",  # ldr x1, [x0]
        b"\xc0\x03\x5f\xd6",  # ret
        nop * part2_count,
    ]
    code = b"".join(code_parts)
    trigger_addr = 0x400000 + (part1_count * 4)

    raw = build_aarch64_elf(
        code_bytes=code,
        base_address=0x400000,
        symbols=[
            ("bench_func", 0x400000, len(code), True),
            ("trigger_point", trigger_addr, 12, True),
        ],
        dwarf_mappings=[("bench.c", trigger_addr, 42)],
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(raw)
    return output_path
