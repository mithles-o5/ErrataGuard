"""DWARF debug info reader and address-to-source mapper."""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Any
import logging

from errataguard.errors import DWARFError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SourceLocation:
    """Resolved source code location."""
    file: str
    line: int
    column: Optional[int] = None

    def __str__(self) -> str:
        if self.column is not None and self.column > 0:
            return f"{self.file}:{self.line}:{self.column}"
        return f"{self.file}:{self.line}"


class DWARFSourceMapper:
    """Extracts and indexes DWARF line information for fast address lookup."""

    def __init__(self, elf_file: Any):
        self._address_map: list[tuple[int, SourceLocation]] = []
        self._has_debug_info = False

        if elf_file is None:
            return

        try:
            if not hasattr(elf_file, "has_dwarf_info") or not elf_file.has_dwarf_info():
                logger.debug("ELF does not contain DWARF debug information")
                return

            dwarf_info = elf_file.get_dwarf_info()
            self._has_debug_info = True
            self._build_line_map(dwarf_info)
        except Exception as ex:
            logger.warning("Failed to parse DWARF info: %s", ex)
            # DWARF can be malformed in stripped/truncated binaries; do not crash analyzer
            self._has_debug_info = False

    @property
    def has_debug_info(self) -> bool:
        return self._has_debug_info

    def _build_line_map(self, dwarf_info: Any) -> None:
        raw_mappings: list[tuple[int, SourceLocation]] = []

        for cu in dwarf_info.iter_CUs():
            line_prog = dwarf_info.line_program_for_CU(cu)
            if line_prog is None:
                continue

            # Extract file list from header
            hdr = line_prog.header
            file_entries = hdr.get("file_entry") or hdr.get("file_names") or []
            dir_entries = hdr.get("include_directory") or hdr.get("directories") or []

            def get_filename(file_idx: int) -> str:
                if file_idx <= 0 or file_idx > len(file_entries):
                    return "<unknown>"
                entry = file_entries[file_idx - 1]
                name_bytes = entry.name
                file_name = name_bytes.decode("utf-8", errors="replace") if isinstance(name_bytes, bytes) else str(name_bytes)
                
                # Check directory index if available
                dir_idx = getattr(entry, "dir_index", 0)
                if dir_idx > 0 and dir_idx <= len(dir_entries):
                    d_bytes = dir_entries[dir_idx - 1]
                    d_str = d_bytes.decode("utf-8", errors="replace") if isinstance(d_bytes, bytes) else str(d_bytes)
                    return f"{d_str}/{file_name}"
                return file_name

            entries = line_prog.get_entries()
            prev_state = None
            for entry in entries:
                state = entry.state
                if state is None:
                    continue
                if state.end_sequence:
                    prev_state = None
                    continue

                if state.line > 0:
                    filename = get_filename(state.file)
                    loc = SourceLocation(file=filename, line=state.line, column=state.column if state.column > 0 else None)
                    raw_mappings.append((state.address, loc))
                prev_state = state

        # Sort by address for range search
        self._address_map = sorted(raw_mappings, key=lambda x: x[0])
        logger.debug("Indexed %d DWARF line table entries", len(self._address_map))

    def find_source_location(self, address: int) -> Optional[SourceLocation]:
        """Find source line for given address."""
        if not self._address_map:
            return None

        # Binary search for closest entry <= address
        low = 0
        high = len(self._address_map) - 1
        best_match: Optional[SourceLocation] = None

        while low <= high:
            mid = (low + high) // 2
            entry_addr, loc = self._address_map[mid]

            if entry_addr == address:
                return loc
            elif entry_addr < address:
                best_match = loc
                low = mid + 1
            else:
                high = mid - 1

        # Only return if difference is reasonable (e.g. within 256 bytes of line statement)
        if best_match and high >= 0:
            matched_addr, _ = self._address_map[high]
            if address - matched_addr <= 256:
                return best_match

        return None
