# ErrataGuard

**AArch64 Cortex-A53 Errata Static Verification Prototype**

[![Tests](https://img.shields.io/badge/tests-26%20passed-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)]()
[![Architecture: AArch64](https://img.shields.io/badge/arch-AArch64-orange.svg)]()

> [!IMPORTANT]
> **Safety Disclaimer:**
> ErrataGuard does not prove hardware safety. It verifies whether supported, statically detectable documented trigger conditions are present in the analyzed ELF.

---

## 1. Problem Statement

A Cortex-A53 processor can have documented hardware errata where a completely valid AArch64 program may trigger incorrect processor behavior under a very specific sequence of instructions and conditions. While compilers and linkers (GCC, LLVM) incorporate mitigations for known errata, independent post-build verification is essential for high-assurance firmware and systems engineering.

**ErrataGuard** is an independent post-build static verification tool. It inspects the final ELF firmware artifact and determines whether it contains statically detectable trigger conditions for documented Cortex-A53 hardware errata, mapping findings back to high-level C source code and providing evidence-backed reports.

---

## 2. Architecture Diagram

```
                    ARM Documentation
                           │
                           ▼
                   Verified Rule Files
                           │
                           ▼
                    ┌───────────────┐
 firmware.elf ────► │   ELF Parser  │
                    └───────┬───────┘
                            ▼
                    ┌───────────────┐
                    │ AArch64       │
                    │ Decoder       │
                    └───────┬───────┘
                            ▼
                    ┌───────────────┐
                    │ Fast Candidate│
                    │ Filter        │
                    └───────┬───────┘
                            │
                       candidates
                            │
                            ▼
                    ┌───────────────┐
                    │ Rule Engine   │
                    └───────┬───────┘
                            ▼
                    ┌───────────────┐
                    │ Context /     │
                    │ Condition     │
                    │ Analyzer      │
                    └───────┬───────┘
                            │
                     ┌──────┴──────┐
                     ▼             ▼
                  No Match       Match
                     │             │
                     ▼             ▼
                  PASS ✓       Evidence
                                   │
                         ┌─────────┴─────────┐
                         ▼                   ▼
                       DWARF             Rule Evidence
                         │                   │
                         └─────────┬─────────┘
                                   ▼
                                Finding
                                   │
                         ┌─────────┼─────────┐
                         ▼         ▼         ▼
                       TXT       JSON      SARIF
```

---

## 3. Core Optimization: Two-Stage Analysis Pipeline

ErrataGuard's most critical performance principle is:

$$\text{Cheap Candidate Filtering} \longrightarrow \text{Lazy Expensive Contextual Verification}$$

1. **Stage 1 (Fast Pre-Filter):**
   - Filters $100,000+$ instructions down to a handful of candidate instructions using cheap properties: instruction mnemonic, class (branch, load, store, system), and destination registers.
   - **Conservative Invariant:** False negatives are completely unacceptable. No instruction that could trigger an active rule is ever discarded.
2. **Stage 2 (Localized Context Verification):**
   - Context analysis (sliding instruction window, data dependencies, and optional CFG construction) is performed **lazily** and only on candidate instructions.
   - Rules requiring CFGs or deep data flow avoid full-binary overhead.

---

## 4. Installation

### Requirements
- Python 3.11 or later
- Operating System: Linux, macOS, or Windows

### Install with pip
```bash
# Clone the repository
git clone https://github.com/errataguard/errataguard.git
cd errataguard

# Install package and dependencies
pip install -e .
```

---

## 5. Usage & CLI Commands

ErrataGuard provides a clean CLI with standardized exit codes for CI integration:
- `0`: PASS (no errata trigger conditions detected)
- `1`: FAIL (one or more erratum triggers detected)
- `2`: ERROR (analyzer, configuration, or input error)

### Basic Analysis
```bash
errataguard firmware.elf
```

### Specify Target CPU and Revision
```bash
errataguard firmware.elf \
    --cpu cortex-a53 \
    --revision r0p2
```

### JSON Output
```bash
errataguard firmware.elf \
    --rules rules/demo \
    --format json
```

### SARIF Output (GitHub Code Scanning)
```bash
errataguard firmware.elf \
    --rules rules/demo \
    --format sarif > errataguard.sarif
```

### Before / After Verification Mode
Verify that a rebuild or workaround resolved the erratum without introducing new issues:
```bash
errataguard verify \
    --before examples/vulnerable/firmware.elf \
    --after examples/fixed/firmware_fixed.elf \
    --cpu cortex-a53 \
    --revision r0p2
```

---

## 6. Output Examples

### Terminal Output (FAIL)
```
$ errataguard firmware.elf --cpu cortex-a53 --revision r0p2

ErrataGuard v0.1.0
==================
Binary:
    firmware.elf
Architecture:
    AArch64
CPU:
    cortex-a53 r0p2
Rules:
    2 loaded
Analysis:
    Instructions scanned: 18,421
    Candidates: 1
    Detailed checks: 1
    Duration: 0.0004s
Result:
    FAIL

Findings:
--------------------------------------------------
[A53-DEMO-001] Demo ADRP-LDR sequence vulnerability
Address:
    0x0040082C
Function:
    process_data()
Source:
    demo.c:7
Matched conditions:
    ✓ candidate instruction 'adrp'
    ✓ CPU revision affected (r0p2)
    ✓ ADRP instruction immediately followed by LDR
    ✓ LDR depends on ADRP destination register
Workaround:
    DEMO ONLY. Insert a NOP or insert an intervening independent instruction between ADRP and LDR.
References:
    - DEMO RULE - NON-AUTHORITATIVE ARCHITECTURAL DEMO
Confidence:
    Static match
--------------------------------------------------
```

### Terminal Output (PASS)
```
$ errataguard firmware_fixed.elf --cpu cortex-a53 --revision r0p2

ErrataGuard v0.1.0
==================
Binary:
    firmware_fixed.elf
Architecture:
    AArch64
CPU:
    cortex-a53 r0p2
Rules:
    2 loaded
Analysis:
    Instructions scanned: 18,422
    Candidates: 1
    Detailed checks: 1
    Duration: 0.0004s
Result:
    PASS

No statically detectable supported trigger conditions were found in the analyzed binary.
```

### Verification Mode Output
```
$ errataguard verify --before firmware.elf --after firmware_fixed.elf --cpu cortex-a53 --revision r0p2

ErrataGuard Verification
========================
Before findings:
    1
After findings:
    0
Resolved:
    A53-DEMO-001
Result:
    PASS
Interpretation:
    The documented statically detectable trigger condition is no longer present in the analyzed binary.
```

---

## 7. Rule Format & Specification

Rules are loaded from external YAML files and parsed safely with `yaml.safe_load`.

```yaml
erratum: A53-DEMO-001
title: Demo ADRP-LDR sequence vulnerability
architecture: AArch64
cpu: Cortex-A53
authoritative: false
affected_revisions:
  - r0p0
  - r0p1
  - r0p2
candidate:
  mnemonics:
    - adrp
conditions:
  - type: instruction_sequence
    description: "ADRP instruction immediately followed by LDR"
    pattern:
      - ldr
  - type: register_dependency
    description: "LDR depends on ADRP destination register"
    dependency: destination_to_source
    offset: 1
workaround:
  description: >
    DEMO ONLY. Insert a NOP or insert an intervening independent instruction between ADRP and LDR.
references:
  - "DEMO RULE - NON-AUTHORITATIVE ARCHITECTURAL DEMO"
severity: warning
```

> [!NOTE]
> Rules in `rules/demo/` are explicitly synthetic demo rules to validate the static analyzer architecture without inventing unauthorized ARM errata conditions. Authoritative ARM errata rules can be dropped directly into the directory without modifying analyzer code.

---

## 8. DWARF Source Mapping

If the target ELF binary contains DWARF debug sections (`.debug_line`, `.debug_info`, `.debug_abbrev`), ErrataGuard indexes the line table:
```
Virtual Address (0x0040082C) ──► DWARF Engine ──► demo.c:7
```
If the binary is stripped or lacks debug info, ErrataGuard degrades gracefully, reporting `Source: unavailable` and function `<unknown>` without failing the scan.

---

## 9. Continuous Integration (GitHub Actions)

Add ErrataGuard as a post-build verification step in your GitHub Actions workflow:

```yaml
name: Firmware Errata Verification

on: [push, pull_request]

jobs:
  verify-errata:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install ErrataGuard
        run: pip install -e .

      - name: Build Firmware
        run: |
          aarch64-linux-gnu-gcc -g -O2 -o build/firmware.elf src/main.c

      - name: Run ErrataGuard Verification
        run: |
          errataguard build/firmware.elf \
            --cpu cortex-a53 \
            --revision r0p2 \
            --format sarif > errataguard.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: errataguard.sarif
```

---

## 10. Benchmarking & Performance Methodology

> [!TIP]
> **Performance Disclaimer:**
> Performance numbers are environment-dependent and must be measured on the benchmark machine.

We benchmark both execution modes on a synthetic binary containing **100,000 instructions**:
1. **Baseline Analyzer:** Evaluates all rules on all 100,000 instructions.
2. **Optimized Analyzer:** Uses candidate pre-filtering to eliminate irrelevant instructions before detailed contextual evaluation.

### Measured Results (100,000 instructions)
```
Metric                         | Baseline     | Optimized   
------------------------------------------------------------
Total instructions             | 100,000      | 100,000     
Candidate filter checks        | 0 (all)      | 1           
Detailed contextual checks     | 100,000      | 1           
Findings detected              | 1            | 1           
------------------------------------------------------------
Detailed evaluation time       | 350.659 ms   | 0.059 ms
Evaluation Stage Speedup       | 5923x faster
```

### Critical Correctness Guarantee
The benchmark script automatically asserts that:
$$\text{Baseline Findings} \equiv \text{Optimized Findings}$$
If the optimized analyzer ever produces a different set of findings than the baseline analyzer, the test suite aborts.

Run the benchmarks yourself:
```bash
python benchmarks/optimized.py
```

---

## 11. Testing

The test suite covers unit and end-to-end integration tests:
- **ELF Parsing:** Valid ELF, corrupt magic bytes, missing files, unsupported architectures, missing executable sections.
- **AArch64 Disassembly:** Capstone decoding, symbol table mapping, stripped binaries.
- **Candidate Filtering:** Acceptance, rejection, conservative non-elimination guarantees.
- **Rules & Schema:** YAML safety, schema validation, CPU revision matching.
- **DWARF Line Mapping:** Address-to-source resolution, stripped binary fallback.
- **Reporting:** Terminal formatting, JSON schema validation, SARIF 2.1.0 compliance.
- **Integration:** Vulnerable, fixed, negative, and unaffected CPU revision binaries.

Run tests:
```bash
python -m pytest -v
```

---

## 12. Security Considerations

- **Untrusted Input:** Target ELF binaries are treated as untrusted data. ErrataGuard never executes the binary or embedded code.
- **Safe Parsing:** Uses `yaml.safe_load` for rule parsing. No `eval()`, `exec()`, or dynamic code execution is permitted.
- **Path Sanitization:** File paths and locations are resolved safely without invoking shell interpreters.

---

## 13. Limitations & Future Work

- **Static Detectability:** Only statically detectable instruction patterns within executable sections can be verified. Dynamic runtime conditions (bus delays, cache line flushes, external interrupt timing) are beyond static ELF scope.
- **Stripped Binaries:** Function names and line numbers rely on symbols and DWARF. In stripped binaries, addresses and basic blocks are verified, but source lines are reported as `unavailable`.
- **Future Work:**
  - Ingestion of official ARM Silicon Errata Notice data files once verified.
  - Multi-threaded function-level parallel analysis for multi-megabyte monolithic kernels.
  - Integration with linker scripts for automated relaxation hints.
