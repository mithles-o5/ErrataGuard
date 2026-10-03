import sys
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


from typing import Tuple

from errataguard.config import CPUInfo
from errataguard.elf.parser import parse_elf
from errataguard.rules.loader import load_rules
from errataguard.analysis.verifier import StaticVerifier
from errataguard.reporting.models import AnalysisReport
from benchmarks.baseline import run_baseline_benchmark


def run_optimized_benchmark(
    binary_path: Path,
    rules_dir: Path,
    cpu: CPUInfo,
) -> Tuple[AnalysisReport, dict[str, float]]:
    """Execute optimized verification and measure component latencies."""
    timings: dict[str, float] = {}

    t0 = time.perf_counter()
    rules = load_rules(rules_dir)
    timings["rules_loading"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    elf = parse_elf(binary_path)
    timings["elf_parsing"] = time.perf_counter() - t0

    verifier = StaticVerifier(rules=rules, cpu=cpu)

    t0 = time.perf_counter()
    report = verifier.analyze(elf, baseline=False)
    timings["analysis_total"] = time.perf_counter() - t0
    timings["disassembly"] = report.statistics.stage_durations.get("disassembly", 0.0)
    timings["candidate_filtering"] = report.statistics.stage_durations.get("candidate_filtering", 0.0)
    timings["evaluation"] = report.statistics.stage_durations.get("evaluation", 0.0)
    timings["total"] = timings["rules_loading"] + timings["elf_parsing"] + timings["analysis_total"]

    return report, timings


def verify_equivalence(baseline_report: AnalysisReport, optimized_report: AnalysisReport) -> bool:
    """CRITICAL CORRECTNESS CHECK: Ensure optimized produces exactly the same findings as baseline."""
    b_findings = [(f.erratum_id, f.address, f.source_display) for f in baseline_report.findings]
    o_findings = [(f.erratum_id, f.address, f.source_display) for f in optimized_report.findings]

    if b_findings != o_findings:
        print("ERROR: Finding mismatch between baseline and optimized!", file=sys.stderr)
        print(f"Baseline findings ({len(b_findings)}): {b_findings}", file=sys.stderr)
        print(f"Optimized findings ({len(o_findings)}): {o_findings}", file=sys.stderr)
        return False
    return True


def main():
    root = Path(__file__).resolve().parent.parent
    rules_dir = root / "rules" / "demo"

    # Default to synthetic large binary or vulnerable demo
    synthetic_elf = root / "benchmarks" / "synthetic_100k.elf"
    if not synthetic_elf.exists():
        from tests.fixtures.elf_generator import create_synthetic_benchmark_elf
        print("Generating 100,000+ instruction benchmark fixture...")
        create_synthetic_benchmark_elf(synthetic_elf, total_instructions=100_000)

    target = sys.argv[1] if len(sys.argv) > 1 else str(synthetic_elf)
    cpu = CPUInfo(architecture="AArch64", model="cortex-a53", revision="r0p2")

    print(f"Benchmarking target binary: {target}")
    print("=" * 60)

    # Run Baseline
    print("Running baseline analysis (no filtering)...")
    base_report, base_timings = run_baseline_benchmark(Path(target), rules_dir, cpu)

    # Run Optimized
    print("Running optimized analysis (candidate filtering)...")
    opt_report, opt_timings = run_optimized_benchmark(Path(target), rules_dir, cpu)

    # Verify Correctness
    print("\nVerifying Correctness:")
    print("----------------------")
    match = verify_equivalence(base_report, opt_report)
    if not match:
        sys.exit(1)
    print("✓ PASS: Baseline findings and Optimized findings are IDENTICAL.")

    # Performance Comparison
    eval_speedup = (
        base_timings["evaluation"] / opt_timings["evaluation"]
        if opt_timings["evaluation"] > 0 else 1.0
    )
    analysis_speedup = (
        base_timings["analysis_total"] / opt_timings["analysis_total"]
        if opt_timings["analysis_total"] > 0 else 1.0
    )

    print("\nBenchmark Summary & Metrics:")
    print("============================================================")
    print(f"{'Metric':<30} | {'Baseline':<12} | {'Optimized':<12}")
    print("-" * 60)
    print(f"{'Total instructions':<30} | {base_report.statistics.instructions_scanned:<12,} | {opt_report.statistics.instructions_scanned:<12,}")
    print(f"{'Candidate filter checks':<30} | {'0 (all checked)':<12} | {opt_report.statistics.candidates_found:<12,}")
    print(f"{'Detailed contextual checks':<30} | {base_report.statistics.detailed_checks:<12,} | {opt_report.statistics.detailed_checks:<12,}")
    print(f"{'Findings detected':<30} | {len(base_report.findings):<12} | {len(opt_report.findings):<12}")
    print("-" * 60)
    print(f"{'ELF Parsing time':<30} | {base_timings['elf_parsing']*1000:<10.3f}ms | {opt_timings['elf_parsing']*1000:<10.3f}ms")
    print(f"{'Disassembly time':<30} | {base_timings['disassembly']*1000:<10.3f}ms | {opt_timings['disassembly']*1000:<10.3f}ms")
    print(f"{'Candidate filtering time':<30} | {'N/A':<12} | {opt_timings['candidate_filtering']*1000:<10.3f}ms")
    print(f"{'Detailed evaluation time':<30} | {base_timings['evaluation']*1000:<10.3f}ms | {opt_timings['evaluation']*1000:<10.3f}ms")
    print(f"{'Analysis stage total':<30} | {base_timings['analysis_total']*1000:<10.3f}ms | {opt_timings['analysis_total']*1000:<10.3f}ms")
    print("=" * 60)
    print(f"Evaluation Stage Speedup: {eval_speedup:.2f}x faster")
    print(f"Analysis Stage Speedup:   {analysis_speedup:.2f}x faster")
    print("\nNote: Performance numbers are environment-dependent and must be measured on the benchmark machine.")


if __name__ == "__main__":
    main()
