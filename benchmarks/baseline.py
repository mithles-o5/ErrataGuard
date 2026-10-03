import sys
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typing import Tuple

from errataguard.config import CPUInfo
from errataguard.elf.parser import parse_elf
from errataguard.rules.loader import load_rules
from errataguard.analysis.verifier import StaticVerifier
from errataguard.reporting.models import AnalysisReport


def run_baseline_benchmark(
    binary_path: Path,
    rules_dir: Path,
    cpu: CPUInfo,
) -> Tuple[AnalysisReport, dict[str, float]]:
    """Execute baseline verification and measure component latencies."""
    timings: dict[str, float] = {}

    t0 = time.perf_counter()
    rules = load_rules(rules_dir)
    timings["rules_loading"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    elf = parse_elf(binary_path)
    timings["elf_parsing"] = time.perf_counter() - t0

    verifier = StaticVerifier(rules=rules, cpu=cpu)

    t0 = time.perf_counter()
    report = verifier.analyze(elf, baseline=True)
    timings["analysis_total"] = time.perf_counter() - t0
    timings["disassembly"] = report.statistics.stage_durations.get("disassembly", 0.0)
    timings["evaluation"] = report.statistics.stage_durations.get("evaluation", 0.0)
    timings["total"] = timings["rules_loading"] + timings["elf_parsing"] + timings["analysis_total"]

    return report, timings


def main():
    import sys
    root = Path(__file__).resolve().parent.parent
    rules_dir = root / "rules" / "demo"
    target = sys.argv[1] if len(sys.argv) > 1 else str(root / "examples" / "vulnerable" / "firmware.elf")
    cpu = CPUInfo(architecture="AArch64", model="cortex-a53", revision="r0p2")

    print(f"Running baseline benchmark on {target}...")
    report, timings = run_baseline_benchmark(Path(target), rules_dir, cpu)

    print("\nBaseline Benchmark Results:")
    print("----------------------------")
    print(f"Instructions:       {report.statistics.instructions_scanned:,}")
    print(f"Detailed checks:    {report.statistics.detailed_checks:,}")
    print(f"Findings:           {len(report.findings)}")
    print(f"ELF Parsing:        {timings['elf_parsing']*1000:.3f} ms")
    print(f"Disassembly:        {timings['disassembly']*1000:.3f} ms")
    print(f"Detailed Eval:      {timings['evaluation']*1000:.3f} ms")
    print(f"Total Time:         {timings['total']*1000:.3f} ms")


if __name__ == "__main__":
    main()
