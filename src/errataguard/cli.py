"""Command-line interface (CLI) for ErrataGuard."""

import argparse
import logging
import sys
from pathlib import Path
from typing import Optional, Sequence

from errataguard import __version__
from errataguard.config import CPUInfo, Config
from errataguard.elf.parser import parse_elf
from errataguard.rules.loader import load_rules
from errataguard.analysis.verifier import StaticVerifier, compare_reports
from errataguard.reporting.terminal import render_terminal_report, render_verification_report
from errataguard.reporting.json import format_json_report, format_json_comparison
from errataguard.reporting.sarif import format_sarif_report
from errataguard.errors import ErrataGuardError

logger = logging.getLogger("errataguard")


def setup_logging(verbose: bool) -> None:
    """Configure console logging level and format."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="[%(levelname)s] %(message)s",
        stream=sys.stderr,
    )



def resolve_default_rules_dir() -> Path:
    """Find default rules directory in workspace or relative to package."""
    candidates = [
        Path.cwd() / "rules" / "demo",
        Path.cwd() / "rules",
        Path(__file__).resolve().parent.parent.parent / "rules" / "demo",
        Path(__file__).resolve().parent.parent.parent / "rules",
    ]
    for c in candidates:
        if c.exists() and c.is_dir():
            return c
    return Path.cwd() / "rules" / "demo"


def parse_arguments(args: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command line arguments."""
    argv = list(args) if args is not None else sys.argv[1:]

    if argv and argv[0] == "verify":
        verify_parser = argparse.ArgumentParser(
            prog="errataguard verify",
            description="Compare before and after binaries to verify mitigation",
        )
        verify_parser.add_argument(
            "--before",
            type=Path,
            required=True,
            help="Path to unmitigated (before) ELF binary",
        )
        verify_parser.add_argument(
            "--after",
            type=Path,
            required=True,
            help="Path to mitigated (after) ELF binary",
        )
        verify_parser.add_argument(
            "--cpu",
            type=str,
            default="cortex-a53",
            help="Target CPU model (default: cortex-a53)",
        )
        verify_parser.add_argument(
            "--revision",
            type=str,
            default=None,
            help="Target CPU revision (e.g. r0p2, r0p4)",
        )
        verify_parser.add_argument(
            "--rules",
            type=Path,
            default=None,
            help="Path to rules directory or YAML file (default: rules/demo)",
        )
        verify_parser.add_argument(
            "--format",
            choices=["terminal", "json"],
            default="terminal",
            help="Output report format (default: terminal)",
        )
        verify_parser.add_argument(
            "-v", "--verbose",
            action="store_true",
            help="Enable verbose debug logging",
        )
        ns = verify_parser.parse_args(argv[1:])
        ns.subcommand = "verify"
        return ns

    parser = argparse.ArgumentParser(
        prog="errataguard",
        description="AArch64 Cortex-A53 Errata Static Verification Prototype",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "binary",
        nargs="?",
        type=Path,
        help="Target AArch64 ELF binary to analyze",
    )
    parser.add_argument(
        "--cpu",
        type=str,
        default="cortex-a53",
        help="Target CPU model (default: cortex-a53)",
    )
    parser.add_argument(
        "--revision",
        type=str,
        default=None,
        help="Target CPU revision (e.g. r0p2, r0p4)",
    )
    parser.add_argument(
        "--rules",
        type=Path,
        default=None,
        help="Path to rules directory or YAML file (default: rules/demo)",
    )
    parser.add_argument(
        "--format",
        choices=["terminal", "json", "sarif"],
        default="terminal",
        help="Output report format (default: terminal)",
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="Run baseline analysis without fast candidate pre-filtering",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debug logging",
    )
    ns = parser.parse_args(argv)
    ns.subcommand = "analyze"
    return ns



def run_verify(args: argparse.Namespace) -> int:
    """Execute before/after verification mode."""
    rules_path = args.rules or resolve_default_rules_dir()
    cpu_info = CPUInfo(architecture="AArch64", model=args.cpu, revision=args.revision)

    logger.debug("Loading rules from %s", rules_path)
    rules = load_rules(rules_path)

    logger.debug("Parsing before binary: %s", args.before)
    elf_before = parse_elf(args.before)

    logger.debug("Parsing after binary: %s", args.after)
    elf_after = parse_elf(args.after)

    verifier = StaticVerifier(rules=rules, cpu=cpu_info)

    report_before = verifier.analyze(elf_before)
    report_after = verifier.analyze(elf_after)

    comparison = compare_reports(report_before, report_after)

    if args.format == "json":
        sys.stdout.write(format_json_comparison(comparison) + "\n")
    else:
        render_verification_report(comparison, sys.stdout)

    return comparison.exit_code


def run_analyze(args: argparse.Namespace) -> int:
    """Execute single binary analysis."""
    if not args.binary:
        sys.stderr.write("ERROR: Missing required target binary path.\nRun 'errataguard --help' for usage.\n")
        return 2

    rules_path = args.rules or resolve_default_rules_dir()
    cpu_info = CPUInfo(architecture="AArch64", model=args.cpu, revision=args.revision)

    logger.debug("Loading rules from %s", rules_path)
    rules = load_rules(rules_path)

    logger.debug("Parsing target binary: %s", args.binary)
    elf_image = parse_elf(args.binary)

    verifier = StaticVerifier(rules=rules, cpu=cpu_info)
    report = verifier.analyze(elf_image, baseline=args.baseline)

    if args.format == "json":
        sys.stdout.write(format_json_report(report) + "\n")
    elif args.format == "sarif":
        sys.stdout.write(format_sarif_report(report) + "\n")
    else:
        render_terminal_report(report, sys.stdout)

    return report.exit_code


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Main entrypoint for CLI execution."""
    try:
        args = parse_arguments(argv)
        setup_logging(args.verbose)

        if args.subcommand == "verify":
            return run_verify(args)
        else:
            return run_analyze(args)

    except ErrataGuardError as err:
        sys.stderr.write(f"ERROR: {err}\n")
        return 2
    except KeyboardInterrupt:
        sys.stderr.write("\nAnalysis interrupted by user.\n")
        return 2
    except Exception as ex:
        sys.stderr.write(f"UNEXPECTED ERROR: {ex}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
