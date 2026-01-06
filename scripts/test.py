#!/usr/bin/env python3
"""
Test runner script for ab0t_auth.

Usage:
    python scripts/test.py              # Run all tests
    python scripts/test.py -v           # Verbose output
    python scripts/test.py --cov        # With coverage
    python scripts/test.py -k tenant    # Run only tenant tests
    python scripts/test.py --fast       # Skip slow tests
"""

import argparse
import subprocess
import sys
from pathlib import Path


def get_project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).parent.parent


def run_tests(
    verbose: bool = False,
    coverage: bool = False,
    coverage_html: bool = False,
    pattern: str | None = None,
    markers: str | None = None,
    fast: bool = False,
    failed_first: bool = False,
    last_failed: bool = False,
    parallel: bool = False,
    extra_args: list[str] | None = None,
) -> int:
    """
    Run pytest with specified options.

    Returns exit code from pytest.
    """
    project_root = get_project_root()
    tests_dir = project_root / "tests"

    # Build pytest command
    cmd = [sys.executable, "-m", "pytest", str(tests_dir)]

    # Verbosity
    if verbose:
        cmd.append("-v")

    # Coverage
    if coverage or coverage_html:
        cmd.extend(["--cov=ab0t_auth", "--cov-report=term-missing"])
        if coverage_html:
            cmd.append("--cov-report=html")

    # Pattern filter (-k)
    if pattern:
        cmd.extend(["-k", pattern])

    # Marker filter (-m)
    if markers:
        cmd.extend(["-m", markers])

    # Fast mode - skip slow tests
    if fast:
        cmd.extend(["-m", "not slow"])

    # Failed first
    if failed_first:
        cmd.append("--ff")

    # Last failed only
    if last_failed:
        cmd.append("--lf")

    # Parallel execution (requires pytest-xdist)
    if parallel:
        cmd.extend(["-n", "auto"])

    # Short traceback by default
    cmd.append("--tb=short")

    # Extra arguments
    if extra_args:
        cmd.extend(extra_args)

    # Run pytest
    print(f"Running: {' '.join(cmd)}")
    print("-" * 60)

    result = subprocess.run(cmd, cwd=project_root)
    return result.returncode


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Run ab0t_auth tests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s                    Run all tests
    %(prog)s -v                 Verbose output
    %(prog)s --cov              With coverage report
    %(prog)s --cov-html         With HTML coverage report
    %(prog)s -k tenant          Run tests matching 'tenant'
    %(prog)s -k "jwt or token"  Run JWT or token tests
    %(prog)s --fast             Skip slow tests
    %(prog)s --ff               Run failed tests first
    %(prog)s --lf               Run only last failed tests
    %(prog)s -p                 Run tests in parallel
        """,
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose test output",
    )
    parser.add_argument(
        "--cov", "--coverage",
        action="store_true",
        dest="coverage",
        help="Run with coverage report",
    )
    parser.add_argument(
        "--cov-html",
        action="store_true",
        dest="coverage_html",
        help="Generate HTML coverage report",
    )
    parser.add_argument(
        "-k", "--pattern",
        type=str,
        help="Only run tests matching pattern",
    )
    parser.add_argument(
        "-m", "--markers",
        type=str,
        help="Only run tests with given markers",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Skip slow tests",
    )
    parser.add_argument(
        "--ff", "--failed-first",
        action="store_true",
        dest="failed_first",
        help="Run failed tests first",
    )
    parser.add_argument(
        "--lf", "--last-failed",
        action="store_true",
        dest="last_failed",
        help="Run only last failed tests",
    )
    parser.add_argument(
        "-p", "--parallel",
        action="store_true",
        help="Run tests in parallel (requires pytest-xdist)",
    )
    parser.add_argument(
        "extra_args",
        nargs="*",
        help="Additional arguments to pass to pytest",
    )

    args = parser.parse_args()

    return run_tests(
        verbose=args.verbose,
        coverage=args.coverage,
        coverage_html=args.coverage_html,
        pattern=args.pattern,
        markers=args.markers,
        fast=args.fast,
        failed_first=args.failed_first,
        last_failed=args.last_failed,
        parallel=args.parallel,
        extra_args=args.extra_args if args.extra_args else None,
    )


if __name__ == "__main__":
    sys.exit(main())
