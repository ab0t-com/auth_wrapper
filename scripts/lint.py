#!/usr/bin/env python3
"""
Linting and formatting script for ab0t_auth.

Usage:
    python scripts/lint.py              # Check all (no changes)
    python scripts/lint.py --fix        # Auto-fix issues
    python scripts/lint.py --format     # Format only (black + isort)
    python scripts/lint.py --check      # Check only (CI mode)
"""

import argparse
import subprocess
import sys
from pathlib import Path


def get_project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).parent.parent


def run_command(cmd: list[str], check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    """Run a command and handle errors."""
    print(f"  → {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
    )
    if check and result.returncode != 0:
        return result
    return result


def run_black(paths: list[str], check_only: bool = False) -> int:
    """Run black formatter."""
    cmd = [sys.executable, "-m", "black"]
    if check_only:
        cmd.append("--check")
    cmd.extend(paths)
    result = run_command(cmd, check=False)
    return result.returncode


def run_isort(paths: list[str], check_only: bool = False) -> int:
    """Run isort import sorter."""
    cmd = [sys.executable, "-m", "isort"]
    if check_only:
        cmd.append("--check-only")
    cmd.extend(paths)
    result = run_command(cmd, check=False)
    return result.returncode


def run_ruff(paths: list[str], fix: bool = False) -> int:
    """Run ruff linter."""
    cmd = [sys.executable, "-m", "ruff", "check"]
    if fix:
        cmd.append("--fix")
    cmd.extend(paths)
    result = run_command(cmd, check=False)
    return result.returncode


def run_mypy(paths: list[str]) -> int:
    """Run mypy type checker."""
    cmd = [sys.executable, "-m", "mypy"]
    cmd.extend(paths)
    result = run_command(cmd, check=False)
    return result.returncode


def run_flake8(paths: list[str]) -> int:
    """Run flake8 linter."""
    cmd = [sys.executable, "-m", "flake8"]
    cmd.extend(paths)
    result = run_command(cmd, check=False)
    return result.returncode


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Lint and format ab0t_auth code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s                    Check all (no changes made)
    %(prog)s --fix              Auto-fix all fixable issues
    %(prog)s --format           Format code only (black + isort)
    %(prog)s --check            Strict check mode (for CI)
    %(prog)s --mypy             Run type checking only
    %(prog)s --ruff             Run ruff linter only
        """,
    )

    parser.add_argument(
        "--fix",
        action="store_true",
        help="Auto-fix issues where possible",
    )
    parser.add_argument(
        "--format",
        action="store_true",
        dest="format_only",
        help="Run formatters only (black + isort)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check mode - fail on any issues (for CI)",
    )
    parser.add_argument(
        "--black",
        action="store_true",
        help="Run black only",
    )
    parser.add_argument(
        "--isort",
        action="store_true",
        help="Run isort only",
    )
    parser.add_argument(
        "--ruff",
        action="store_true",
        help="Run ruff only",
    )
    parser.add_argument(
        "--mypy",
        action="store_true",
        help="Run mypy only",
    )
    parser.add_argument(
        "--flake8",
        action="store_true",
        help="Run flake8 only",
    )

    args = parser.parse_args()

    project_root = get_project_root()
    src_path = str(project_root / "src")
    tests_path = str(project_root / "tests")
    paths = [src_path, tests_path]

    # Determine mode
    check_only = args.check and not args.fix
    fix_mode = args.fix

    # Track results
    results = {}
    exit_code = 0

    # Determine which tools to run
    run_all = not any([args.black, args.isort, args.ruff, args.mypy, args.flake8, args.format_only])
    run_formatters = args.format_only or run_all
    run_linters = not args.format_only or run_all

    print("=" * 60)
    print("Ab0t Auth Linting")
    print("=" * 60)

    # Formatters
    if run_formatters or args.black:
        print("\n[Black] Code formatter")
        results["black"] = run_black(paths, check_only=check_only and not fix_mode)
        if results["black"] != 0:
            exit_code = 1

    if run_formatters or args.isort:
        print("\n[isort] Import sorter")
        results["isort"] = run_isort(paths, check_only=check_only and not fix_mode)
        if results["isort"] != 0:
            exit_code = 1

    if args.format_only:
        # Stop here for format-only mode
        print("\n" + "=" * 60)
        print("Formatting complete!")
        return exit_code

    # Linters
    if (run_linters or args.ruff) and not args.format_only:
        print("\n[Ruff] Fast Python linter")
        results["ruff"] = run_ruff(paths, fix=fix_mode)
        if results["ruff"] != 0:
            exit_code = 1

    if args.flake8:
        print("\n[Flake8] Style checker")
        results["flake8"] = run_flake8(paths)
        if results["flake8"] != 0:
            exit_code = 1

    # Type checker
    if args.mypy:
        print("\n[Mypy] Type checker")
        results["mypy"] = run_mypy([src_path])
        if results["mypy"] != 0:
            exit_code = 1

    # Summary
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)

    for tool, code in results.items():
        status = "PASS" if code == 0 else "FAIL"
        symbol = "✓" if code == 0 else "✗"
        print(f"  {symbol} {tool}: {status}")

    print()
    if exit_code == 0:
        print("All checks passed!")
    else:
        print("Some checks failed. Run with --fix to auto-fix issues.")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
