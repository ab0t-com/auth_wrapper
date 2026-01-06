#!/usr/bin/env python3
"""
Publish ab0t-auth to PyPI.

Usage:
    python scripts/publish.py              # Build and publish to PyPI
    python scripts/publish.py --test       # Publish to TestPyPI first
    python scripts/publish.py --build-only # Build without publishing
    python scripts/publish.py --check      # Check package before publishing
"""

import argparse
import subprocess
import sys
import shutil
from pathlib import Path


def get_project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).parent.parent


def run_command(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a command and handle errors."""
    print(f"  → {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=False)
    if check and result.returncode != 0:
        print(f"Command failed with exit code {result.returncode}")
        sys.exit(result.returncode)
    return result


def clean_build_dirs(project_root: Path) -> None:
    """Clean previous build artifacts."""
    dirs_to_clean = ["dist", "build", "src/ab0t_auth.egg-info"]

    for dir_name in dirs_to_clean:
        dir_path = project_root / dir_name
        if dir_path.exists():
            print(f"  Removing {dir_name}/")
            shutil.rmtree(dir_path)


def check_tools() -> bool:
    """Check that required tools are installed."""
    tools = {
        "build": [sys.executable, "-m", "build", "--version"],
        "twine": [sys.executable, "-m", "twine", "--version"],
    }

    missing = []
    for name, cmd in tools.items():
        try:
            subprocess.run(cmd, capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            missing.append(name)

    if missing:
        print(f"Missing tools: {', '.join(missing)}")
        print(f"Install with: pip install {' '.join(missing)}")
        return False

    return True


def build_package(project_root: Path) -> bool:
    """Build the package."""
    print("\n[Build] Creating distribution packages...")

    result = run_command(
        [sys.executable, "-m", "build", str(project_root)],
        check=False,
    )

    if result.returncode != 0:
        print("Build failed!")
        return False

    # List built files
    dist_dir = project_root / "dist"
    if dist_dir.exists():
        print("\nBuilt packages:")
        for f in dist_dir.iterdir():
            print(f"  - {f.name}")

    return True


def check_package(project_root: Path) -> bool:
    """Check the package with twine."""
    print("\n[Check] Validating package...")

    dist_dir = project_root / "dist"
    if not dist_dir.exists() or not list(dist_dir.iterdir()):
        print("No packages found in dist/. Run build first.")
        return False

    result = run_command(
        [sys.executable, "-m", "twine", "check", str(dist_dir / "*")],
        check=False,
    )

    return result.returncode == 0


def publish_package(project_root: Path, test_pypi: bool = False) -> bool:
    """Publish the package to PyPI or TestPyPI."""
    dist_dir = project_root / "dist"

    if not dist_dir.exists() or not list(dist_dir.iterdir()):
        print("No packages found in dist/. Run build first.")
        return False

    if test_pypi:
        print("\n[Publish] Uploading to TestPyPI...")
        cmd = [
            sys.executable, "-m", "twine", "upload",
            "--repository", "testpypi",
            str(dist_dir / "*"),
        ]
    else:
        print("\n[Publish] Uploading to PyPI...")
        cmd = [
            sys.executable, "-m", "twine", "upload",
            str(dist_dir / "*"),
        ]

    result = run_command(cmd, check=False)

    if result.returncode == 0:
        if test_pypi:
            print("\nPublished to TestPyPI!")
            print("Install with: pip install --index-url https://test.pypi.org/simple/ ab0t-auth")
        else:
            print("\nPublished to PyPI!")
            print("Install with: pip install ab0t-auth")
        return True

    return False


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Publish ab0t-auth to PyPI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s                  Build and publish to PyPI
    %(prog)s --test           Publish to TestPyPI first
    %(prog)s --build-only     Build without publishing
    %(prog)s --check          Check package validity
    %(prog)s --clean          Clean build artifacts only

Environment:
    TWINE_USERNAME    PyPI username (or use __token__ for API tokens)
    TWINE_PASSWORD    PyPI password or API token

For API tokens, set:
    export TWINE_USERNAME=__token__
    export TWINE_PASSWORD=pypi-xxxxxxxxxxxx
        """,
    )

    parser.add_argument(
        "--test",
        action="store_true",
        help="Publish to TestPyPI instead of PyPI",
    )
    parser.add_argument(
        "--build-only",
        action="store_true",
        help="Build package without publishing",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check package validity only",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Clean build artifacts only",
    )
    parser.add_argument(
        "--no-clean",
        action="store_true",
        help="Skip cleaning before build",
    )

    args = parser.parse_args()
    project_root = get_project_root()

    print("=" * 60)
    print("Ab0t Auth - Package Publisher")
    print("=" * 60)

    # Clean only
    if args.clean:
        print("\n[Clean] Removing build artifacts...")
        clean_build_dirs(project_root)
        print("Done!")
        return 0

    # Check tools
    print("\n[Setup] Checking required tools...")
    if not check_tools():
        return 1
    print("  All tools available")

    # Clean previous builds
    if not args.no_clean and not args.check:
        print("\n[Clean] Removing previous build artifacts...")
        clean_build_dirs(project_root)

    # Check only
    if args.check:
        if check_package(project_root):
            print("\nPackage check passed!")
            return 0
        else:
            print("\nPackage check failed!")
            return 1

    # Build
    if not build_package(project_root):
        return 1

    # Check
    if not check_package(project_root):
        print("\nPackage validation failed!")
        return 1

    # Build only
    if args.build_only:
        print("\nBuild complete (--build-only specified)")
        return 0

    # Publish
    if publish_package(project_root, test_pypi=args.test):
        return 0
    else:
        print("\nPublish failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
