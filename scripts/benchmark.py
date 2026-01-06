#!/usr/bin/env python3
"""
Performance benchmark for ab0t-auth.

Usage:
    python scripts/benchmark.py              # Run all benchmarks
    python scripts/benchmark.py --quick      # Quick benchmark (fewer iterations)
    python scripts/benchmark.py --json       # Output results as JSON
    python scripts/benchmark.py --save       # Save results to file
"""

import argparse
import asyncio
import json
import statistics
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Any

# Add src to path for local testing
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ab0t_auth.core import AuthenticatedUser, AuthMethod, TokenType, TokenClaims
from ab0t_auth.permissions import (
    check_permission,
    check_any_permission,
    check_all_permissions,
    check_permission_pattern,
)
from ab0t_auth.cache import TokenCache, PermissionCache
from ab0t_auth.config import create_config


@dataclass
class BenchmarkResult:
    """Result of a benchmark run."""

    name: str
    iterations: int
    total_time_ms: float
    avg_time_ms: float
    min_time_ms: float
    max_time_ms: float
    p50_time_ms: float
    p95_time_ms: float
    p99_time_ms: float
    ops_per_second: float
    times: list[float] = field(default_factory=list, repr=False)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "iterations": self.iterations,
            "total_time_ms": round(self.total_time_ms, 3),
            "avg_time_ms": round(self.avg_time_ms, 4),
            "min_time_ms": round(self.min_time_ms, 4),
            "max_time_ms": round(self.max_time_ms, 4),
            "p50_time_ms": round(self.p50_time_ms, 4),
            "p95_time_ms": round(self.p95_time_ms, 4),
            "p99_time_ms": round(self.p99_time_ms, 4),
            "ops_per_second": round(self.ops_per_second, 0),
        }


def percentile(data: list[float], p: float) -> float:
    """Calculate percentile of data."""
    sorted_data = sorted(data)
    idx = int(len(sorted_data) * p / 100)
    return sorted_data[min(idx, len(sorted_data) - 1)]


def benchmark_sync(
    name: str,
    func: Callable[[], Any],
    iterations: int = 10000,
    warmup: int = 100,
) -> BenchmarkResult:
    """Benchmark a synchronous function."""

    # Warmup
    for _ in range(warmup):
        func()

    # Benchmark
    times = []
    start_total = time.perf_counter()

    for _ in range(iterations):
        start = time.perf_counter()
        func()
        end = time.perf_counter()
        times.append((end - start) * 1000)  # Convert to ms

    end_total = time.perf_counter()
    total_time_ms = (end_total - start_total) * 1000

    return BenchmarkResult(
        name=name,
        iterations=iterations,
        total_time_ms=total_time_ms,
        avg_time_ms=statistics.mean(times),
        min_time_ms=min(times),
        max_time_ms=max(times),
        p50_time_ms=percentile(times, 50),
        p95_time_ms=percentile(times, 95),
        p99_time_ms=percentile(times, 99),
        ops_per_second=iterations / (total_time_ms / 1000),
        times=times,
    )


async def benchmark_async(
    name: str,
    func: Callable[[], Any],
    iterations: int = 10000,
    warmup: int = 100,
) -> BenchmarkResult:
    """Benchmark an async function."""

    # Warmup
    for _ in range(warmup):
        await func()

    # Benchmark
    times = []
    start_total = time.perf_counter()

    for _ in range(iterations):
        start = time.perf_counter()
        await func()
        end = time.perf_counter()
        times.append((end - start) * 1000)

    end_total = time.perf_counter()
    total_time_ms = (end_total - start_total) * 1000

    return BenchmarkResult(
        name=name,
        iterations=iterations,
        total_time_ms=total_time_ms,
        avg_time_ms=statistics.mean(times),
        min_time_ms=min(times),
        max_time_ms=max(times),
        p50_time_ms=percentile(times, 50),
        p95_time_ms=percentile(times, 95),
        p99_time_ms=percentile(times, 99),
        ops_per_second=iterations / (total_time_ms / 1000),
        times=times,
    )


def create_test_user(num_permissions: int = 50) -> AuthenticatedUser:
    """Create a test user with permissions."""
    permissions = tuple(f"resource{i}:action{j}" for i in range(10) for j in range(num_permissions // 10))
    roles = ("user", "editor", "viewer")

    claims = TokenClaims(
        sub="user_123",
        email="test@example.com",
        org_id="org_456",
        permissions=permissions,
        roles=roles,
        exp=9999999999,
        raw={"tenant_id": "tenant_789"},
    )

    return AuthenticatedUser(
        user_id="user_123",
        email="test@example.com",
        org_id="org_456",
        permissions=permissions,
        roles=roles,
        auth_method=AuthMethod.JWT,
        token_type=TokenType.BEARER,
        claims=claims,
    )


def run_permission_benchmarks(iterations: int) -> list[BenchmarkResult]:
    """Run permission checking benchmarks."""
    results = []
    user = create_test_user(50)

    # Single permission check (exists)
    results.append(benchmark_sync(
        "check_permission (exists)",
        lambda: check_permission(user, "resource5:action2"),
        iterations=iterations,
    ))

    # Single permission check (not exists)
    results.append(benchmark_sync(
        "check_permission (not exists)",
        lambda: check_permission(user, "nonexistent:permission"),
        iterations=iterations,
    ))

    # Any permission check
    results.append(benchmark_sync(
        "check_any_permission (3 perms)",
        lambda: check_any_permission(user, "resource1:action1", "resource2:action2", "nonexistent:perm"),
        iterations=iterations,
    ))

    # All permissions check
    results.append(benchmark_sync(
        "check_all_permissions (3 perms)",
        lambda: check_all_permissions(user, "resource1:action1", "resource2:action2", "resource3:action3"),
        iterations=iterations,
    ))

    # Pattern matching
    results.append(benchmark_sync(
        "check_permission_pattern (resource5:*)",
        lambda: check_permission_pattern(user, "resource5:*"),
        iterations=iterations,
    ))

    # has_permission method
    results.append(benchmark_sync(
        "user.has_permission()",
        lambda: user.has_permission("resource5:action2"),
        iterations=iterations,
    ))

    # has_any_permission method
    results.append(benchmark_sync(
        "user.has_any_permission()",
        lambda: user.has_any_permission("resource1:action1", "nonexistent:perm"),
        iterations=iterations,
    ))

    return results


def run_cache_benchmarks(iterations: int) -> list[BenchmarkResult]:
    """Run cache benchmarks."""
    results = []
    config = create_config(auth_url="https://auth.example.com")

    # Token cache
    token_cache = TokenCache(max_size=1000, ttl=60)
    user = create_test_user()
    claims = user.claims

    # Pre-populate cache
    for i in range(100):
        token_cache.set(f"token_{i}", user, claims)

    # Cache hit
    results.append(benchmark_sync(
        "token_cache.get() (hit)",
        lambda: token_cache.get("token_50"),
        iterations=iterations,
    ))

    # Cache miss
    results.append(benchmark_sync(
        "token_cache.get() (miss)",
        lambda: token_cache.get("nonexistent_token"),
        iterations=iterations,
    ))

    # Cache set
    counter = [0]
    def cache_set():
        counter[0] += 1
        token_cache.set(f"new_token_{counter[0]}", user, claims)

    results.append(benchmark_sync(
        "token_cache.set()",
        cache_set,
        iterations=iterations,
    ))

    # Permission cache
    perm_cache = PermissionCache(max_size=1000, ttl=300)

    # Pre-populate
    for i in range(100):
        perm_cache.set(f"user_{i}", "resource:action", True)

    results.append(benchmark_sync(
        "permission_cache.get() (hit)",
        lambda: perm_cache.get("user_50", "resource:action"),
        iterations=iterations,
    ))

    results.append(benchmark_sync(
        "permission_cache.get() (miss)",
        lambda: perm_cache.get("nonexistent", "resource:action"),
        iterations=iterations,
    ))

    return results


def run_user_creation_benchmarks(iterations: int) -> list[BenchmarkResult]:
    """Run user object creation benchmarks."""
    results = []

    # Create user with minimal data
    results.append(benchmark_sync(
        "AuthenticatedUser (minimal)",
        lambda: AuthenticatedUser(
            user_id="user_123",
            auth_method=AuthMethod.JWT,
            token_type=TokenType.BEARER,
        ),
        iterations=iterations,
    ))

    # Create user with full data
    permissions = tuple(f"perm:{i}" for i in range(50))
    roles = ("admin", "user", "editor")

    results.append(benchmark_sync(
        "AuthenticatedUser (full, 50 perms)",
        lambda: AuthenticatedUser(
            user_id="user_123",
            email="test@example.com",
            org_id="org_456",
            permissions=permissions,
            roles=roles,
            auth_method=AuthMethod.JWT,
            token_type=TokenType.BEARER,
        ),
        iterations=iterations,
    ))

    return results


def print_results(results: list[BenchmarkResult], json_output: bool = False) -> None:
    """Print benchmark results."""
    if json_output:
        print(json.dumps({
            "timestamp": datetime.now().isoformat(),
            "results": [r.to_dict() for r in results],
        }, indent=2))
        return

    print("\n" + "=" * 80)
    print("BENCHMARK RESULTS")
    print("=" * 80)

    # Group by category
    categories = {}
    for r in results:
        if "permission" in r.name.lower() or "has_" in r.name.lower():
            cat = "Permission Checks"
        elif "cache" in r.name.lower():
            cat = "Cache Operations"
        elif "user" in r.name.lower() or "auth" in r.name.lower():
            cat = "Object Creation"
        else:
            cat = "Other"

        if cat not in categories:
            categories[cat] = []
        categories[cat].append(r)

    for category, cat_results in categories.items():
        print(f"\n{category}")
        print("-" * 80)
        print(f"{'Benchmark':<45} {'Ops/sec':>12} {'Avg':>10} {'P99':>10}")
        print("-" * 80)

        for r in cat_results:
            ops_str = f"{r.ops_per_second:,.0f}"
            avg_str = f"{r.avg_time_ms:.4f}ms"
            p99_str = f"{r.p99_time_ms:.4f}ms"
            print(f"{r.name:<45} {ops_str:>12} {avg_str:>10} {p99_str:>10}")

    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)

    # Calculate overall stats
    total_ops = sum(r.iterations for r in results)
    total_time = sum(r.total_time_ms for r in results)

    print(f"Total operations: {total_ops:,}")
    print(f"Total time: {total_time/1000:.2f}s")

    # Find fastest and slowest
    fastest = min(results, key=lambda r: r.avg_time_ms)
    slowest = max(results, key=lambda r: r.avg_time_ms)

    print(f"Fastest: {fastest.name} ({fastest.ops_per_second:,.0f} ops/sec)")
    print(f"Slowest: {slowest.name} ({slowest.ops_per_second:,.0f} ops/sec)")


def save_results(results: list[BenchmarkResult], path: Path) -> None:
    """Save benchmark results to file."""
    data = {
        "timestamp": datetime.now().isoformat(),
        "results": [r.to_dict() for r in results],
    }

    path.write_text(json.dumps(data, indent=2))
    print(f"\nResults saved to: {path}")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Run ab0t-auth performance benchmarks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s                Run all benchmarks (10,000 iterations)
    %(prog)s --quick        Quick run (1,000 iterations)
    %(prog)s --iterations 50000   Custom iteration count
    %(prog)s --json         Output as JSON
    %(prog)s --save         Save results to benchmarks/results.json
        """,
    )

    parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick benchmark with fewer iterations",
    )
    parser.add_argument(
        "--iterations", "-n",
        type=int,
        default=None,
        help="Number of iterations per benchmark",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Save results to file",
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Output file path (default: benchmarks/results.json)",
    )

    args = parser.parse_args()

    # Determine iterations
    if args.iterations:
        iterations = args.iterations
    elif args.quick:
        iterations = 1000
    else:
        iterations = 10000

    if not args.json:
        print("=" * 80)
        print("Ab0t Auth - Performance Benchmark")
        print("=" * 80)
        print(f"Iterations per benchmark: {iterations:,}")
        print("Running benchmarks...")

    # Run all benchmarks
    all_results = []

    all_results.extend(run_permission_benchmarks(iterations))
    all_results.extend(run_cache_benchmarks(iterations))
    all_results.extend(run_user_creation_benchmarks(iterations))

    # Print results
    print_results(all_results, json_output=args.json)

    # Save if requested
    if args.save:
        project_root = Path(__file__).parent.parent
        output_dir = project_root / "benchmarks"
        output_dir.mkdir(exist_ok=True)

        if args.output:
            output_path = Path(args.output)
        else:
            output_path = output_dir / f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        save_results(all_results, output_path)

    return 0


if __name__ == "__main__":
    sys.exit(main())
