#!/usr/bin/env python3
"""Benchmark certmonitor's chain validator at scale.

Two phases:

1. **Microbench** — how fast is ``certinfo.analyze_chain`` on a cached DER
   chain? Answers "how much CPU does always-on chain parsing actually cost?"
2. **Pipeline** — end-to-end runs against ~100 real hosts, concurrent.
   Answers "does the chain validator scale with concurrency, and does the
   structural validation hold up against the diversity of real-world chains?"

Run it from the repo root:

    uv run python scripts/bench_chain.py
    uv run python scripts/bench_chain.py --mode micro
    uv run python scripts/bench_chain.py --mode pipeline --concurrency 30

This is **not** part of CI. It's a local benchmark / sanity-check tool that
hits the public internet, so it's deliberately ad-hoc and tolerant of
network flakiness.
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import sys
import time
from pathlib import Path
from typing import List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from certmonitor import CertMonitor, certinfo  # noqa: E402

# A diverse set of stable public HTTPS endpoints. Picked to span CAs
# (Google Trust Services, DigiCert, Let's Encrypt, Sectigo, Amazon, etc.),
# chain depths, key types (RSA + ECDSA), and to avoid hosts that are known
# to require unusual user agents or aggressive rate limiting.
HOSTS: List[str] = [
    # Google
    "google.com",
    "www.google.com",
    "mail.google.com",
    "drive.google.com",
    "accounts.google.com",
    "youtube.com",
    "www.youtube.com",
    # Apple
    "apple.com",
    "www.apple.com",
    "icloud.com",
    "developer.apple.com",
    # Microsoft
    "microsoft.com",
    "www.microsoft.com",
    "azure.microsoft.com",
    "login.microsoftonline.com",
    "outlook.com",
    # Amazon
    "amazon.com",
    "www.amazon.com",
    "aws.amazon.com",
    "console.aws.amazon.com",
    # Meta / social
    "facebook.com",
    "www.facebook.com",
    "instagram.com",
    "www.instagram.com",
    "linkedin.com",
    "www.linkedin.com",
    "x.com",
    "www.x.com",
    # Dev / source
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "gist.github.com",
    "gitlab.com",
    "bitbucket.org",
    "stackoverflow.com",
    "www.stackoverflow.com",
    # Package registries
    "pypi.org",
    "www.python.org",
    "docs.python.org",
    "registry.npmjs.org",
    "www.npmjs.com",
    "crates.io",
    # Languages
    "rust-lang.org",
    "www.rust-lang.org",
    "doc.rust-lang.org",
    "go.dev",
    "nodejs.org",
    # Cloud / infra
    "cloudflare.com",
    "www.cloudflare.com",
    "fastly.com",
    "netlify.com",
    "vercel.com",
    "digitalocean.com",
    "heroku.com",
    "render.com",
    "supabase.com",
    # News / media
    "nytimes.com",
    "www.nytimes.com",
    "bbc.com",
    "bbc.co.uk",
    "cnn.com",
    "www.cnn.com",
    "reuters.com",
    "theguardian.com",
    "www.theguardian.com",
    # Knowledge
    "wikipedia.org",
    "en.wikipedia.org",
    "wikimedia.org",
    "mozilla.org",
    "www.mozilla.org",
    "archive.org",
    "web.archive.org",
    # Search / browsers
    "duckduckgo.com",
    "www.duckduckgo.com",
    "brave.com",
    # Privacy / messaging
    "signal.org",
    "proton.me",
    "discord.com",
    "www.discord.com",
    # Commerce / payments
    "stripe.com",
    "www.stripe.com",
    "paypal.com",
    "www.paypal.com",
    "shopify.com",
    "www.shopify.com",
    "ebay.com",
    "www.ebay.com",
    # Other widely-used
    "spotify.com",
    "www.spotify.com",
    "reddit.com",
    "www.reddit.com",
    "twitch.tv",
    "www.twitch.tv",
    "wordpress.com",
    "www.wordpress.com",
    "medium.com",
    "www.medium.com",
    "imgur.com",
    "www.imgur.com",
    "example.com",
    "www.example.com",
]


def _percentile(sorted_samples: List[float], p: float) -> float:
    if not sorted_samples:
        return 0.0
    k = min(int(len(sorted_samples) * p), len(sorted_samples) - 1)
    return sorted_samples[k]


def microbench(iterations: int) -> None:
    chain_dir = REPO_ROOT / "tests" / "fixtures"
    chain = [(chain_dir / f"chain_{i}.der").read_bytes() for i in range(3)]

    # Warm up to populate caches and pay one-time costs.
    for _ in range(200):
        certinfo.analyze_chain(chain)

    samples: List[float] = []
    for _ in range(iterations):
        t = time.perf_counter()
        certinfo.analyze_chain(chain)
        samples.append(time.perf_counter() - t)

    samples.sort()
    total = sum(samples)

    print("=" * 64)
    print("MICROBENCH — certinfo.analyze_chain (3-cert fixture)")
    print("=" * 64)
    print(f"  iterations:     {iterations:,}")
    print(f"  total time:     {total*1000:.1f} ms")
    print(f"  min:            {samples[0]*1e6:8.1f} us")
    print(f"  median:         {samples[len(samples) // 2]*1e6:8.1f} us")
    print(f"  p95:            {_percentile(samples, 0.95)*1e6:8.1f} us")
    print(f"  p99:            {_percentile(samples, 0.99)*1e6:8.1f} us")
    print(f"  max:            {samples[-1]*1e6:8.1f} us")
    print(f"  throughput:     {iterations / total:,.0f} calls/sec")
    print()


def _run_one(host: str, port: int, timeout: float) -> Tuple[str, bool, float, int, bool, str]:
    """Run CertMonitor synchronously. Returns (host, ok, elapsed_s, chain_len, chain_valid, error)."""
    start = time.perf_counter()
    try:
        with CertMonitor(
            host,
            port,
            enabled_validators=[
                "expiration",
                "hostname",
                "root_certificate",
                "chain",
            ],
        ) as cm:
            cm.get_cert_info()
            results = cm.validate()
        elapsed = time.perf_counter() - start
        chain = results.get("chain", {}) if isinstance(results, dict) else {}
        if not isinstance(chain, dict):
            chain = {}
        return (
            host,
            True,
            elapsed,
            int(chain.get("chain_length") or 0),
            bool(chain.get("is_valid")),
            "",
        )
    except Exception as e:  # noqa: BLE001
        return (host, False, time.perf_counter() - start, 0, False, str(e)[:100])


async def _bounded(
    sem: asyncio.Semaphore, host: str, port: int, timeout: float
) -> Tuple[str, bool, float, int, bool, str]:
    async with sem:
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(_run_one, host, port, timeout),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            return (host, False, timeout, 0, False, f"timeout >{timeout}s")


async def pipeline_bench(
    hosts: List[str], concurrency: int, port: int, timeout: float, verbose: bool
) -> None:
    print("=" * 64)
    print(f"PIPELINE — {len(hosts)} hosts, concurrency={concurrency}, timeout={timeout}s")
    print("=" * 64)

    sem = asyncio.Semaphore(concurrency)
    tasks = [_bounded(sem, h, port, timeout) for h in hosts]

    wall_start = time.perf_counter()
    results = await asyncio.gather(*tasks)
    wall = time.perf_counter() - wall_start

    successes = [r for r in results if r[1]]
    failures = [r for r in results if not r[1]]
    chain_valid = [r for r in successes if r[4]]
    chain_invalid = [r for r in successes if not r[4]]

    print(f"  wall clock:     {wall:.2f}s")
    print(f"  successes:      {len(successes)}/{len(hosts)}")
    print(f"  failures:       {len(failures)}")
    print(f"  chain valid:    {len(chain_valid)}/{len(successes)}")
    print(f"  chain invalid:  {len(chain_invalid)}")

    if successes:
        elapsed = sorted(r[2] for r in successes)
        chain_lens = [r[3] for r in successes]
        print()
        print("  Per-host elapsed (successes only):")
        print(f"    min:        {elapsed[0]:.3f}s")
        print(f"    median:     {elapsed[len(elapsed) // 2]:.3f}s")
        print(f"    p95:        {_percentile(elapsed, 0.95):.3f}s")
        print(f"    p99:        {_percentile(elapsed, 0.99):.3f}s")
        print(f"    max:        {elapsed[-1]:.3f}s")
        print(f"    mean:       {statistics.mean(elapsed):.3f}s")
        print()
        print("  Chain length distribution:")
        print(f"    min:        {min(chain_lens)}")
        print(f"    median:     {int(statistics.median(chain_lens))}")
        print(f"    max:        {max(chain_lens)}")

    if chain_invalid and verbose:
        print()
        print("  Chains flagged as invalid:")
        for host, _, _, length, _, _ in chain_invalid[:30]:
            print(f"    {host:35s} chain_length={length}")
        if len(chain_invalid) > 30:
            print(f"    ... and {len(chain_invalid) - 30} more")

    if failures:
        print()
        print(f"  Failures ({len(failures)}):")
        for host, _, elapsed, _, _, err in failures[:30]:
            print(f"    {host:35s} ({elapsed:5.1f}s) {err}")
        if len(failures) > 30:
            print(f"    ... and {len(failures) - 30} more")

    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--mode",
        choices=["all", "micro", "pipeline"],
        default="all",
        help="Which benchmarks to run (default: all)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=10000,
        help="Microbench iteration count (default: 10000)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=20,
        help="Pipeline max concurrent connections (default: 20)",
    )
    parser.add_argument(
        "--port", type=int, default=443, help="Port (default: 443)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="Per-host timeout in seconds (default: 15.0)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="List all chain-invalid hosts in the pipeline output",
    )
    args = parser.parse_args()

    if args.mode in ("all", "micro"):
        microbench(args.iterations)

    if args.mode in ("all", "pipeline"):
        asyncio.run(
            pipeline_bench(
                HOSTS, args.concurrency, args.port, args.timeout, args.verbose
            )
        )


if __name__ == "__main__":
    main()
