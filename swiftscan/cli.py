"""
swiftscan/cli.py
Command-line interface for SwiftScan.

Usage examples:
    swiftscan 192.168.1.1
    swiftscan scanme.nmap.org -p top1000 -c 2000 --banner
    swiftscan 10.0.0.0/24 -p 22,80,443 -o results.json --format json
    swiftscan target.com -p 1-65535 -c 5000 --timeout 0.5
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import sys
from typing import Optional

from . import __version__
from .scanner import async_scan, parse_ports, resolve_target, TOP_100_PORTS
from .output import (
    print_banner, print_scan_header, print_progress,
    print_results, save_output, GREEN, RED, YELLOW, BOLD, DIM, CYAN,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="swiftscan",
        description="SwiftScan — Async TCP port scanner. 50x faster than nmap defaults.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  swiftscan 192.168.1.1                      # top-100 ports, default settings
  swiftscan target.com -p top1000            # top-1000 ports
  swiftscan target.com -p 1-65535 -c 5000   # all ports, high concurrency
  swiftscan target.com -p 22,80,443,8080    # specific ports
  swiftscan target.com -p top1000 --banner  # with banner grabbing
  swiftscan target.com -p 80,443 -o r.json --format json
  swiftscan target.com -p 80,443 -o r.md   --format md

Port Specs:
  top100        — 100 most common ports (default)
  top1000       — 1000 most common ports
  -             — all 65535 ports
  1-1024        — range
  22,80,443     — comma list
  22,80,8000-9000 — mixed

Ethical Use:
  Only scan targets you are explicitly authorized to test.
  Unauthorized scanning is illegal in most jurisdictions.
""",
    )

    p.add_argument("target", help="Target hostname or IP address")
    p.add_argument(
        "-p", "--ports",
        default="top100",
        metavar="PORTS",
        help="Port specification (default: top100)",
    )
    p.add_argument(
        "-c", "--concurrency",
        type=int,
        default=1000,
        metavar="N",
        help="Max concurrent connections (default: 1000)",
    )
    p.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.0,
        metavar="SEC",
        help="Per-port connect timeout in seconds (default: 1.0)",
    )
    p.add_argument(
        "--banner",
        action="store_true",
        default=False,
        help="Attempt banner grabbing on open ports (slightly slower)",
    )
    p.add_argument(
        "--no-banner",
        dest="banner",
        action="store_false",
        help="Disable banner grabbing (faster)",
    )
    p.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Save report to file",
    )
    p.add_argument(
        "--format",
        choices=["json", "md", "markdown"],
        default="json",
        metavar="FMT",
        help="Output format: json | md (default: json)",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output",
    )
    p.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress banner and progress bar (machine-friendly)",
    )
    p.add_argument(
        "-v", "--version",
        action="version",
        version=f"SwiftScan {__version__}",
    )
    return p


def expand_cidr(cidr: str) -> list[str]:
    """Expand a CIDR notation into individual host IPs."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Disable colour if requested
    if args.no_color:
        import swiftscan.output as _out
        _out._IS_TTY = False  # monkey-patch

    if not args.quiet:
        print_banner(__version__)

    # Parse ports
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(RED(f"[!] Invalid port spec: {e}"), file=sys.stderr)
        return 1

    if not ports:
        print(RED("[!] No ports to scan."), file=sys.stderr)
        return 1

    # CIDR expansion
    targets: list[str] = []
    if "/" in args.target:
        hosts = expand_cidr(args.target)
        if not hosts:
            print(RED(f"[!] Invalid CIDR: {args.target}"), file=sys.stderr)
            return 1
        targets = hosts
        print(YELLOW(f"  [*] CIDR expanded to {len(targets)} hosts\n"))
    else:
        targets = [args.target]

    all_results = []
    exit_code = 0

    for target in targets:
        if not args.quiet:
            try:
                ip = resolve_target(target)
            except ValueError as e:
                print(RED(f"[!] {e}"), file=sys.stderr)
                exit_code = 1
                continue

            print_scan_header(
                target, ip, len(ports),
                args.concurrency, args.timeout,
            )

        # Progress callback (only when not quiet and single target)
        progress_cb = None
        if not args.quiet and len(targets) == 1:
            progress_cb = print_progress

        try:
            result = asyncio.run(
                async_scan(
                    target=target,
                    ports=ports,
                    timeout=args.timeout,
                    concurrency=args.concurrency,
                    grab_banners=args.banner,
                    progress_cb=progress_cb,
                )
            )
        except ValueError as e:
            print(RED(f"\n[!] {e}"), file=sys.stderr)
            exit_code = 1
            continue
        except KeyboardInterrupt:
            print(YELLOW("\n[!] Scan interrupted by user."), file=sys.stderr)
            return 130

        if not args.quiet:
            print_results(result)

        all_results.append(result)

        # Save output if requested (per-target when multiple)
        if args.output:
            out_path = args.output
            if len(targets) > 1:
                out_path = f"{target.replace('/', '_')}_{args.output}"
            try:
                save_output(result, args.format, out_path)
            except Exception as e:
                print(RED(f"[!] Failed to save output: {e}"), file=sys.stderr)
                exit_code = 1

    # Final summary for CIDR scans
    if len(all_results) > 1 and not args.quiet:
        total_open = sum(len(r.open_ports) for r in all_results)
        hosts_with_open = sum(1 for r in all_results if r.open_ports)
        print(BOLD("\n  ── CIDR Summary ──────────────────────────────────"))
        print(f"  Hosts scanned  : {len(all_results)}")
        print(f"  Hosts with open: {GREEN(str(hosts_with_open))}")
        print(f"  Total open ports: {GREEN(str(total_open))}")
        print()

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
