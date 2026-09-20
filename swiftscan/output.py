"""
swiftscan/output.py
Rich terminal output, JSON export, and Markdown report generation.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from typing import Optional

from .scanner import ScanResult, PortResult

# ANSI colour codes — fall back to empty strings if not a TTY
_IS_TTY = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    if not _IS_TTY:
        return text
    return f"\033[{code}m{text}\033[0m"

RED     = lambda t: _c("91", t)
GREEN   = lambda t: _c("92", t)
YELLOW  = lambda t: _c("93", t)
BLUE    = lambda t: _c("94", t)
MAGENTA = lambda t: _c("95", t)
CYAN    = lambda t: _c("96", t)
BOLD    = lambda t: _c("1",  t)
DIM     = lambda t: _c("2",  t)
RESET   = "\033[0m"


BANNER_ART = r"""
 ____          _  __ _   ____
/ ___|_      _(_)/ _| |_/ ___|  ___ __ _ _ __
\___ \ \ /\ / / | |_| __\___ \ / __/ _` | '_ \
 ___) \ V  V /| |  _| |_ ___) | (_| (_| | | | |
|____/ \_/\_/ |_|_|  \__|____/ \___\__,_|_| |_|

"""


def print_banner(version: str = "1.0.0") -> None:
    print(CYAN(BANNER_ART))
    print(BOLD(f"  SwiftScan v{version}") + DIM(" — Async TCP Scanner for Kali Linux"))
    print(DIM("  github.com/harshexploits/swiftscan") + "\n")


def print_scan_header(target: str, ip: str, ports_count: int,
                      concurrency: int, timeout: float) -> None:
    print(f"  {BOLD('Target      :')} {CYAN(target)}  {DIM('→')}  {ip}")
    print(f"  {BOLD('Ports       :')} {ports_count:,}")
    print(f"  {BOLD('Concurrency :')} {concurrency}")
    print(f"  {BOLD('Timeout     :')} {timeout}s")
    print(f"  {BOLD('Started     :')} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()


def print_progress(completed: int, total: int) -> None:
    """In-place progress bar printed to stderr."""
    pct = completed / total * 100
    bar_len = 30
    filled = int(bar_len * completed / total)
    bar = "█" * filled + "░" * (bar_len - filled)
    print(
        f"\r  {DIM('Scanning')} [{CYAN(bar)}] {pct:5.1f}%  {completed:,}/{total:,}",
        end="",
        flush=True,
        file=sys.stderr,
    )
    if completed == total:
        print(file=sys.stderr)  # newline after completion


def _port_line(p: PortResult) -> str:
    state_col = GREEN("open")
    port_col  = BOLD(f"{p.port:>5}/tcp")
    svc_col   = YELLOW(f"{p.service:<20}")
    lat_col   = DIM(f"{p.latency*1000:>6.1f}ms")
    hv_col    = RED(" ★ HIGH VALUE") if p.high_value else ""
    banner    = f"  {DIM(p.banner[:80])}" if p.banner else ""
    return f"  {port_col}  {state_col}  {svc_col}  {lat_col}{hv_col}{banner}"


def print_results(result: ScanResult) -> None:
    """Print scan results table to stdout."""
    open_ports = result.open_ports

    print()
    if not open_ports:
        print(f"  {DIM('No open ports found.')}")
    else:
        print(BOLD(f"  {'PORT':<9} {'STATE':<6} {'SERVICE':<20} {'LATENCY'}"))
        print(DIM("  " + "─" * 70))
        for p in sorted(open_ports, key=lambda x: x.port):
            print(_port_line(p))

    print()
    print(BOLD("  ── Summary ──────────────────────────────────────"))
    print(f"  Open ports     : {GREEN(str(len(open_ports)))}")
    print(f"  Total scanned  : {result.total_scanned:,}")
    print(f"  Duration       : {result.duration:.2f}s")
    rate = result.total_scanned / result.duration if result.duration else 0
    print(f"  Scan rate      : {rate:,.0f} ports/sec")

    hv = [p for p in open_ports if p.high_value]
    if hv:
        print()
        print(RED(f"  ★ High-value ports: ") + ", ".join(str(p.port) for p in hv))
    print()


def to_json(result: ScanResult, indent: int = 2) -> str:
    """Serialize ScanResult to JSON string."""
    data = {
        "meta": {
            "target":        result.target,
            "ip":            result.ip,
            "scan_started":  datetime.fromtimestamp(result.start_time).isoformat(),
            "scan_ended":    datetime.fromtimestamp(result.end_time).isoformat(),
            "duration_s":    round(result.duration, 3),
            "total_scanned": result.total_scanned,
            "open_count":    len(result.open_ports),
        },
        "open_ports": [
            {
                "port":       p.port,
                "service":    p.service,
                "banner":     p.banner,
                "latency_ms": round(p.latency * 1000, 2),
                "high_value": p.high_value,
            }
            for p in sorted(result.open_ports, key=lambda x: x.port)
        ],
    }
    return json.dumps(data, indent=indent)


def to_markdown(result: ScanResult) -> str:
    """Generate a Markdown scan report."""
    lines = [
        f"# SwiftScan Report — {result.target}",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Target | `{result.target}` |",
        f"| IP | `{result.ip}` |",
        f"| Scan Started | {datetime.fromtimestamp(result.start_time).strftime('%Y-%m-%d %H:%M:%S')} |",
        f"| Duration | {result.duration:.2f}s |",
        f"| Ports Scanned | {result.total_scanned:,} |",
        f"| Open Ports | **{len(result.open_ports)}** |",
        "",
        "## Open Ports",
        "",
    ]

    open_ports = sorted(result.open_ports, key=lambda x: x.port)
    if not open_ports:
        lines.append("_No open ports found._")
    else:
        lines.append("| Port | Service | Latency | High Value | Banner |")
        lines.append("|------|---------|---------|------------|--------|")
        for p in open_ports:
            hv  = "⚠️ YES" if p.high_value else "—"
            ban = f"`{p.banner[:60]}…`" if p.banner else "—"
            lines.append(f"| {p.port}/tcp | {p.service} | {p.latency*1000:.1f}ms | {hv} | {ban} |")

    hv_ports = [p for p in open_ports if p.high_value]
    if hv_ports:
        lines += [
            "",
            "## ⚠️ High-Value Ports",
            "",
            "> These ports commonly expose critical services. Verify and investigate manually.",
            "",
        ]
        for p in hv_ports:
            lines.append(f"- **{p.port}/tcp** — {p.service}")

    lines += [
        "",
        "---",
        "",
        "_Report generated by [SwiftScan](https://github.com/harshexploits/swiftscan). "
        "All findings require manual verification._",
    ]
    return "\n".join(lines)


def save_output(result: ScanResult, fmt: str, path: str) -> None:
    """Save result in json or markdown format to a file."""
    if fmt == "json":
        content = to_json(result)
    elif fmt in ("md", "markdown"):
        content = to_markdown(result)
    else:
        raise ValueError(f"Unknown output format: {fmt}")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    print(GREEN(f"  ✓ Report saved → {path}"))
