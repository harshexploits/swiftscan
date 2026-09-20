"""
swiftscan/scanner.py
Core async TCP scanner engine.
Uses asyncio.open_connection() for maximum concurrency.
"""

from __future__ import annotations

import asyncio
import time
import socket
from dataclasses import dataclass, field
from typing import Optional, Callable

from .fingerprint import identify_service, is_high_value

# Probes sent to open ports to grab banners
BANNER_PROBES = [
    b"",                            # wait for server hello (SSH, SMTP, FTP…)
    b"HEAD / HTTP/1.0\r\n\r\n",    # HTTP
    b"\r\n",                        # generic
]


@dataclass
class PortResult:
    ip:      str
    port:    int
    state:   str          # "open" | "closed" | "filtered"
    service: str = "Unknown"
    banner:  Optional[str] = None
    latency: float = 0.0  # seconds
    high_value: bool = False


@dataclass
class ScanResult:
    target:     str
    ip:         str
    start_time: float = field(default_factory=time.time)
    end_time:   float = 0.0
    ports:      list[PortResult] = field(default_factory=list)
    total_scanned: int = 0

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state == "open"]

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time


async def grab_banner(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    timeout: float = 2.0,
) -> Optional[str]:
    """Try to grab a service banner from an already-open connection."""
    for probe in BANNER_PROBES:
        try:
            if probe:
                writer.write(probe)
                await asyncio.wait_for(writer.drain(), timeout=1.0)
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            if data:
                # Decode best-effort; strip non-printable except newlines
                text = data.decode("utf-8", errors="replace")
                clean = "".join(c if c.isprintable() or c in "\r\n" else "." for c in text)
                return clean.strip()[:256]
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            continue
    return None


async def scan_port(
    ip: str,
    port: int,
    timeout: float,
    grab_banners: bool,
    semaphore: asyncio.Semaphore,
) -> PortResult:
    """Attempt a TCP connect to a single port and optionally grab its banner."""
    async with semaphore:
        t0 = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
            latency = time.monotonic() - t0

            banner: Optional[str] = None
            if grab_banners:
                banner = await grab_banner(reader, writer, timeout=min(timeout, 3.0))

            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass

            service = identify_service(port, banner)
            return PortResult(
                ip=ip,
                port=port,
                state="open",
                service=service,
                banner=banner,
                latency=latency,
                high_value=is_high_value(port, service),
            )

        except (asyncio.TimeoutError, ConnectionRefusedError):
            return PortResult(ip=ip, port=port, state="closed",
                              latency=time.monotonic() - t0)
        except OSError:
            return PortResult(ip=ip, port=port, state="filtered",
                              latency=time.monotonic() - t0)


def resolve_target(target: str) -> str:
    """Resolve hostname to IP. Raises ValueError on failure."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve '{target}': {e}") from e


def parse_ports(port_spec: str) -> list[int]:
    """
    Parse port specification string into a list of ints.
    Examples:
        "80"          → [80]
        "80,443"      → [80, 443]
        "1-1024"      → [1 … 1024]
        "22,80,443,8000-8100"  → [22, 80, 443, 8000 … 8100]
        "top100"      → top 100 common ports
        "top1000"     → top 1000 common ports
        "-"           → all 65535 ports
    """
    if port_spec.lower() in ("top100", "-t100"):
        return TOP_100_PORTS
    if port_spec.lower() in ("top1000", "-t1000"):
        return TOP_1000_PORTS
    if port_spec == "-":
        return list(range(1, 65536))

    ports: set[int] = set()
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part and not part.startswith("-"):
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


async def async_scan(
    target: str,
    ports: list[int],
    timeout: float = 1.0,
    concurrency: int = 1000,
    grab_banners: bool = True,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> ScanResult:
    """
    Main async scan coroutine.

    Args:
        target      : hostname or IP
        ports       : list of port numbers to scan
        timeout     : per-port connect timeout in seconds
        concurrency : max simultaneous connections (semaphore limit)
        grab_banners: whether to attempt banner grabbing on open ports
        progress_cb : optional callback(completed, total) for live progress

    Returns:
        ScanResult
    """
    ip = resolve_target(target)
    result = ScanResult(target=target, ip=ip, total_scanned=len(ports))

    sem = asyncio.Semaphore(concurrency)
    completed = 0

    async def _scan_and_track(port: int) -> PortResult:
        nonlocal completed
        r = await scan_port(ip, port, timeout, grab_banners, sem)
        completed += 1
        if progress_cb:
            progress_cb(completed, len(ports))
        return r

    tasks = [asyncio.create_task(_scan_and_track(p)) for p in ports]
    results = await asyncio.gather(*tasks, return_exceptions=False)

    result.ports = [r for r in results if r.state == "open"]
    result.end_time = time.time()
    return result


# ──────────────────────────────────────────────────────────────
# Pre-defined port lists
# ──────────────────────────────────────────────────────────────

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 123, 135, 139,
    143, 161, 194, 389, 443, 445, 465, 514, 515, 543, 587, 631, 636, 873,
    993, 995, 1080, 1433, 1521, 1723, 2049, 2375, 2376, 3000, 3306, 3389,
    4369, 5432, 5672, 5900, 5985, 5986, 6379, 6443, 7001, 8000, 8080,
    8443, 8888, 9000, 9090, 9200, 9300, 10250, 11211, 27017, 27018,
    50000, 50070, 4444, 4445, 8008, 8009, 8180, 8181, 8282, 8383, 8484,
    8585, 8686, 9999, 10000, 10001, 10002, 10003, 10004, 10080, 10443,
    12000, 12345, 15672, 16379, 18080, 18443, 20000, 25565, 27015, 28017,
    49152, 49153, 49154, 49155, 49156, 49157,
]

TOP_1000_PORTS = sorted(set(TOP_100_PORTS + list(range(1, 1025))))
