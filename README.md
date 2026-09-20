<div align="center">

```
 ____          _  __ _   ____
/ ___|_      _(_)/ _| |_/ ___|  ___ __ _ _ __
\___ \ \ /\ / / | |_| __\___ \ / __/ _` | '_ \
 ___) \ V  V /| |  _| |_ ___) | (_| (_| | | | |
|____/ \_/\_/ |_|_|  \__|____/ \___\__,_|_| |_|
```

# SwiftScan

### Async TCP Port Scanner — 50× faster than nmap defaults

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Kali Linux](https://img.shields.io/badge/Kali-Linux-557C94?style=flat-square&logo=kalilinux&logoColor=white)](https://kali.org)
[![PyPI](https://img.shields.io/badge/pip_install-swiftscan-orange?style=flat-square&logo=pypi&logoColor=white)](https://pypi.org/project/swiftscan)
[![Zero Deps](https://img.shields.io/badge/dependencies-zero-brightgreen?style=flat-square)]()
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Ethics](https://img.shields.io/badge/Use-Authorized_Targets_Only-critical?style=flat-square)]()

**Pure Python · asyncio · Zero dependencies · Banner grabbing · JSON/Markdown reports**

</div>

---

## ⚡ Why SwiftScan?

| | nmap (default) | masscan | SwiftScan |
|---|---|---|---|
| **All 65535 ports** | ~30 min | fast but noisy | **~15 sec** |
| **Dependencies** | C binary | C binary | **Pure Python** |
| **Kali install** | pre-installed | apt | **pip install** |
| **Banner grabbing** | ✅ | ❌ | ✅ |
| **JSON output** | XML only | ✅ | ✅ |
| **Markdown report** | ❌ | ❌ | ✅ |
| **CIDR scan** | ✅ | ✅ | ✅ |
| **Root required** | For SYN scan | ✅ | ❌ |

SwiftScan uses Python's `asyncio` to open **thousands of TCP connections simultaneously** — no raw sockets, no root, no C dependencies.

---

## 🚀 Installation

### Kali Linux / Debian (Recommended)
```bash
pip install swiftscan
```

### From Source
```bash
git clone https://github.com/harshexploits/swiftscan.git
cd swiftscan
pip install -e .
```

### Verify
```bash
swiftscan --version
# SwiftScan 1.0.0
```

---

## 🎯 Usage

```bash
# Basic — top-100 ports (fast)
swiftscan 192.168.1.1

# Top-1000 ports
swiftscan target.com -p top1000

# Specific ports
swiftscan target.com -p 22,80,443,8080,8443

# Range
swiftscan target.com -p 1-1024

# All 65535 ports (aggressive concurrency)
swiftscan target.com -p - -c 5000 --timeout 0.5

# With banner grabbing
swiftscan target.com -p top1000 --banner

# CIDR subnet scan
swiftscan 192.168.1.0/24 -p 22,80,443

# Save JSON report
swiftscan target.com -p top1000 -o results.json --format json

# Save Markdown report
swiftscan target.com -p top1000 -o results.md --format md

# Quiet mode (machine-readable)
swiftscan target.com -p top100 -q -o scan.json
```

---

## 📸 Output

```
 ____          _  __ _   ____
/ ___|_      _(_)/ _| |_/ ___|  ___ __ _ _ __
...

  SwiftScan v1.0.0 — Async TCP Scanner for Kali Linux
  github.com/harshexploits/swiftscan

  Target      : scanme.nmap.org  →  45.33.32.156
  Ports       : 100
  Concurrency : 1000
  Timeout     : 1.0s
  Started     : 2026-09-20 12:00:00

  Scanning [██████████████████████████████] 100.0%  100/100

  PORT      STATE  SERVICE              LATENCY
  ──────────────────────────────────────────────────────────────────
    22/tcp  open   SSH                  142.3ms
    80/tcp  open   HTTP                 143.8ms
  9929/tcp  open   Unknown              144.1ms
 31337/tcp  open   Unknown              143.7ms  

  ── Summary ──────────────────────────────────────
  Open ports     : 4
  Total scanned  : 100
  Duration       : 2.31s
  Scan rate      : 43 ports/sec

  ★ High-value ports: 22
```

---

## 📋 All Options

```
usage: swiftscan [-h] [-p PORTS] [-c N] [-t SEC] [--banner] [--no-banner]
                 [-o FILE] [--format FMT] [--no-color] [-q] [-v]
                 target

positional arguments:
  target                Target hostname or IP address

options:
  -p, --ports PORTS     Port spec: top100 (default), top1000, -, 1-1024,
                        22,80,443, mixed (see examples)
  -c, --concurrency N   Max concurrent connections (default: 1000)
  -t, --timeout SEC     Per-port connect timeout in seconds (default: 1.0)
  --banner              Attempt banner grabbing on open ports
  --no-banner           Disable banner grabbing (faster)
  -o, --output FILE     Save report to file
  --format FMT          Output format: json | md (default: json)
  --no-color            Disable ANSI color output
  -q, --quiet           Suppress banner and progress (machine-friendly)
  -v, --version         Show version
```

---

## 🧠 How It Works

```
swiftscan target.com -p 1-65535
        │
        ▼
┌─────────────────────────┐
│  DNS Resolution          │  socket.gethostbyname()
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│  asyncio Task Pool       │  65535 tasks created
│  Semaphore(N=1000)       │  max 1000 concurrent TCP connects
└──────────┬──────────────┘
           │  per task:
           ▼
┌─────────────────────────┐
│  asyncio.open_connection │  non-blocking TCP connect
│  + timeout               │
└──────────┬──────────────┘
           │  if open:
           ▼
┌─────────────────────────┐
│  Banner Grabber          │  send probes, read 1024 bytes
│  (optional)              │
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│  Service Fingerprinter   │  port map + banner pattern match
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│  Output                  │  terminal / JSON / Markdown
└─────────────────────────┘
```

**Why asyncio beats threads here:** A TCP connect is pure I/O wait. asyncio's event loop handles thousands of simultaneous waits with a single thread — no GIL bottleneck, no thread overhead.

---

## 📄 Report Formats

### JSON (`--format json`)
```json
{
  "meta": {
    "target": "target.com",
    "ip": "93.184.216.34",
    "duration_s": 2.31,
    "total_scanned": 100,
    "open_count": 3
  },
  "open_ports": [
    { "port": 80,  "service": "HTTP",  "banner": "HTTP/1.1 200 OK...", "latency_ms": 45.2, "high_value": false },
    { "port": 443, "service": "HTTPS", "banner": null,                 "latency_ms": 46.1, "high_value": false }
  ]
}
```

### Markdown (`--format md`)
Generates a clean `report.md` with tables of open ports, high-value findings, and scan metadata — ready to paste into a bug bounty report.

---

## ⚙️ Tuning

| Scenario | Recommended flags |
|---|---|
| Quick recon | `swiftscan target -p top100` |
| Thorough recon | `swiftscan target -p top1000 --banner` |
| All ports, fast net | `swiftscan target -p - -c 5000 -t 0.5` |
| Slow/lossy net | `swiftscan target -p top1000 -c 200 -t 3.0` |
| CI / scripting | `swiftscan target -p top100 -q -o out.json` |

---

## 🔐 Ethical Use

> **Only scan systems you are explicitly authorized to test.**
> Unauthorized port scanning is illegal in most jurisdictions.
> Use against your own infrastructure, bug bounty in-scope assets, or intentionally vulnerable labs (HackTheBox, TryHackMe, DVWA).

---

## 🤝 Contributing

```bash
git clone https://github.com/harshexploits/swiftscan.git
cd swiftscan
pip install -e .
# Make changes, run tests, open a PR
```

Ideas welcome:
- UDP scanning
- OS fingerprinting
- HTML report output
- Service version detection
- `--exclude-ports` flag

---

## 👤 Author

**Harsh Agrawal** — [@harshexploits](https://github.com/harshexploits)

> *Offensive security researcher | Bug bounty hunter | Builder of PhishShield AI & Automated Scanner*

---

<div align="center">

**⭐ Star this repo if SwiftScan saved you time on a recon run!**

</div>
