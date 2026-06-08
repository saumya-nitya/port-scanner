# 🔍 Port Scanner

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Security](https://img.shields.io/badge/Purpose-Security%20Research-orange)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

A fast, multithreaded TCP port scanner written in Python for security research and network reconnaissance. Built with raw sockets and Python's threading library — no external dependencies required.

> ⚠️ **Legal Notice:** Only scan systems you own or have explicit written permission to test. Unauthorized port scanning may be illegal in your jurisdiction.

---

## Features

- **Multithreaded** — scans hundreds of ports simultaneously using a thread pool
- **Banner grabbing** — identifies running service versions
- **Named services** — maps 20 well-known ports to service names automatically
- **Flexible port ranges** — scan a single port, a range, or all 65535 ports
- **Progress indicator** — real-time scan progress in the terminal
- **Zero dependencies** — uses only Python standard library

---

## Requirements

- Python 3.8 or higher
- No third-party packages needed

---

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/port-scanner.git
cd port-scanner

# (Optional) Create a virtual environment
python -m venv venv
source venv/bin/activate       # Linux/macOS
venv\Scripts\activate          # Windows

# No pip install needed — zero external dependencies
```

---

## Usage

```bash
python port_scanner.py <target> [options]
```

### Arguments

| Argument | Description | Default |
|---|---|---|
| `target` | IP address or hostname to scan | required |
| `-p`, `--ports` | Port range (`1-1024`) or `common` | `1-1024` |
| `-t`, `--threads` | Number of concurrent threads | `100` |
| `--timeout` | Connection timeout in seconds | `0.5` |
| `--banner` | Attempt to grab service banners | off |

### Examples

```bash
# Scan top 20 well-known ports
python port_scanner.py 192.168.1.1 -p common

# Scan ports 1–1024 (standard privileged ports)
python port_scanner.py 192.168.1.1 -p 1-1024

# Fast full scan with 300 threads
python port_scanner.py 192.168.1.1 -p 1-65535 -t 300

# Scan with banner grabbing enabled
python port_scanner.py 192.168.1.1 -p 1-1024 --banner

# Slow/distant target — increase timeout
python port_scanner.py example.com -p 80-443 --timeout 2.0
```

### Sample Output

```
[!] Only scan systems you own or have explicit permission to test.

============================================================
  PORT SCANNER — Security Research Tool
============================================================
  Target     : 192.168.1.1 (192.168.1.1)
  Port range : 1–1024
  Threads    : 100
  Started    : 2024-01-15 14:32:07
============================================================

  Scan completed in 3.42s

  PORT     SERVICE         BANNER
  --------------------------------------------------------
  22       SSH               SSH-2.0-OpenSSH_8.9
  80       HTTP              HTTP/1.1 200 OK
  443      HTTPS
  3306     MySQL
```

---

## How It Works

```
Main thread
    │
    ├─ Resolves hostname → IP
    ├─ Fills a Queue with port numbers
    │
    ├─ Spawns N worker threads ──────────────────────────┐
    │                                                     │
    │   Thread 1: pulls port 80  → connect_ex() → open   │
    │   Thread 2: pulls port 81  → connect_ex() → closed │
    │   Thread 3: pulls port 443 → connect_ex() → open   │
    │   ...                                               │
    │                                                     │
    └─ queue.join() waits for all threads ◄───────────────┘
           │
           └─ Sorts and prints results
```

Key concepts used:
- **`socket.connect_ex()`** — returns `0` if port is open, error code otherwise
- **`threading.Lock`** — prevents race conditions when threads write results
- **`Queue`** — thread-safe work distribution (producer-consumer pattern)
- **`settimeout()`** — prevents threads from hanging on filtered ports

---

## Project Structure

```
port-scanner/
├── port_scanner.py       # Main scanner script
├── tests/
│   └── test_scanner.py   # Unit tests
├── examples/
│   └── scan_examples.sh  # Ready-to-use example commands
├── docs/
│   └── concepts.md       # Learning notes on networking concepts
├── .gitignore
├── LICENSE
└── README.md
```

---

## Running Tests

```bash
python -m pytest tests/ -v
```

---

## Learning Resources

- [TCP/IP Fundamentals](https://www.cloudflare.com/learning/ddos/glossary/tcp-ip/)
- [Python `socket` module docs](https://docs.python.org/3/library/socket.html)
- [Python `threading` module docs](https://docs.python.org/3/library/threading.html)
- [OWASP Network Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Nmap — the professional reference](https://nmap.org/book/toc.html)

---

## Ethical Use

This tool is built for:
- Learning TCP/IP and socket programming
- Scanning your own home/lab network
- Authorized penetration testing engagements
- CTF (Capture The Flag) challenges

**Do not** use this on networks or systems without written authorization.

---

## Contributing

Pull requests are welcome. For major changes, open an issue first to discuss what you'd like to change. Please make sure to update tests accordingly.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/udp-scanning`)
3. Commit your changes (`git commit -m 'Add UDP scanning support'`)
4. Push and open a Pull Request

---

## License

[MIT](LICENSE) — free to use, modify, and distribute.
