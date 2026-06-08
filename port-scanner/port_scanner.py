#!/usr/bin/env python3
"""
Port Scanner - Security Research Tool
Usage: python port_scanner.py <target> [options]
"""

import socket
import threading
import argparse
import sys
import time
from datetime import datetime
from queue import Queue

# ─── Common ports with service names ───────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB"
}

# ─── Thread-safe results store ──────────────────────────────────────────────────
open_ports = []
lock = threading.Lock()


def resolve_target(target: str) -> str:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[ERROR] Cannot resolve '{target}'. Check the hostname/IP and try again.")
        sys.exit(1)


def grab_banner(sock: socket.socket) -> str:
    """Try to grab a service banner from an open socket."""
    try:
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        # Return just the first line to keep output clean
        return banner.split("\n")[0][:60] if banner else ""
    except Exception:
        return ""


def scan_port(target_ip: str, port: int, timeout: float, grab_banners: bool) -> None:
    """Attempt a TCP connection to a single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))

        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            banner = ""
            if grab_banners:
                banner = grab_banner(sock)
            with lock:
                open_ports.append((port, service, banner))
        sock.close()
    except socket.error:
        pass


def worker(target_ip: str, queue: Queue, timeout: float, grab_banners: bool) -> None:
    """Thread worker: pull ports from queue and scan them."""
    while not queue.empty():
        port = queue.get()
        scan_port(target_ip, port, timeout, grab_banners)
        queue.task_done()


def print_banner(target: str, ip: str, port_range: tuple, threads: int) -> None:
    print("=" * 60)
    print("  PORT SCANNER — Security Research Tool")
    print("=" * 60)
    print(f"  Target     : {target} ({ip})")
    print(f"  Port range : {port_range[0]}–{port_range[1]}")
    print(f"  Threads    : {threads}")
    print(f"  Started    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)


def print_results(elapsed: float) -> None:
    print(f"\n  Scan completed in {elapsed:.2f}s\n")
    if not open_ports:
        print("  No open ports found.")
    else:
        sorted_ports = sorted(open_ports, key=lambda x: x[0])
        print(f"  {'PORT':<8} {'SERVICE':<15} {'BANNER'}")
        print("  " + "-" * 56)
        for port, service, banner in sorted_ports:
            banner_display = f"  {banner}" if banner else ""
            print(f"  {port:<8} {service:<15}{banner_display}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="TCP Port Scanner for security research",
        epilog="Example: python port_scanner.py 192.168.1.1 -p 1-1024 -t 200"
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Port range, e.g. 1-1024 or 'common' (default: 1-1024)"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=100,
        help="Number of threads (default: 100, max: 500)"
    )
    parser.add_argument(
        "--timeout", type=float, default=0.5,
        help="Connection timeout in seconds (default: 0.5)"
    )
    parser.add_argument(
        "--banner", action="store_true",
        help="Attempt to grab service banners"
    )
    args = parser.parse_args()

    # ── Resolve target ─────────────────────────────────────────────────────────
    target_ip = resolve_target(args.target)

    # ── Parse port range ───────────────────────────────────────────────────────
    if args.ports.lower() == "common":
        ports = list(COMMON_PORTS.keys())
        port_range = (min(ports), max(ports))
    else:
        try:
            parts = args.ports.split("-")
            start, end = int(parts[0]), int(parts[1]) if len(parts) > 1 else int(parts[0])
            if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                raise ValueError
            ports = list(range(start, end + 1))
            port_range = (start, end)
        except (ValueError, IndexError):
            print("[ERROR] Invalid port range. Use format: 1-1024 or 'common'")
            sys.exit(1)

    # ── Cap threads ────────────────────────────────────────────────────────────
    num_threads = min(args.threads, 500)

    print_banner(args.target, target_ip, port_range, num_threads)

    # ── Fill queue ─────────────────────────────────────────────────────────────
    queue = Queue()
    for port in ports:
        queue.put(port)

    # ── Launch threads ─────────────────────────────────────────────────────────
    start_time = time.time()
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(
            target=worker,
            args=(target_ip, queue, args.timeout, args.banner),
            daemon=True
        )
        t.start()
        threads.append(t)

    # ── Progress indicator ─────────────────────────────────────────────────────
    total = len(ports)
    while not queue.empty():
        done = total - queue.qsize()
        pct = (done / total) * 100
        print(f"  Scanning... {done}/{total} ports ({pct:.0f}%)", end="\r")
        time.sleep(0.3)

    queue.join()
    elapsed = time.time() - start_time

    print_results(elapsed)


if __name__ == "__main__":
    # Ethical use reminder
    print("\n[!] Only scan systems you own or have explicit permission to test.\n")
    main()
