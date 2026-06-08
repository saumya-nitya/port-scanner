# Networking Concepts Behind the Port Scanner

A reference guide explaining the core concepts this project is built on.

---

## TCP and the Three-Way Handshake

When this scanner "opens" a port, it's completing a TCP handshake:

```
Scanner                    Target
   │                          │
   │──── SYN ────────────────►│   "I want to connect"
   │                          │
   │◄─── SYN-ACK ────────────│   "OK, I'm listening"  ← port is OPEN
   │                          │
   │──── ACK ────────────────►│   "Great, connected"
   │                          │
   └── connect_ex() returns 0 ┘
```

If the port is **closed**, the target replies with `RST` (reset) immediately.
If the port is **filtered** (firewall), there is no reply — the connection times out.

---

## What `connect_ex()` Returns

| Return value | Meaning |
|---|---|
| `0` | Port is open — connection succeeded |
| `111` (Linux) / `10061` (Windows) | Connection refused — port is closed |
| Times out | Port is filtered by a firewall |

---

## Ports: Three Ranges

| Range | Name | Description |
|---|---|---|
| 0–1023 | Well-known / System | Assigned by IANA (HTTP=80, SSH=22...) |
| 1024–49151 | Registered | Claimed by apps (MySQL=3306, RDP=3389...) |
| 49152–65535 | Dynamic / Ephemeral | Used temporarily by OS for outgoing connections |

---

## Why Multithreading?

A single-threaded scanner would do this:

```
scan port 1  → wait up to 500ms → result
scan port 2  → wait up to 500ms → result
scan port 3  → wait up to 500ms → result
...
scan port 1024 → wait → result
Total: 1024 × 0.5s = ~8.5 minutes
```

With 100 threads scanning in parallel:

```
Thread 1: port 1, Thread 2: port 2, ..., Thread 100: port 100
(all waiting simultaneously)
→ ~0.5s for the whole first batch of 100 ports
Total: ~5 seconds
```

The speedup is roughly equal to the number of threads.

---

## Banner Grabbing

Many services announce themselves when you connect. The scanner sends:

```
HEAD / HTTP/1.0\r\n\r\n
```

A web server might reply:

```
HTTP/1.1 200 OK
Server: Apache/2.4.54 (Ubuntu)
```

This reveals the software and version — useful for identifying vulnerable versions.

---

## What Nmap Does Differently

This scanner does basic TCP connect scanning. Nmap goes further:

| Technique | How | Benefit |
|---|---|---|
| SYN scan (`-sS`) | Sends SYN, never completes handshake | Stealthier, faster |
| UDP scan (`-sU`) | Sends UDP packets | Finds DNS, SNMP, etc. |
| OS fingerprinting | Analyses TCP/IP quirks | Identifies the OS |
| Service detection (`-sV`) | Deep banner analysis | Exact version identification |
| NSE scripts | Lua scripts per service | Vulnerability detection |

Building those features is your natural next step.

---

## Further Reading

- RFC 793 — the original TCP specification
- `man 7 tcp` on Linux — kernel-level TCP documentation
- *TCP/IP Illustrated, Volume 1* by W. Richard Stevens — the definitive book
- Nmap Network Scanning (free online) — https://nmap.org/book/
