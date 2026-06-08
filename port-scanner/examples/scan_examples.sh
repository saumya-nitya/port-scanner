#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  Port Scanner — Example Commands
#  Only run these against systems you own or have permission to scan.
# ─────────────────────────────────────────────────────────────

# 1. Quick scan of your own machine (localhost)
python port_scanner.py 127.0.0.1 -p 1-1024

# 2. Scan your home router (common gateway IPs)
python port_scanner.py 192.168.1.1 -p common

# 3. Fast full scan of a lab machine
python port_scanner.py 192.168.1.100 -p 1-65535 -t 300 --timeout 0.3

# 4. Scan with banner grabbing to identify service versions
python port_scanner.py 192.168.1.100 -p 1-1024 --banner

# 5. Web server port check only
python port_scanner.py example.com -p 80-443

# 6. Database ports check
python port_scanner.py 192.168.1.100 -p 3306-5432

# 7. Slow/distant target — increase timeout to reduce false negatives
python port_scanner.py example.com -p 1-1024 --timeout 2.0 -t 50
