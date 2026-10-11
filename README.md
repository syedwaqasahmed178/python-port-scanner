# Python Port Scanner

A small multithreaded TCP port scanner written in Python. It finds open ports on a target, identifies the common service for each port, optionally grabs a service banner, and saves a JSON report.

Built as a learning project for network reconnaissance fundamentals.

> **Use responsibly.** Only scan systems you own or have written permission to test. Safe targets: `127.0.0.1`, your own lab VMs, or `scanme.nmap.org`.

## Features

- TCP connect scanning with a configurable thread pool (fast, 100 threads by default)
- Flexible port input: `22,80,443`, `1-1024`, or a mix
- Service name lookup (e.g. 22 -> ssh, 80 -> http)
- Optional banner grabbing (`-b`)
- JSON report output (`-o`)
- Standard library only, no installs needed

## Usage

```bash
python3 portscanner.py <host> [-p PORTS] [-t THREADS] [--timeout SECONDS] [-b] [-o report.json]
```

Examples:

```bash
# Scan the first 1024 ports of your own machine
python3 portscanner.py 127.0.0.1

# Scan specific ports with banner grabbing and save a report
python3 portscanner.py 127.0.0.1 -p 22,80,443,8000-8100 -b -o report.json
```

Example output:

```
Scanning 127.0.0.1 (127.0.0.1) - 101 ports, 100 threads

PORT    SERVICE       BANNER
8765    unknown       HTTP/1.0 200 OK

Done: 1 open port(s) in 0.51s
```

## How it works

1. `parse_ports` converts the port argument into a list of port numbers.
2. `scan_port` opens a TCP connection to each port using `connect_ex`. A return value of `0` means the port is open.
3. A `ThreadPoolExecutor` runs many port checks in parallel, so a scan finishes in seconds instead of minutes.
4. `grab_banner` reads what the service sends first (SSH, FTP, SMTP), or sends a minimal `HEAD` request for web servers.
5. Results are printed as a table and optionally written to JSON.

## Possible improvements

- UDP scanning
- Service/version detection
- Scanning multiple hosts or a CIDR range
- HTML report output

## Skills practiced

Python, sockets and TCP networking, multithreading, command-line tools (`argparse`), basic network reconnaissance.
