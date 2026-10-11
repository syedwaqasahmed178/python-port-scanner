import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime


def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    for p in ports:
        if not 1 <= p <= 65535:
            raise ValueError(f"Port out of range: {p}")
    return sorted(ports)


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def grab_banner(sock):
    data = b""
    try:
        data = sock.recv(1024)
    except socket.timeout:
        pass
    except OSError:
        return ""
    try:
        if not data:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = sock.recv(1024)
        return data.decode(errors="ignore").strip().splitlines()[0][:120] if data else ""
    except (OSError, IndexError):
        return ""


def scan_port(host, port, timeout, banner):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) != 0:
                return None
            result = {"port": port, "service": service_name(port), "banner": ""}
            if banner:
                result["banner"] = grab_banner(s)
            return result
    except OSError:
        return None


def main():
    parser = argparse.ArgumentParser(description="Simple TCP port scanner (use only with permission).")
    parser.add_argument("host", help="Target hostname or IP address")
    parser.add_argument("-p", "--ports", default="1-1024", help="Ports, e.g. 22,80,443 or 1-1024 (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=0.5, help="Seconds to wait per port (default: 0.5)")
    parser.add_argument("-b", "--banner", action="store_true", help="Try to grab service banners")
    parser.add_argument("-o", "--output", help="Save results to a JSON file")
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.host)
        ports = parse_ports(args.ports)
    except (socket.gaierror, ValueError) as err:
        sys.exit(f"Error: {err}")

    print(f"Scanning {args.host} ({ip}) - {len(ports)} ports, {args.threads} threads")
    started = time.time()

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        results = pool.map(lambda p: scan_port(ip, p, args.timeout, args.banner), ports)
        open_ports = sorted((r for r in results if r), key=lambda r: r["port"])

    elapsed = time.time() - started

    if open_ports:
        print(f"\n{'PORT':<8}{'SERVICE':<14}BANNER")
        for r in open_ports:
            print(f"{r['port']:<8}{r['service']:<14}{r['banner']}")
    else:
        print("\nNo open ports found.")
    print(f"\nDone: {len(open_ports)} open port(s) in {elapsed:.2f}s")

    if args.output:
        report = {
            "target": args.host,
            "ip": ip,
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
            "ports_scanned": len(ports),
            "open_ports": open_ports,
        }
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Report saved to {args.output}")


if __name__ == "__main__":
    main()
