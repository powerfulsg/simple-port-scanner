#!/usr/bin/env python3
import socket
import argparse
from datetime import datetime


# -----------------------------------------------------------
# Common Service Mapping
# -----------------------------------------------------------
COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Proxy"
}


# -----------------------------------------------------------
# Banner Grabbing (TCP only)
# -----------------------------------------------------------
def grab_banner(sock):
    try:
        sock.settimeout(2)
        banner = sock.recv(1024)
        return banner.decode(errors="ignore").strip()
    except:
        return None


# -----------------------------------------------------------
# Service Detection
# -----------------------------------------------------------
def detect_service(port):
    return COMMON_SERVICES.get(port, "Unknown/Unmapped Service")


# -----------------------------------------------------------
# TCP Port Scanning
# -----------------------------------------------------------
def scan_tcp(ip, port, enable_banner, enable_service):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))

        if result == 0:
            print(f"[+] Port {port}/TCP is OPEN")

            if enable_service:
                print(f"    ↳ Service: {detect_service(port)}")

            if enable_banner:
                banner = grab_banner(sock)
                if banner:
                    print(f"    ↳ Banner: {banner}")
                else:
                    print("    ↳ No banner returned")

        sock.close()

    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user.")
        exit()


# -----------------------------------------------------------
# UDP Port Scanning
# -----------------------------------------------------------
def scan_udp(ip, port, enable_service):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)

        # Send a dummy packet
        try:
            sock.sendto(b"", (ip, port))
            data, addr = sock.recvfrom(1024)

            print(f"[+] Port {port}/UDP is OPEN")

            if enable_service:
                print(f"    ↳ Service: {detect_service(port)}")

        except socket.timeout:
            print(f"[?] Port {port}/UDP is OPEN or FILTERED")

        except Exception:
            pass

        sock.close()

    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user.")
        exit()


# -----------------------------------------------------------
# Argument Parser
# -----------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Python Port Scanner (TCP/UDP + Banner + Service Detection)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument("-H", "--host", required=True, help="Target IP / Hostname")
    parser.add_argument("-p", "--ports", required=True, help="Port or port range (e.g., 53 or 1-1000)")
    parser.add_argument("-b", "--banner", action="store_true", help="Enable banner grabbing (TCP only)")
    parser.add_argument("-s", "--service", action="store_true", help="Enable service detection")

    # Protocol flags
    parser.add_argument("--tcp", action="store_true", help="Scan using TCP")
    parser.add_argument("--udp", action="store_true", help="Scan using UDP")

    return parser.parse_args()


# -----------------------------------------------------------
# Main Program
# -----------------------------------------------------------
if __name__ == "__main__":
    args = parse_args()

    # Default to TCP if neither UDP/TCP is selected
    if not args.tcp and not args.udp:
        args.tcp = True

    # Parse port range or single port
    if "-" in args.ports:
        start_port, end_port = map(int, args.ports.split("-"))
    else:
        start_port = end_port = int(args.ports)

    print("\n=== Python Port Scanner ===")
    print(f"Target Host: {args.host}")
    print(f"Port Range: {start_port}-{end_port}")
    print(f"Protocols: {'TCP' if args.tcp else ''} {'UDP' if args.udp else ''}")
    print(f"Banner Grabbing: {'Enabled' if args.banner else 'Disabled'}")
    print(f"Service Detection: {'Enabled' if args.service else 'Disabled'}")
    print("-" * 60)

    start_time = datetime.now()

    # Loop through ports
    for port in range(start_port, end_port + 1):
        if args.tcp:
            scan_tcp(args.host, port, args.banner, args.service)

        if args.udp:
            scan_udp(args.host, port, args.service)

    end_time = datetime.now()

    print("-" * 60)
    print(f"Scan Completed in: {end_time - start_time}")
    print("Done.")
