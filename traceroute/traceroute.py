import argparse
import logging
import socket

logger = logging.getLogger("scapy")
logger.setLevel(logging.CRITICAL)

import sys
import time
from scapy.all import sr1
from scapy.layers.inet import IP, ICMP, TCP, UDP


def get_asn(ip_address):
    asn = b"Internal"
    query = f"{ip_address}\r\n"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("whois.radb.net", 43))
        s.sendall(query.encode())
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data

    lines = response.splitlines()
    for line in lines:
        if b"origin:" in line.lower():
            parts = line.split()
            if len(parts) >= 2:
                asn = parts[1].strip()

    return f"[{asn.decode()}]"


def traceroute(target_ip, protocol, timeout, port, max_requests, verbose=False):
    ttl = 1
    requests_amount = 0
    while max_requests == -1 or requests_amount < max_requests:
        ip_packet = IP(dst=target_ip, ttl=ttl)
        if protocol == "icmp":
            packet = ip_packet / ICMP()
        elif protocol == "tcp":
            packet = ip_packet / TCP(dport=port, flags="S")
        elif protocol == "udp":
            packet = ip_packet / UDP(dport=port)
        else:
            print("Unsupported protocol. Supported protocols: icmp, tcp, udp")
            sys.exit(1)

        start_time = time.time()
        reply = sr1(packet, timeout=timeout, verbose=0, iface=None)
        requests_amount += 1
        if reply is None:
            print(f"{ttl} *")
        else:
            elapsed_time = (time.time() - start_time) * 1000
            ip = reply.src
            asn = "" if not verbose else get_asn(ip)
            print(f"{ttl} {ip} [{elapsed_time:.2f},ms] {asn}")

            if ip == target_ip:
                break

        ttl += 1
    else:
        print("The number of requests has been exceeded")


parser = argparse.ArgumentParser(description="Custom Traceroute")
parser.add_argument("target_ip", help="Target IP address")
parser.add_argument("protocol", choices=["icmp", "tcp", "udp"], help="Protocol to use")
parser.add_argument("-t", "--timeout", type=int, default=2, help="Timeout in seconds for each "
                                                                 "packet")
parser.add_argument("-p", "--port", type=int, default=80, help="Port for TCP or UDP")
parser.add_argument("-n", "--max-requests", type=int, default=-1, help="Maximum number of "
                                                                       "requests")
parser.add_argument("-v", "--verbose", action="store_true", help="Show AS information")

args = parser.parse_args()
traceroute(args.target_ip, args.protocol, args.timeout, args.port, args.max_requests,
           args.verbose)

