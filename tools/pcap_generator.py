#!/usr/bin/env python3
# tools/pcap_generator.py
# Generates a sample PCAP with payloads that trigger typical detection rules.

from scapy.all import IP, TCP, UDP, Raw, wrpcap
import os

OUT_DIR = "data"
OUT_FILE = os.path.join(OUT_DIR, "sample_attack.pcap")
os.makedirs(OUT_DIR, exist_ok=True)

pkts = []

# Helper to add a tcp packet with raw payload
def add_tcp(src, dst, sport, dport, payload):
    p = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="PA")/Raw(load=payload.encode('utf-8', errors='replace'))
    pkts.append(p)

# 1) Repeated SSH SYNs (simulate brute force) - note: SYNs have no payload but we include small
for i in range(6):
    add_tcp("192.0.2.50", "192.0.2.10", 2000+i, 22, "SSH-2.0-demo")

# 2) HTTP GET to /.git/HEAD (should trigger git HEAD signature rules)
http_get = "GET /.git/HEAD HTTP/1.1\r\nHost: victim\r\nUser-Agent: test\r\n\r\n"
add_tcp("198.51.100.77", "192.0.2.10", 40000, 80, http_get)

# 3) HTTP request containing an XSS payload (reflected XSS)
xss = "GET /search?q=<script>alert('XSS')</script> HTTP/1.1\r\nHost: victim\r\n\r\n"
add_tcp("198.51.100.100", "192.0.2.10", 40001, 80, xss)

# 4) HTTP POST with SQLi-like payload
sqli = "POST /login HTTP/1.1\r\nHost: victim\r\nContent-Length: 20\r\n\r\nusername=admin' OR 1=1--"
add_tcp("203.0.113.9", "192.0.2.10", 41000, 80, sqli)

# 5) Payload containing known-test signature (EICAR-like) for detection example
eicar = "X5O!P%@AP[TEST-SIGNATURE]"
add_tcp("198.51.100.200", "192.0.2.10", 42000, 8080, f"GET /download?file={eicar} HTTP/1.1\r\nHost: victim\r\n\r\n")

# 6) "Failed login" text in an application log-like payload (for brute-force text matching)
for i in range(3):
    add_tcp("192.0.2.66", "192.0.2.10", 5000+i, 443, f"POST /auth HTTP/1.1\r\nHost: victim\r\n\r\nusername=guest&status=Failed login attempt {i}")

# Write PCAP
wrpcap(OUT_FILE, pkts)
print(f"Wrote {len(pkts)} packets to {OUT_FILE}")
