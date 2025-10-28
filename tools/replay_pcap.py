#!/usr/bin/env python3
# tools/replay_pcap.py
import sys, json
from scapy.all import rdpcap, TCP, UDP, IP, Raw

def pkt_to_record(pkt):
    rec = {}
    if IP in pkt:
        rec['src'] = pkt[IP].src
        rec['dst'] = pkt[IP].dst
    if TCP in pkt:
        rec['protocol'] = 'TCP'
        rec['sport'] = pkt[TCP].sport
        rec['dport'] = pkt[TCP].dport
    elif UDP in pkt:
        rec['protocol'] = 'UDP'
        rec['sport'] = pkt[UDP].sport
        rec['dport'] = pkt[UDP].dport
    else:
        rec['protocol'] = 'OTHER'
    # payload
    payload = ""
    if Raw in pkt:
        try:
            payload = pkt[Raw].load.decode('utf-8', errors='replace')
        except Exception:
            payload = str(pkt[Raw].load)
    rec['payload'] = payload
    return rec

def replay(path):
    pkts = rdpcap(path)
    for pkt in pkts:
        rec = pkt_to_record(pkt)
        print(json.dumps(rec, ensure_ascii=False))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tools/replay_pcap.py data/sample_attack.pcap")
        sys.exit(1)
    replay(sys.argv[1])
