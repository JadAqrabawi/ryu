#!/usr/bin/env python3
"""
Integrated Scenario 1 testbed script for external Ryu controller:

- Connects Mininet topology to remote Ryu controller (adjust IP below)
- Runs Mininet topology with attacker and clients
- Runs attack generator inside attacker node
- Starts ping traffic from clients to their AP gateways
- Collects and logs packet loss and latency
- Runs multiple test iterations
"""

import time
import csv
from mininet.wifi.net import Mininet_wifi
from mininet.node import RemoteController, OVSKernelAP
from mininet.log import setLogLevel, info
import threading
import re
import os

# === Configuration ===
RYU_CONTROLLER_IP = "10.0.0.3"  # Change to your Ryu controller IP
RYU_CONTROLLER_PORT = 6633

ATTACK_GENERATOR_SCRIPT = "./attack_generator.py"  # Adjust inside attacker node
NUM_RUNS = 6
PING_COUNT = 35  # number of pings to send per client
PING_INTERVAL = 1  # seconds between pings
CSV_LOG = "scenario1_integrated_metrics.csv"

AP_GATEWAYS = {
    'sta1': '10.0.1.254',
    'sta2': '10.0.1.254',
    'sta3': '10.0.1.254',
    'sta4': '10.0.1.254',
    'sta5': '10.0.2.254',
    'sta6': '10.0.2.254',
    'sta7': '10.0.2.254',
    'sta8': '10.0.3.254',
    'sta9': '10.0.3.254',
    'sta10': '10.0.3.254'
}

CLIENTS = list(AP_GATEWAYS.keys())


def parse_ping_output(ping_output):
    loss_match = re.search(r'(\d+)% packet loss', ping_output)
    avg_match = re.search(r'rtt min/avg/max/mdev = [\d\.]+/([\d\.]+)/', ping_output)
    packet_loss = float(loss_match.group(1)) if loss_match else 100.0
    avg_latency = float(avg_match.group(1)) if avg_match else 0.0
    return packet_loss, avg_latency


def start_mininet():
    """Create Mininet WiFi topology connecting to remote Ryu controller."""
    net = Mininet_wifi(controller=None, accessPoint=OVSKernelAP)

    info("*** Creating Access Points\n")
    ap1 = net.addAccessPoint('ap1', ssid='ssid_ap1', mode='g', channel='1', position='50,50,0', ip='10.0.1.254/24')
    ap2 = net.addAccessPoint('ap2', ssid='ssid_ap2', mode='g', channel='6', position='150,50,0', ip='10.0.2.254/24')
    ap3 = net.addAccessPoint('ap3', ssid='ssid_ap3', mode='g', channel='11', position='250,50,0', ip='10.0.3.254/24')

    info("*** Creating Stations\n")
    sta1 = net.addStation('sta1', ip='10.0.1.1/24', position='45,70,0')
    sta2 = net.addStation('sta2', ip='10.0.1.2/24', position='55,70,0')
    sta3 = net.addStation('sta3', ip='10.0.1.3/24', position='40,80,0')
    sta4 = net.addStation('sta4', ip='10.0.1.4/24', position='60,80,0')

    sta5 = net.addStation('sta5', ip='10.0.2.1/24', position='145,70,0')
    sta6 = net.addStation('sta6', ip='10.0.2.2/24', position='155,70,0')
    sta7 = net.addStation('sta7', ip='10.0.2.3/24', position='150,80,0')

    sta8 = net.addStation('sta8', ip='10.0.3.1/24', position='245,70,0')
    sta9 = net.addStation('sta9', ip='10.0.3.2/24', position='255,70,0')
    sta10 = net.addStation('sta10', ip='10.0.3.3/24', position='250,80,0')

    attacker = net.addStation('attacker', ip='192.168.0.100/24', mac='00:11:22:33:44:55', position='35,60,0')

    info("*** Adding Remote Controller\n")
    c0 = net.addController('c0', controller=RemoteController,
                          ip=RYU_CONTROLLER_IP, port=RYU_CONTROLLER_PORT)

    info("*** Configuring WiFi nodes\n")
    net.configureWifiNodes()

    info("*** Associating Stations to APs\n")
    net.addLink(ap1, sta1)
    net.addLink(ap1, sta2)
    net.addLink(ap1, sta3)
    net.addLink(ap1, sta4)
    net.addLink(ap1, attacker)

    net.addLink(ap2, sta5)
    net.addLink(ap2, sta6)
    net.addLink(ap2, sta7)

    net.addLink(ap3, sta8)
    net.addLink(ap3, sta9)
    net.addLink(ap3, sta10)

    info("*** Starting network\n")
    net.build()
    c0.start()
    ap1.start([c0])
    ap2.start([c0])
    ap3.start([c0])

    return net


def ping_client(net, client, target_ip, results):
    ping_cmd = f'ping -c {PING_COUNT} -i {PING_INTERVAL} {target_ip}'
    output = net.get(client).cmd(ping_cmd)
    loss, latency = parse_ping_output(output)
    results[client] = (loss, latency)


def run_attack(net):
    attacker = net.get('attacker')
    print("Starting attack generator in attacker node...")
    attacker.cmd(f'python3 {ATTACK_GENERATOR_SCRIPT} &')


def main():
    setLogLevel('info')

    net = start_mininet()

    if not os.path.exists(CSV_LOG):
        with open(CSV_LOG, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['runID', 'client', 'packet_loss_%', 'avg_latency_ms'])

    for run in range(1, NUM_RUNS + 1):
        info(f"=== Starting test run {run} ===\n")

        ping_results = {}
        threads = []
        for client in CLIENTS:
            t = threading.Thread(target=ping_client,
                                 args=(net, client, AP_GATEWAYS[client], ping_results))
            t.start()
            threads.append(t)

        time.sleep(3)  # stabilize pings

        run_attack(net)

        for t in threads:
            t.join()

        with open(CSV_LOG, 'a', newline='') as f:
            writer = csv.writer(f)
            for client, (loss, latency) in ping_results.items():
                writer.writerow([run, client, loss, latency])
                info(f"Run {run} - {client}: Packet loss {loss}%, Avg latency {latency} ms\n")

        info(f"=== Completed run {run} ===\n")
        time.sleep(5)

    info("All runs completed.")
    net.stop()


if __name__ == "__main__":
    import threading
    main()
