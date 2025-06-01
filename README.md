sudo systemctl restart NetworkManager

chmod +x attack_generator.sh

RYU_LOG_LEVEL=INFO ryu-manager ryu_controller.py

ryu-manager ryu_controller.py

sudo python3 mininet_sdn_script.py --controller=remote,ip=<10.0.0.1>,port=6633

# README: SDN Wi-Fi De-auth Attack Mitigation Experiment

## Overview

This project tests an SDN-based framework to mitigate Wi-Fi deauthentication jamming attacks using Ryu controller and Mininet-WiFi emulation. The system detects attacks, blocks attackers, reroutes disconnected clients, and restores connectivity after attacks.

---

## Components

* **ryu\_controller.py**
  Ryu SDN controller implementing detection, blocking, rerouting, restoration with detailed logging.

* **mininet\_sdn\_script.py**
  Mininet-WiFi script creating a topology with 3 APs, 10 stations, and an attacker node. Runs automated test runs with pings before/during/after attacks, starts the attack generator, logs results, and provides interactive CLI access after tests.

* **attack\_generator.py**
  Script run inside the attacker node to send spoofed deauth frames at \~50 fps for 30 seconds.

---

## Setup Instructions

1. **Environment**
   Use a Linux VM (Ubuntu 20.04 recommended) with:

   * Mininet-WiFi installed
   * Ryu controller installed (preferably v4 or later)
   * Python 3 with Scapy installed (for attack\_generator.py)

2. **Network Configuration**
   Make sure VM network adapter is configured as “Host-Only” or “Bridged” for controller and Mininet to communicate.

3. **File Placement**
   Place all scripts (`ryu_controller.py`, `mininet_sdn_script.py`, `attack_generator.py`) in the same directory on the Mininet host.

---

## Running the Experiment

### Step 1: Start the Ryu Controller

```bash
RYU_LOG_LEVEL=INFO ryu-manager ryu_controller.py
```

Watch the terminal for flow installation and detection logs.

### Step 2: Run Mininet-WiFi Topology and Tests

In another terminal on the same VM, run:

```bash
sudo python3 mininet_sdn_script.py --controller=remote,ip=10.0.0.3,port=6633
```

* This runs 3 test runs by default (modify `NUM_RUNS` in the script if needed).
* For each run, it performs baseline pings, launches attack generator in the attacker node, pings during attack, waits, then pings after attack.
* Results are logged in `scenario1_integrated_metrics.csv`.

### Step 3: Use Mininet CLI for Manual Checks

After the scripted runs complete, the Mininet CLI opens:

* Use commands like:

  * `pingall` to check connectivity.
  * `nodes` to list all nodes.
  * `xterm attacker` to open terminal on attacker station.
  * `dump` to inspect flows and interfaces.
* When done, type `exit` to quit CLI and cleanly stop Mininet.

---

## Notes & Tips

* Adjust attacker interface name in `attack_generator.py` if needed (`INTERFACE` variable).
* Replace MAC addresses in `attack_generator.py` with real AP and client MACs if available.
* Use controller logs to verify that flows are installed for blocking, rerouting, and restoring clients.
* Check the CSV logs for packet loss and latency metrics during different phases.
* To increase test runs, change `NUM_RUNS` in `mininet_sdn_script.py`.
* For debugging, increase Ryu logging level to DEBUG.

## Troubleshooting

* **Mininet nodes can't ping controller:**
  Check VM network adapter settings and IP addresses.

* **Attack generator not sending packets:**
  Confirm wireless interface name inside attacker (`ifconfig` in Mininet CLI).

* **Flows not installed or clients not rerouted:**
  Verify Ryu controller logs and flow table.

* **Permission errors running scripts:**
  Use `sudo` for Mininet scripts as required.


