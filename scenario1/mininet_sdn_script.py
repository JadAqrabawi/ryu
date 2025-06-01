#!/usr/bin/env python3
"""
Scenario 1 – three APs, nine stations, 20-s wired-link outage on ap2
"""

import os, time, threading, random, csv
from mininet.node  import RemoteController, OVSSwitch
from mininet.link  import TCLink
from mininet.log   import setLogLevel, info
from mn_wifi.net   import Mininet_wifi
from mn_wifi.node  import OVSKernelAP
from mn_wifi.cli   import CLI
from mn_wifi.link  import wmediumd
from mn_wifi.wmediumdConnector import interference
setLogLevel('info')

# results folder
RESULTS_DIR = os.path.dirname(os.path.abspath(__file__))
RUN_LOG = os.path.join(RESULTS_DIR, "scenario1_runs.csv")

def record(row: dict):
    hdr = not os.path.exists(RUN_LOG)
    with open(RUN_LOG, "a", newline="") as f:
        w = csv.writer(f)
        if hdr:
            w.writerow(row.keys())
        w.writerow(row.values())

# ───── topology ─────
def build():
    net = Mininet_wifi(controller=RemoteController,
                       link=TCLink,
                       accessPoint=OVSKernelAP,
                       switch=OVSSwitch,
                       wmediumd_mode=interference)

    net.addController("c0", ip="127.0.0.1", port=6653)
    s1 = net.addSwitch("s1")

    aps = {}
    for name, pos, ch in (("ap1", "10,30,0", "1"),
                          ("ap2", "30,30,0", "6"),
                          ("ap3", "50,30,0", "11")):
        ap = net.addAccessPoint(name, ssid=f"ssid-{name}",
                                mode="g", channel=ch,
                                position=pos)
        ap.params["position"] = pos
        ap.lastpos            = pos
        ap.wmIfaces           = []
        aps[name] = ap

    gw = net.addHost("gw", ip="10.0.0.254/24")

    stations = []
    for i in range(1, 10):
        pos = f"{5*i},10,0"
        sta = net.addStation(f"sta{i}", ip=f"10.0.0.{i}/24",
                             position=pos)
        sta.params["position"] = pos
        sta.lastpos            = pos
        sta.wmIfaces           = []
        stations.append(sta)

    net.setPropagationModel(model="logDistance", exp=4)
    net.configureWifiNodes()

    for ap in aps.values():
        net.addLink(ap, s1, bw=100)

    # gateway now hangs off ap1 (same L2 domain as stations)
    net.addLink(gw, aps["ap1"], bw=100)

    return net, aps, stations

# helpers
def start_pings(stations, dst="10.0.0.254"):
    for sta in stations:
        sta.cmd(f"ping -i 0.5 {dst} &")

def outage(net, ap2):
    info("*** waiting 30 s – then bring ap2-s1 link DOWN for 20 s\n")
    time.sleep(30)
    if ap2.name in net.nameToNode:
        net.configLinkStatus(ap2, "s1", "down")
        info("*** link down\n")
    else:
        info("*** ap2 not found in net\n")
    time.sleep(20)
    if ap2.name in net.nameToNode:
        net.configLinkStatus(ap2, "s1", "up")
        info("*** link restored\n")
    else:
        info("*** ap2 not found in net\n")

# main
def run():
    net, aps, stations = build()
    info("*** build & start\n")
    net.build()
    net.start()

    start_pings(stations)

    threading.Thread(target=outage,
                     args=(net, aps["ap2"]), daemon=True).start()

    record({ "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
             "run_id"   : random.randint(10000, 99999),
             "scenario" : "1",
             "note"     : "ap2 wired link down 20 s" })

    CLI(net)
    net.stop()

if __name__ == "__main__":
    run()
