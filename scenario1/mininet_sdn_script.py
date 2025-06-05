from mn_wifi.net import Mininet_wifi
from mininet.node import UserAP, Station
from mn_wifi.node  import OVSKernelAP
from mininet.cli import CLI
from mn_wifi.link import wmediumd
from mn_wifi.wmediumdConnector import interference
from mininet.node import Controller
from mininet.log import setLogLevel

from mininet.log import setLogLevel, info

import sys
import time

def createTopo():
    net = Mininet_wifi(controller=Controller, link=wmediumd,
                       accessPoint=OVSKernelAP, enable_interference=True)
    
    # Add controller
    c0 = net.addController('c0', controller=Controller, ip='127.0.0.1', port=6653)

    # Create 3 Access Points
    ap1 = net.addAccessPoint('ap1', ssid='AP1', mode='g', channel='1',
                             position='100,100,0', range=100)
    ap2 = net.addAccessPoint('ap2', ssid='AP2', mode='g', channel='6',
                             position='200,100,0', range=100)
    ap3 = net.addAccessPoint('ap3', ssid='AP3', mode='g', channel='11',
                             position='300,100,0', range=100)
    reserved_ap = net.addAccessPoint('reserved', ssid='ReservedAP', mode='g',
                                     channel='1', position='150,200,0', range=100)

    # Create 10 stations (clients)
    stations = []
    positions = [(90,90), (110,90), (90,110), (110,110),  # AP1 clients
                 (190,90), (210,90), (190,110),           # AP2 clients
                 (290,90), (310,90), (290,110)]           # AP3 clients

    for i in range(1, 11):
        sta = net.addStation(f'sta{i}', mac=f'00:00:00:00:00:{i:02d}',
                             ip=f'10.0.0.{i}/24', position=positions[i-1])
        stations.append(sta)

    # Add attacker
    attacker = net.addStation('attacker', mac='00:00:00:00:00:AA',
                              ip='10.0.0.100/24', position='100,150,0')

    # Configure propagation model
    net.setPropagationModel(model="logDistance", exp=3.5)

    # Build network
    net.configureWifiNodes()

    # Link APs in backbone
    net.addLink(ap1, ap2)
    net.addLink(ap2, ap3)
    net.addLink(ap3, reserved_ap)

    return net, stations, attacker

def start_benign_traffic(net, stations):
    print("Generating normal traffic...")
    for i in range(20):  # 20 runs
        print(f"Run {i+1}/20 - Normal traffic")
        for sta in stations:
            sta.cmd("wget http://10.0.0.1/index.html -O /dev/null &")
            sta.cmd("ping -c 10 -i 0.2 10.0.0.1 &")
        time.sleep(10)

def start_attack(net, attacker):
    print("Starting de-authentication attack on AP1...")
    # Start de-auth attack targeting AP1 clients
    attacker.cmd("aireplay-ng -0 0 -a 00:00:00:00:01:00 mon0 &")
    time.sleep(30)
    attacker.cmd("killall aireplay-ng")

def start_mitigation(net, stations):
    for run_id in range(20):
        print(f"Run {run_id+1}/20 - SDN mitigation")
        start_attack(net, net.get('attacker'))
        time.sleep(5)  # Detection and mitigation time
        time.sleep(25)  # Attack duration
        time.sleep(10)  # Restoration period

def main(scenario):
    setLogLevel('info')
    net, stations, attacker = createTopo()
    
    net.start()
    net.get('c0').start()
    
    # Start web server on sta1
    net.get('sta1').cmd('python -m SimpleHTTPServer 80 &')
    
    # Start monitor mode on attacker
    attacker.cmd('ifconfig attacker-wlan0 down')
    attacker.cmd('iwconfig attacker-wlan0 mode monitor')
    attacker.cmd('ifconfig attacker-wlan0 up')
    attacker.cmd('ifconfig attacker-wlan0 mon0')
    
    # Associate stations with APs
    for sta in stations[0:4]:
        sta.cmd('iwconfig sta-wlan0 essid AP1')
    for sta in stations[4:7]:
        sta.cmd('iwconfig sta-wlan0 essid AP2')
    for sta in stations[7:10]:
        sta.cmd('iwconfig sta-wlan0 essid AP3')
    
    if scenario == 'baseline':
        start_benign_traffic(net, stations)
    elif scenario == 'attack':
        start_attack(net, attacker)
    elif scenario == 'mitigation':
        start_mitigation(net, stations)
    else:
        CLI_wifi(net)
    
    net.stop()

if __name__ == '__main__':
    scenario = 'mitigation' if len(sys.argv) < 2 else sys.argv[1]
    main(scenario)