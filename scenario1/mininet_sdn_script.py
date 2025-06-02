
from mn_wifi.net import Mininet_wifi
from mininet.node import OVSKernelAP
from mn_wifi.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import time
import subprocess
import random

def scenario1_topology():
    net = Mininet_wifi(controller=RemoteController, accessPoint=OVSKernelAP)

    info("*** Creating Access Points\n")
    ap1 = net.addAccessPoint('ap1', ssid='ssid_ap1', mode='g', channel='1', 
                            position='30,50,0', ip='10.0.1.254/24')
    ap2 = net.addAccessPoint('ap2', ssid='ssid_ap2', mode='g', channel='6', 
                            position='60,50,0', ip='10.0.2.254/24')
    ap3 = net.addAccessPoint('ap3', ssid='ssid_ap3', mode='g', channel='11', 
                            position='90,50,0', ip='10.0.3.254/24')

    info("*** Creating Stations\n")
    sta1 = net.addStation('sta1', ip='10.0.1.1/24', position='25,45,0')
    sta2 = net.addStation('sta2', ip='10.0.1.2/24', position='30,45,0')
    sta3 = net.addStation('sta3', ip='10.0.1.3/24', position='35,45,0')
    sta4 = net.addStation('sta4', ip='10.0.1.4/24', position='40,45,0')
    sta5 = net.addStation('sta5', ip='10.0.2.1/24', position='55,45,0')
    sta6 = net.addStation('sta6', ip='10.0.2.2/24', position='60,45,0')
    sta7 = net.addStation('sta7', ip='10.0.2.3/24', position='65,45,0')
    sta8 = net.addStation('sta8', ip='10.0.3.1/24', position='85,45,0')
    sta9 = net.addStation('sta9', ip='10.0.3.2/24', position='90,45,0')
    sta10 = net.addStation('sta10', ip='10.0.3.3/24', position='95,45,0')
    
    attacker = net.addStation('attacker', ip='10.0.1.100/24', position='30,55,0')

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

    info("*** Adding Remote Controller\n")
    c0 = net.addController('c0', controller=RemoteController, ip='10.0.0.3', port=6633)

    info("*** Starting network\n")
    net.build()
    c0.start()
    ap1.start([c0])
    ap2.start([c0])
    ap3.start([c0])

    info("*** Setting up routing\n")
    # Enable IP forwarding
    ap1.cmd("sysctl -w net.ipv4.ip_forward=1")
    ap2.cmd("sysctl -w net.ipv4.ip_forward=1")
    ap3.cmd("sysctl -w net.ipv4.ip_forward=1")
    
    # Add direct routes
    ap1.cmd('ip route add 10.0.2.0/24 dev ap1-wlan1')
    ap1.cmd('ip route add 10.0.3.0/24 dev ap1-wlan1')
    ap2.cmd('ip route add 10.0.1.0/24 dev ap2-wlan1')
    ap2.cmd('ip route add 10.0.3.0/24 dev ap2-wlan1')
    ap3.cmd('ip route add 10.0.1.0/24 dev ap3-wlan1')
    ap3.cmd('ip route add 10.0.2.0/24 dev ap3-wlan1')
    
    # Set default routes for stations
    stations = net.stations
    for sta in stations:
        subnet = sta.IP().split('.')[2]
        sta.cmd(f'ip route add default via 10.0.{subnet}.254')

    info("*** Testing connectivity before attack\n")
    net.pingAll()

    info("*** Configuring attacker interface\n")
    attacker.cmd('ip link set %s-wlan0 down' % attacker.name)
    attacker.cmd('iw dev %s-wlan0 set type monitor' % attacker.name)
    attacker.cmd('ip link set %s-wlan0 up' % attacker.name)
    
    info("*** Starting deauthentication attack\n")
    attacker.cmd('echo "10.0.1.1\n10.0.1.2\n10.0.1.3\n10.0.1.4" > targets.txt')
    attacker.cmd('mdk4 %s-wlan0 d -B targets.txt &' % attacker.name)
    
    info("*** Starting traffic monitoring\n")
    # Start ping tests to gateways
    for sta in stations:
        if sta != attacker:
            subnet = sta.IP().split('.')[2]
            gateway = f'10.0.{subnet}.254'
            sta.cmd(f'ping {gateway} -i 0.5 -c 60 > ping_{sta.name}.log &')

    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    scenario1_topology()