#!/usr/bin/python3

"""
Mininet-WiFi topology for Scenario 1 with attacker node:
- 3 APs (AP1, AP2, AP3)
- 10 stations (clients)
- 1 attacker station connected to AP1
- Fixed IPs and association as per scenario 1
- Remote Ryu controller at 127.0.0.1:6633
"""

from mininet.wifi.net import Mininet_wifi
from mininet.node import RemoteController, OVSKernelAP
from mininet.cli import CLI
from mininet.log import setLogLevel, info


def scenario1_topology():
    net = Mininet_wifi(controller=RemoteController, accessPoint=OVSKernelAP)

    info("*** Creating Access Points\n")
    ap1 = net.addAccessPoint('ap1', ssid='ssid_ap1', mode='g', channel='1', position='50,50,0', ip='10.0.1.254/24')
    ap2 = net.addAccessPoint('ap2', ssid='ssid_ap2', mode='g', channel='6', position='150,50,0', ip='10.0.2.254/24')
    ap3 = net.addAccessPoint('ap3', ssid='ssid_ap3', mode='g', channel='11', position='250,50,0', ip='10.0.3.254/24')

    info("*** Creating Stations\n")
    # AP1 clients
    sta1 = net.addStation('sta1', ip='10.0.1.1/24', position='45,70,0')
    sta2 = net.addStation('sta2', ip='10.0.1.2/24', position='55,70,0')
    sta3 = net.addStation('sta3', ip='10.0.1.3/24', position='40,80,0')
    sta4 = net.addStation('sta4', ip='10.0.1.4/24', position='60,80,0')

    # AP2 clients
    sta5 = net.addStation('sta5', ip='10.0.2.1/24', position='145,70,0')
    sta6 = net.addStation('sta6', ip='10.0.2.2/24', position='155,70,0')
    sta7 = net.addStation('sta7', ip='10.0.2.3/24', position='150,80,0')

    # AP3 clients
    sta8 = net.addStation('sta8', ip='10.0.3.1/24', position='245,70,0')
    sta9 = net.addStation('sta9', ip='10.0.3.2/24', position='255,70,0')
    sta10 = net.addStation('sta10', ip='10.0.3.3/24', position='250,80,0')

    # Attacker station
    attacker = net.addStation('attacker', ip='192.168.0.100/24', mac='00:11:22:33:44:55', position='35,60,0')

    info("*** Adding Controller\n")
    c0 = net.addController('c0', controller=RemoteController, ip='10.0.0.3', port=6633)

    info("*** Configuring Wifi nodes\n")
    net.configureWifiNodes()

    info("*** Associating Stations to APs\n")
    # Link AP1 clients and attacker
    net.addLink(ap1, sta1)
    net.addLink(ap1, sta2)
    net.addLink(ap1, sta3)
    net.addLink(ap1, sta4)
    net.addLink(ap1, attacker)

    # AP2 clients
    net.addLink(ap2, sta5)
    net.addLink(ap2, sta6)
    net.addLink(ap2, sta7)

    # AP3 clients
    net.addLink(ap3, sta8)
    net.addLink(ap3, sta9)
    net.addLink(ap3, sta10)

    info("*** Starting Network\n")
    net.build()
    c0.start()
    ap1.start([c0])
    ap2.start([c0])
    ap3.start([c0])

    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping Network\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    scenario1_topology()
