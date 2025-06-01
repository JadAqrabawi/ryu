from mn_wifi.net import Mininet_wifi
from mn_wifi.node import RemoteController, OVSKernelAP
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import time
import subprocess

def scenario1_topology():
    net = Mininet_wifi(controller=RemoteController, accessPoint=OVSKernelAP)

    info("*** Creating Access Points\n")
    ap1 = net.addAccessPoint('ap1', ssid='ssid_ap1', mode='g', channel='1', ip='10.0.1.254/24')
    ap2 = net.addAccessPoint('ap2', ssid='ssid_ap2', mode='g', channel='6', ip='10.0.2.254/24')
    ap3 = net.addAccessPoint('ap3', ssid='ssid_ap3', mode='g', channel='11', ip='10.0.3.254/24')

    info("*** Creating Stations\n")
    # AP1 clients
    sta1 = net.addStation('sta1', ip='10.0.1.1/24', position='10,20,0')
    sta2 = net.addStation('sta2', ip='10.0.1.2/24', position='15,20,0')
    sta3 = net.addStation('sta3', ip='10.0.1.3/24', position='20,20,0')
    sta4 = net.addStation('sta4', ip='10.0.1.4/24', position='25,20,0')

    # AP2 clients
    sta5 = net.addStation('sta5', ip='10.0.2.1/24', position='40,20,0')
    sta6 = net.addStation('sta6', ip='10.0.2.2/24', position='45,20,0')
    sta7 = net.addStation('sta7', ip='10.0.2.3/24', position='50,20,0')

    # AP3 clients
    sta8 = net.addStation('sta8', ip='10.0.3.1/24', position='70,20,0')
    sta9 = net.addStation('sta9', ip='10.0.3.2/24', position='75,20,0')
    sta10 = net.addStation('sta10', ip='10.0.3.3/24', position='80,20,0')

    # Attacker station (in AP1 subnet)
    attacker = net.addStation('attacker', ip='10.0.1.100/24', position='10,30,0')

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

    info("*** Associating Stations to APs\n")
    net.addLink(sta1, ap1)
    net.addLink(sta2, ap1)
    net.addLink(sta3, ap1)
    net.addLink(sta4, ap1)

    net.addLink(sta5, ap2)
    net.addLink(sta6, ap2)
    net.addLink(sta7, ap2)

    net.addLink(sta8, ap3)
    net.addLink(sta9, ap3)
    net.addLink(sta10, ap3)

    # Associate attacker to AP1 explicitly
    net.addLink(attacker, ap1)

    info("*** Adding Remote Controller\n")
    c0 = net.addController('c0', controller=RemoteController, ip='10.0.0.3', port=6633)

    info("*** Starting network\n")
    net.build()
    c0.start()
    ap1.start([c0])
    ap2.start([c0])
    ap3.start([c0])

    # Configure routing
    ap1.cmd('ip route add 10.0.2.0/24 via 10.0.1.254')
    ap1.cmd('ip route add 10.0.3.0/24 via 10.0.1.254')
    ap2.cmd('ip route add 10.0.1.0/24 via 10.0.2.254')
    ap2.cmd('ip route add 10.0.3.0/24 via 10.0.2.254')
    ap3.cmd('ip route add 10.0.1.0/24 via 10.0.3.254')
    ap3.cmd('ip route add 10.0.2.0/24 via 10.0.3.254')

    info("*** Testing connectivity before attack\n")
    net.pingAll()

    info("*** Setting up attack interface\n")
    # Put attacker interface in monitor mode
    attacker.cmd('ip link set %s-wlan0 down' % attacker.name)
    attacker.cmd('iw dev %s-wlan0 set type monitor' % attacker.name)
    attacker.cmd('ip link set %s-wlan0 up' % attacker.name)
    
    info("*** Starting attack generator in attacker node\n")
    # Generate target list and start attack
    attacker.cmd('echo "10.0.1.1\n10.0.1.2\n10.0.1.3\n10.0.1.4" > targets.txt')
    attacker.cmd('mdk4 %s-wlan0 d -B targets.txt &' % attacker.name)
    
    info("*** Starting traffic monitor\n")
    # Start background traffic monitoring
    for sta in [sta1, sta2, sta3, sta4, sta5, sta6, sta7, sta8, sta9, sta10]:
        sta.cmd('ping 10.0.1.254 -i 0.5 -w 300 > ping_results_%s.txt &' % sta.name)

    info("*** Dropping to CLI\n")
    CLI(net)

    info("*** Collecting results\n")
    # Collect ping results from all stations
    for sta in [sta1, sta2, sta3, sta4, sta5, sta6, sta7, sta8, sta9, sta10]:
        sta.cmd('cat ping_results_%s.txt' % sta.name)

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    scenario1_topology()