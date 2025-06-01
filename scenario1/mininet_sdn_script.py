from mn_wifi.net import Mininet_wifi
from mn_wifi.node import RemoteController, OVSKernelAP
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import time

def scenario1_topology():
    net = Mininet_wifi(controller=RemoteController, accessPoint=OVSKernelAP)

    info("*** Creating Access Points\n")
    ap1 = net.addAccessPoint('ap1', ssid='ssid_ap1', mode='g', channel='1', ip='10.0.1.254/24')
    ap2 = net.addAccessPoint('ap2', ssid='ssid_ap2', mode='g', channel='6', ip='10.0.2.254/24')
    ap3 = net.addAccessPoint('ap3', ssid='ssid_ap3', mode='g', channel='11', ip='10.0.3.254/24')

    info("*** Creating Stations\n")
    # AP1 clients
    sta1 = net.addStation('sta1', ip='10.0.1.1/24')
    sta2 = net.addStation('sta2', ip='10.0.1.2/24')
    sta3 = net.addStation('sta3', ip='10.0.1.3/24')
    sta4 = net.addStation('sta4', ip='10.0.1.4/24')

    # AP2 clients
    sta5 = net.addStation('sta5', ip='10.0.2.1/24')
    sta6 = net.addStation('sta6', ip='10.0.2.2/24')
    sta7 = net.addStation('sta7', ip='10.0.2.3/24')

    # AP3 clients
    sta8 = net.addStation('sta8', ip='10.0.3.1/24')
    sta9 = net.addStation('sta9', ip='10.0.3.2/24')
    sta10 = net.addStation('sta10', ip='10.0.3.3/24')

    # Attacker station (in AP1 subnet)
    attacker = net.addStation('attacker', ip='10.0.1.100/24')

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

    info("*** Running baseline ping to check connectivity\n")
    net.pingAll()

    info("*** Starting attack generator in attacker node\n")
    # Execute attack generator script inside attacker node automatically
    # Assuming attack_generator.sh is in current directory and executable
    attacker.cmd('chmod +x ./attack_generator.sh')
    attacker.cmd('./attack_generator.sh &')  # Run attack in background

    time.sleep(2)  # Optional delay to let attack start

    info("*** Dropping to CLI\n")
    CLI(net)

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    scenario1_topology()
