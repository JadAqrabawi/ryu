from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, icmp, ether_types
from ryu.lib import hub
import time
import random
import csv
import os

class SDNDeauthMitigation(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Constants
    DETECTION_PROBABILITY = 0.90
    BLOCKING_SUCCESS_RATE = 0.80
    ATTACK_RATE_THRESHOLD = 50  # fps (simulated)
    CLIENT_DISCONNECT_TIMEOUT = 2  # seconds of no ICMP/traffic
    ATTACK_DURATION = 30  # seconds
    RESTORATION_TRIGGER_TIME = 10  # seconds no attack or disconnection
    NUM_RUNS_PER_SCENARIO = 20

    # Clients and reroute mapping for Scenario 1
    clients_ap1 = ['sta1', 'sta2', 'sta3', 'sta4']
    clients_ap1_ips = ['10.0.1.1', '10.0.1.2', '10.0.1.3', '10.0.1.4']
    reroute_targets = {
        'sta1': 'AP2',
        'sta2': 'AP2',
        'sta3': 'AP3',
        'sta4': 'AP3'
    }

    # Other clients
    clients_ap2_ips = ['10.0.2.1', '10.0.2.2', '10.0.2.3']
    clients_ap3_ips = ['10.0.3.1', '10.0.3.2', '10.0.3.3']

    def __init__(self, *args, **kwargs):
        super(SDNDeauthMitigation, self).__init__(*args, **kwargs)
        random.seed(42)  # For reproducibility

        # Tracking
        self.run_id = 1
        self.attack_detected = False
        self.attack_blocked = False
        self.attack_start_time = None
        self.last_attack_frame_time = None
        self.client_last_seen = {}  # ip -> last packet timestamp
        self.disconnected_clients = set()
        self.rerouted_clients = set()
        self.restored_clients = set()
        self.metrics_file = 'scenario1_metrics.csv'

        self.datapath = None  # will be set on switch connect
        self.monitor_thread = None
        self.restoration_thread = None

        # Initialize CSV file with headers
        if not os.path.exists(self.metrics_file):
            with open(self.metrics_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'runID', 'detected', 'blocked', 'disconnected_clients',
                    'rerouted_clients', 'restored_clients', 'packet_loss_%',
                    'mitigation_latency_s', 'throughput_Mbps'
                ])

        self.logger.info("Controller initialized for Scenario 1")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.datapath = ev.msg.datapath
        self.install_table_miss(self.datapath)

        # Start monitor thread if not started
        if self.monitor_thread is None:
            self.monitor_thread = hub.spawn(self._monitor_clients)

        # Start the first run after short delay
        hub.spawn_after(1, self._start_run)

    def install_table_miss(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def _start_run(self):
        self.logger.info(f"Starting run {self.run_id}")
        # Reset states
        self.attack_detected = False
        self.attack_blocked = False
        self.attack_start_time = time.time()
        self.last_attack_frame_time = self.attack_start_time
        self.client_last_seen.clear()
        self.disconnected_clients.clear()
        self.rerouted_clients.clear()
        self.restored_clients.clear()

        # Simulate attack detection probabilistically
        self.attack_detected = (random.random() < self.DETECTION_PROBABILITY)
        self.logger.info(f"Attack detected? {self.attack_detected}")

        # If detected, try blocking probabilistically
        if self.attack_detected:
            self.attack_blocked = (random.random() < self.BLOCKING_SUCCESS_RATE)
            self.logger.info(f"Attacker blocked? {self.attack_blocked}")

        # If not detected or blocking failed, forcibly disconnect all AP1 clients
        if not self.attack_detected or not self.attack_blocked:
            # Simulate full disconnection of AP1 clients
            for ip in self.clients_ap1_ips:
                # Mark last seen time far in past to trigger disconnection
                self.client_last_seen[ip] = 0
            self.disconnected_clients.update(self.clients_ap1_ips)
            self.logger.info("All AP1 clients forcibly disconnected due to attack")

            # Trigger rerouting for disconnected clients
            self._reroute_clients(self.disconnected_clients)
        else:
            # Attack mitigated early - no disconnection, no reroute
            self.logger.info("Attack mitigated early, no disconnections")

        # Schedule run end after attack duration + restoration delay
        hub.spawn_after(self.ATTACK_DURATION + self.RESTORATION_TRIGGER_TIME,
                        self._end_run)

    def _reroute_clients(self, disconnected_ips):
        self.logger.info(f"Rerouting disconnected clients: {disconnected_ips}")
        for ip in disconnected_ips:
            client = self._ip_to_client(ip)
            if client in self.rerouted_clients:
                continue
            if client in self.reroute_targets:
                self.rerouted_clients.add(client)
                self.logger.info(f"Client {client} rerouted to {self.reroute_targets[client]}")

                # Add flow rule to reroute (simulated, since Mininet-WiFi)
                self._install_reroute_flow(self.datapath, ip, self.reroute_targets[client])

    def _install_reroute_flow(self, datapath, client_ip, target_ap):
        # Placeholder: actual rerouting in Mininet-WiFi would require API calls
        # Here, we just log and simulate adding a flow to drop packets to/from old AP
        self.logger.info(f"Installing reroute flow for {client_ip} to {target_ap}")
        # Implementation depends on actual topology and IP/MAC mapping

    def _restore_clients(self):
        if not self.rerouted_clients:
            return
        self.logger.info(f"Restoring clients to original APs: {self.rerouted_clients}")
        self.restored_clients.update(self.rerouted_clients)
        self.rerouted_clients.clear()
        self.disconnected_clients.clear()

        # Remove reroute flows - simulated by logs
        self.logger.info("Restoration complete")

    def _end_run(self):
        now = time.time()
        mitigation_latency = 0 if not self.attack_detected else (now - self.attack_start_time)

        # Simulated packet loss % (random in realistic range)
        packet_loss = 100 if not self.attack_blocked else random.uniform(3, 7)

        # Simulated throughput (Mbps)
        throughput = 0 if not self.attack_blocked else random.uniform(8, 12)

        # Restore clients if needed
        if self.rerouted_clients:
            self._restore_clients()

        self._log_metrics(
            run_id=self.run_id,
            detected=self.attack_detected,
            blocked=self.attack_blocked,
            disconnected_clients=sorted(self.disconnected_clients),
            rerouted_clients=sorted(self.rerouted_clients),
            restored_clients=sorted(self.restored_clients),
            packet_loss=round(packet_loss, 1),
            mitigation_latency=round(mitigation_latency, 2),
            throughput=round(throughput, 1)
        )

        self.logger.info(f"Run {self.run_id} finished. Starting next run in 5 seconds...")
        self.run_id += 1

        # Schedule next run or finish
        if self.run_id <= self.NUM_RUNS_PER_SCENARIO:
            hub.spawn_after(5, self._start_run)
        else:
            self.logger.info("All runs completed.")

    def _log_metrics(self, run_id, detected, blocked, disconnected_clients,
                     rerouted_clients, restored_clients, packet_loss,
                     mitigation_latency, throughput):
        with open(self.metrics_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                run_id, detected, blocked, disconnected_clients,
                rerouted_clients, restored_clients, packet_loss,
                mitigation_latency, throughput
            ])

    def _ip_to_client(self, ip):
        for i, client_ip in enumerate(self.clients_ap1_ips):
            if client_ip == ip:
                return self.clients_ap1[i]
        # Could extend for other APs if needed
        return None

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Track last packet time for ICMP or any traffic from clients to detect silence.
        """
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Ignore LLDP packets
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        if ip_pkt:
            src_ip = ip_pkt.src
            self.client_last_seen[src_ip] = time.time()

        # Normal L2 forwarding
        dpid = datapath.id
        in_port = msg.match['in_port']
        dst = eth.dst
        src = eth.src

        self.mac_to_port = getattr(self, 'mac_to_port', {})
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # Install flow for known dst
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def _monitor_clients(self):
        """
        Periodically checks client activity to detect disconnections (no traffic for >2s)
        """
        while True:
            now = time.time()
            for ip in self.clients_ap1_ips:
                last_seen = self.client_last_seen.get(ip, 0)
                if (now - last_seen) > self.CLIENT_DISCONNECT_TIMEOUT:
                    if ip not in self.disconnected_clients:
                        self.logger.info(f"Client {ip} considered disconnected due to inactivity")
                        self.disconnected_clients.add(ip)
                        self._reroute_clients({ip})

            # Check for restoration trigger: no disconnection + no attack frames for RESTORATION_TRIGGER_TIME
            if self.attack_detected and self.last_attack_frame_time:
                if (now - self.last_attack_frame_time) > self.RESTORATION_TRIGGER_TIME:
                    self._restore_clients()
                    self.attack_detected = False
                    self.attack_blocked = False

            hub.sleep(1)
