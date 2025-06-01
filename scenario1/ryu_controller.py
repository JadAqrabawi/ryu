from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, ether_types
from ryu.lib import hub
import time
import random
import csv
import os

class DeauthMitigationController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Constants (adjust as needed)
    DETECTION_PROBABILITY = 0.90
    BLOCKING_SUCCESS_RATE = 0.80
    CLIENT_DISCONNECT_TIMEOUT = 2
    RESTORATION_TRIGGER_TIME = 10
    ATTACKER_IP = "10.0.1.100"
    ATTACK_DURATION = 30
    RUNS_TOTAL = 3  # For demonstration; increase as needed

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapath = None
        self.run_id = 1

        # Track client states: IP -> last seen time
        self.client_last_seen = {}

        # Disconnected and rerouted clients sets
        self.disconnected_clients = set()
        self.rerouted_clients = set()
        self.restored_clients = set()

        self.attack_detected = False
        self.attack_blocked = False

        # Reroute mapping for Scenario 1
        self.client_to_backup_ap_port = {
            '10.0.1.1': 2,  # AP2 port on switch
            '10.0.1.2': 2,
            '10.0.1.3': 3,  # AP3 port
            '10.0.1.4': 3
        }
        self.client_original_ap_port = {
            '10.0.1.1': 1,
            '10.0.1.2': 1,
            '10.0.1.3': 1,
            '10.0.1.4': 1
        }

        # Metrics CSV setup
        self.metrics_file = 'scenario1_metrics.csv'
        if not os.path.exists(self.metrics_file):
            with open(self.metrics_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['runID', 'detected', 'blocked', 'disconnected_clients',
                                 'rerouted_clients', 'restored_clients',
                                 'mitigation_latency_s'])

        self.monitor_thread = None

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.datapath = ev.msg.datapath
        self.install_table_miss(self.datapath)

        # Start monitoring thread once controller connected
        if not self.monitor_thread:
            self.monitor_thread = hub.spawn(self._monitor_clients)

        # Start first run after short delay
        hub.spawn_after(1, self._start_run)

    def install_table_miss(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info("Installed table-miss flow")

    def _start_run(self):
        self.logger.info(f"=== Starting run {self.run_id} ===")
        self.attack_detected = (random.random() < self.DETECTION_PROBABILITY)
        self.attack_blocked = self.attack_detected and (random.random() < self.BLOCKING_SUCCESS_RATE)

        self.client_last_seen.clear()
        self.disconnected_clients.clear()
        self.rerouted_clients.clear()
        self.restored_clients.clear()

        self.mitigation_start_time = None

        self.logger.info(f"Attack detected? {self.attack_detected}")
        self.logger.info(f"Attacker blocked? {self.attack_blocked}")

        if self.attack_detected and self.attack_blocked:
            self.block_attacker(self.datapath, self.ATTACKER_IP)
            self.logger.info("Attack mitigated early, no client disconnections")
        else:
            # Simulate all AP1 clients disconnected due to attack
            disconnected_ips = list(self.client_to_backup_ap_port.keys())
            self.logger.info(f"All AP1 clients forcibly disconnected due to attack")
            self._handle_disconnections(disconnected_ips)

        # Schedule run end and restoration after attack duration + restoration time
        hub.spawn_after(self.ATTACK_DURATION + self.RESTORATION_TRIGGER_TIME, self._end_run)

    def block_attacker(self, datapath, attacker_ip):
        self.logger.info(f"Blocking attacker IP: {attacker_ip}")
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(ipv4_src=attacker_ip, eth_type=0x0800)
        actions = []  # drop
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=100,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info("Installed attacker block flow")

    def _handle_disconnections(self, ips):
        for ip in ips:
            if ip not in self.disconnected_clients:
                self.logger.info(f"Client {ip} disconnected due to inactivity")
                self.disconnected_clients.add(ip)

        self._reroute_clients(self.disconnected_clients)

    def _reroute_clients(self, disconnected_ips):
        for ip in disconnected_ips:
            if ip in self.rerouted_clients:
                continue
            self.logger.info(f"Rerouting client {ip} to backup AP port {self.client_to_backup_ap_port[ip]}")
            self._install_flow(self.datapath, ip, self.client_to_backup_ap_port[ip], priority=90)
            self.rerouted_clients.add(ip)
        self.mitigation_start_time = time.time()

    def _install_flow(self, datapath, client_ip, out_port, priority=90):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(ipv4_dst=client_ip, eth_type=0x0800)
        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info(f"Installed flow for {client_ip} output port {out_port} with priority {priority}")

    def _restore_clients(self):
        for ip in list(self.rerouted_clients):
            orig_port = self.client_original_ap_port.get(ip)
            if orig_port is not None:
                self.logger.info(f"Restoring client {ip} to original AP port {orig_port}")
                self._install_flow(self.datapath, ip, orig_port, priority=80)
                self.restored_clients.add(ip)
        self.rerouted_clients.clear()
        self.disconnected_clients.clear()

    def _end_run(self):
        mitigation_latency = 0
        if self.mitigation_start_time:
            mitigation_latency = time.time() - self.mitigation_start_time

        self._restore_clients()

        # Log run results to CSV
        with open(self.metrics_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                self.run_id,
                self.attack_detected,
                self.attack_blocked,
                list(self.disconnected_clients),
                list(self.rerouted_clients),
                list(self.restored_clients),
                round(mitigation_latency, 2)
            ])

        self.logger.info(f"Run {self.run_id} ended. Mitigation latency: {mitigation_latency:.2f} s")

        self.run_id += 1
        if self.run_id <= self.RUNS_TOTAL:
            # Start next run after 5 seconds
            hub.spawn_after(5, self._start_run)
        else:
            self.logger.info("All runs completed.")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # Track client packet times (simplified for demo)
        msg = ev.msg
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            self.client_last_seen[ip_pkt.src] = time.time()

    def _monitor_clients(self):
        while True:
            now = time.time()
            disconnected = []
            for ip, last_seen in self.client_last_seen.items():
                if now - last_seen > self.CLIENT_DISCONNECT_TIMEOUT:
                    if ip not in self.disconnected_clients and ip in self.client_original_ap_port:
                        disconnected.append(ip)
            if disconnected:
                self._handle_disconnections(disconnected)

            # Wait 1 second between checks
            hub.sleep(1)
