from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
import random
import time
import csv
import os

class DeauthDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Constants / Config
    DETECTION_PROBABILITY = 0.90
    BLOCKING_SUCCESS_RATE = 0.80
    CLIENT_DISCONNECT_TIMEOUT = 2  # seconds no ICMP activity
    RESTORATION_TRIGGER_TIME = 10  # seconds no attacks/disconnects before restore
    ATTACKER_IP = '10.0.1.100'
    ATTACKED_AP_CLIENTS = ['10.0.1.1', '10.0.1.2', '10.0.1.3', '10.0.1.4']
    REROUTE_MAP = {
        '10.0.1.1': 2,  # Port to AP2
        '10.0.1.2': 2,
        '10.0.1.3': 3,  # Port to AP3
        '10.0.1.4': 3,
    }

    def __init__(self, *args, **kwargs):
        super(DeauthDefense, self).__init__(*args, **kwargs)
        self.datapath = None
        self.detected = False
        self.blocked = False
        self.disconnected_clients = set()
        self.rerouted_clients = set()
        self.restored_clients = set()
        self.last_activity = {}  # client_ip -> timestamp of last ICMP packet
        self.last_attack_time = 0
        self.restoration_timer = None

        # For logging metrics
        self.run_id = 1
        self.metrics_file = 'scenario1_metrics.csv'
        self._init_metrics_file()

        # Start background thread to monitor clients' inactivity and restoration
        self.monitor_thread = hub.spawn(self._client_monitor)

    def _init_metrics_file(self):
        if not os.path.exists(self.metrics_file):
            with open(self.metrics_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'runID', 'detected', 'blocked', 'disconnected_clients',
                    'rerouted_clients', 'restored_clients', 'mitigation_latency_s'
                ])

    def _log_metrics(self, mitigation_latency=0.0):
        with open(self.metrics_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                self.run_id,
                self.detected,
                self.blocked,
                list(self.disconnected_clients),
                list(self.rerouted_clients),
                list(self.restored_clients),
                round(mitigation_latency, 2)
            ])

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.datapath = ev.msg.datapath
        self.logger.info(f"Switch connected with datapath id {self.datapath.id}")
        self._install_table_miss_flow()

    def _install_table_miss_flow(self):
        parser = self.datapath.ofproto_parser
        ofproto = self.datapath.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=self.datapath,
            priority=0,
            match=match,
            instructions=inst)
        self.datapath.send_msg(mod)
        self.logger.info("Installed table-miss flow")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # This simulates monitoring ICMP packets and detecting attacks
        msg = ev.msg
        pkt = msg.data

        # Fake packet parsing for brevity: assume packet_in events include client IP info
        # Here, you would parse Ethernet/IP/ICMP headers to extract source/dest IPs

        # Simulate client activity update (using source IP as key)
        # For demonstration, assume client IP from some header parsing
        client_ip = self._extract_client_ip(pkt)
        now = time.time()

        if client_ip in self.ATTACKED_AP_CLIENTS:
            self.last_activity[client_ip] = now

        # Simulate attack detection probabilistically when attack duration reached
        if not self.detected:
            self.detected = self._simulate_attack_detection()
            if self.detected:
                self.logger.info(f"Attack detected on run {self.run_id}")
                self.last_attack_time = now
                # Decide to block attacker probabilistically
                if random.random() < self.BLOCKING_SUCCESS_RATE:
                    self.blocked = True
                    self.logger.info(f"Blocking attacker IP {self.ATTACKER_IP}")
                    self._install_block_flow()
                    # No client disconnections expected if blocked early
                    self._log_metrics(mitigation_latency=0)
                    self._start_new_run()
                else:
                    self.blocked = False
                    self.logger.info("Attacker blocking failed, clients will be disconnected")
            else:
                self.logger.info("Attack not detected this run (false negative)")

    def _extract_client_ip(self, pkt):
        # Dummy extraction — in real, parse pkt to get src IP
        # For demo, randomly pick a client from attacked clients simulating packet from them
        return random.choice(self.ATTACKED_AP_CLIENTS)

    def _simulate_attack_detection(self):
        # Simulate 90% detection probability if attack active
        return random.random() < self.DETECTION_PROBABILITY

    def _install_block_flow(self):
        parser = self.datapath.ofproto_parser
        ofproto = self.datapath.ofproto

        match = parser.OFPMatch(ipv4_src=self.ATTACKER_IP, eth_type=0x0800)
        actions = []  # drop attacker packets
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=self.datapath,
            priority=100,
            match=match,
            instructions=inst,
            command=ofproto.OFPFC_ADD)
        self.datapath.send_msg(mod)
        self.logger.info("Installed attacker block flow")

    def _client_monitor(self):
        while True:
            now = time.time()
            disconnected = set()
            for client in self.ATTACKED_AP_CLIENTS:
                last_time = self.last_activity.get(client, 0)
                if now - last_time > self.CLIENT_DISCONNECT_TIMEOUT:
                    if client not in self.disconnected_clients:
                        self.logger.info(f"Client {client} disconnected due to inactivity")
                        disconnected.add(client)

            if disconnected:
                self.disconnected_clients.update(disconnected)
                self._reroute_clients(disconnected)
                self.last_attack_time = now  # reset restoration timer

            # Check if we can restore clients after RESTORATION_TRIGGER_TIME of no attacks
            if (self.detected or self.disconnected_clients) and (now - self.last_attack_time > self.RESTORATION_TRIGGER_TIME):
                self._restore_clients()

            hub.sleep(1)

    def _reroute_clients(self, clients):
        for client in clients:
            if client not in self.rerouted_clients:
                out_port = self.REROUTE_MAP.get(client)
                if out_port:
                    self._install_reroute_flow(client, out_port)
                    self.rerouted_clients.add(client)
                    self.logger.info(f"Rerouted client {client} to port {out_port}")

    def _install_reroute_flow(self, client_ip, out_port):
        parser = self.datapath.ofproto_parser
        ofproto = self.datapath.ofproto

        match = parser.OFPMatch(ipv4_dst=client_ip, eth_type=0x0800)
        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=self.datapath,
            priority=90,
            match=match,
            instructions=inst,
            command=ofproto.OFPFC_ADD)
        self.datapath.send_msg(mod)
        self.logger.info(f"Installed reroute flow for {client_ip} to output port {out_port}")

    def _restore_clients(self):
        if not self.rerouted_clients:
            return
        self.logger.info(f"Restoring clients: {self.rerouted_clients}")
        # Remove reroute flows by installing lower priority or deleting flows (simplified here)
        parser = self.datapath.ofproto_parser
        ofproto = self.datapath.ofproto

        for client_ip in list(self.rerouted_clients):
            match = parser.OFPMatch(ipv4_dst=client_ip, eth_type=0x0800)
            mod = parser.OFPFlowMod(
                datapath=self.datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match)
            self.datapath.send_msg(mod)
            self.logger.info(f"Removed reroute flow for {client_ip}")

        self.restored_clients.update(self.rerouted_clients)
        self.rerouted_clients.clear()
        self.disconnected_clients.clear()
        self.detected = False
        self.blocked = False

        mitigation_latency = time.time() - self.last_attack_time
        self._log_metrics(mitigation_latency=mitigation_latency)
        self.logger.info(f"Clients restored after {mitigation_latency:.2f} seconds")

        self._start_new_run()

    def _start_new_run(self):
        self.run_id += 1
        self.detected = False
        self.blocked = False
        self.disconnected_clients.clear()
        self.rerouted_clients.clear()
        self.restored_clients.clear()
        self.last_activity.clear()
        self.last_attack_time = 0
        self.logger.info(f"Starting run {self.run_id}")

