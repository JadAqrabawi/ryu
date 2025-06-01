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
    CLIENT_DISCONNECT_TIMEOUT = 2  # seconds no traffic
    ATTACK_DURATION = 30  # seconds
    RESTORATION_TRIGGER_TIME = 10  # seconds no attack or disconnection
    NUM_RUNS_PER_SCENARIO = 20

    # Scenario 1 Clients and reroute mapping
    clients_ap1 = ['sta1', 'sta2', 'sta3', 'sta4']
    clients_ap1_ips = ['10.0.1.1', '10.0.1.2', '10.0.1.3', '10.0.1.4']
    reroute_targets = {
        'sta1': 'AP2',
        'sta2': 'AP2',
        'sta3': 'AP3',
        'sta4': 'AP3'
    }

    clients_ap2_ips = ['10.0.2.1', '10.0.2.2', '10.0.2.3']
    clients_ap3_ips = ['10.0.3.1', '10.0.3.2', '10.0.3.3']

    def __init__(self, *args, **kwargs):
        super(SDNDeauthMitigation, self).__init__(*args, **kwargs)
        random.seed(42)  # reproducibility

        self.run_id = 1
        self.attack_detected = False
        self.attack_blocked = False
        self.attack_start_time = None
        self.last_attack_frame_time = None
        self.client_last_seen = {}  # ip -> last pkt timestamp
        self.disconnected_clients = set()
        self.rerouted_clients = set()
        self.restored_clients = set()
        self.metrics_file = 'scenario1_metrics.csv'

        self.datapath = None
        self.monitor_thread = None

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

        if self.monitor_thread is None:
            self.monitor_thread = hub.spawn(self._monitor_clients)

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
        self.logger.info("Installed table-miss flow")

    def _start_run(self):
        self.logger.info(f"=== Starting run {self.run_id} ===")
        self.attack_detected = False
        self.attack_blocked = False
        self.attack_start_time = time.time()
        self.last_attack_frame_time = self.attack_start_time
        self.client_last_seen.clear()
        self.disconnected_clients.clear()
        self.rerouted_clients.clear()
        self.restored_clients.clear()

        self.attack_detected = (random.random() < self.DETECTION_PROBABILITY)
        self.logger.info(f"Attack detected? {self.attack_detected}")

        if self.attack_detected:
            self.attack_blocked = (random.random() < self.BLOCKING_SUCCESS_RATE)
            self.logger.info(f"Attacker blocked? {self.attack_blocked}")

        if not self.attack_detected or not self.attack_blocked:
            # Simulate full disconnection of AP1 clients
            for ip in self.clients_ap1_ips:
                self.client_last_seen[ip] = 0  # last seen far in past
            self.disconnected_clients.update(self.clients_ap1_ips)
            self.logger.info("All AP1 clients forcibly disconnected due to attack")
            self._reroute_clients(self.disconnected_clients)
        else:
            self.logger.info("Attack mitigated early - no disconnections or reroute")

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
                target_ap = self.reroute_targets[client]
                self.logger.info(f"Client {client} rerouted to {target_ap}")
                self._install_reroute_flow(self.datapath, ip, target_ap)

    def _install_reroute_flow(self, datapath, client_ip, target_ap):
        # Here you must map target_ap to switch port number in your topology
        # This is a simulation/logging placeholder
        self.logger.info(f"Installing reroute flow for {client_ip} to {target_ap}")
        # You would build and send a flow mod to redirect traffic in real setup

    def _restore_clients(self):
        if not self.rerouted_clients:
            return
        self.logger.info(f"Restoring clients: {self.rerouted_clients}")
        self.restored_clients.update(self.rerouted_clients)
        self.rerouted_clients.clear()
        self.disconnected_clients.clear()
        self.logger.info("Clients restored to original APs")

    def _end_run(self):
        now = time.time()
        mitigation_latency = 0 if not self.attack_detected else (now - self.attack_start_time)
        packet_loss = 100 if not self.attack_blocked else random.uniform(3, 7)
        throughput = 0 if not self.attack_blocked else random.uniform(8, 12)

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

        self.logger.info(f"Run {self.run_id} finished, scheduling next run in 5 seconds")
        self.run_id += 1
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
        return None

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return  # ignore LLDP

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            self.client_last_seen[src_ip] = time.time()
            self.logger.debug(f"PacketIn: traffic from {src_ip}")

        dpid = datapath.id
        in_port = msg.match['in_port']
        dst = eth.dst
        src = eth.src

        self.mac_to_port = getattr(self, 'mac_to_port', {})
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

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
        self.logger.info(f"Flow added: priority={priority} match={match} actions={actions}")

    def _monitor_clients(self):
        while True:
            now = time.time()
            for ip in self.clients_ap1_ips:
                last_seen = self.client_last_seen.get(ip, 0)
                if (now - last_seen) > self.CLIENT_DISCONNECT_TIMEOUT:
                    if ip not in self.disconnected_clients:
                        self.logger.info(f"Client {ip} considered disconnected due to inactivity")
                        self.disconnected_clients.add(ip)
                        self._reroute_clients({ip})

            # Restoration trigger: no recent attack frames
            if self.attack_detected and self.last_attack_frame_time:
                if (now - self.last_attack_frame_time) > self.RESTORATION_TRIGGER_TIME:
                    self._restore_clients()
                    self.attack_detected = False
                    self.attack_blocked = False

            hub.sleep(1)
