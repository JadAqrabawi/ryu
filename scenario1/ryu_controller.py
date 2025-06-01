import os
import csv
import time
import random
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, icmp

class DeauthDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Configurable parameters
    DETECTION_PROBABILITY = 0.90
    BLOCKING_SUCCESS_RATE = 0.80
    CLIENT_DISCONNECT_TIMEOUT = 5  # Increased timeout
    RESTORATION_TRIGGER_TIME = 15  # Increased restoration time
    ATTACKED_AP_ID = 1
    ATTACKER_IP = '10.0.1.100'
    ATTACK_START_DELAY = 5  # Seconds before attack detection starts

    # Reroute mapping
    AP_PORTS = {
        1: {
            'reroute_ports': {
                '10.0.1.1': 2,  # sta1 -> AP2
                '10.0.1.2': 2,  # sta2 -> AP2
                '10.0.1.3': 3,  # sta3 -> AP3
                '10.0.1.4': 3,  # sta4 -> AP3
            }
        },
        2: {},
        3: {},
    }

    def __init__(self, *args, **kwargs):
        super(DeauthDefense, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.run_id = int(time.time())
        self.attack_detected = False
        self.attack_blocked = False
        self.detection_time = 0
        self.mitigation_start_time = 0

        # Client tracking
        self.disconnected_clients = set()
        self.rerouted_clients = set()
        self.restored_clients = set()
        self.current_disconnections = set()
        self.last_heard_time = {}
        self.last_disconnection_event = 0

        # Metrics
        self.packet_loss_pct = 0.0
        self.throughput_mbps = 0.0
        self.mitigation_latency = 0.0
        self.ping_results = {}

        # Logging setup
        self.csv_file = 'scenario1_metrics.csv'
        self._init_csv()
        
        # Start monitoring threads
        self.monitor_thread = hub.spawn(self._client_monitor)
        self.restoration_thread = hub.spawn(self._restoration_monitor)
        self.detection_thread = hub.spawn(self._detection_trigger)

    def _init_csv(self):
        if not os.path.exists(self.csv_file):
            with open(self.csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'runID', 'detected', 'blocked', 'disconnected_clients',
                    'rerouted_clients', 'restored_clients', 'mitigation_latency_s',
                    'packet_loss_%', 'throughput_Mbps'
                ])

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        self.logger.info(f"Switch connected: datapath id {datapath.id}")
        self._install_table_miss(datapath)

    def _install_table_miss(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        
        if ip_pkt:
            src_ip = ip_pkt.src
            self.last_heard_time[src_ip] = time.time()
            
            # Track ICMP echo requests
            if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                self.ping_results.setdefault(src_ip, {'sent': 0, 'received': 0})
                self.ping_results[src_ip]['sent'] += 1
                
            # Track ICMP echo replies
            if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REPLY:
                self.ping_results.setdefault(src_ip, {'sent': 0, 'received': 0})
                self.ping_results[src_ip]['received'] += 1

    def _detection_trigger(self):
        hub.sleep(self.ATTACK_START_DELAY)
        self._detection_logic()

    def _detection_logic(self):
        # Simulate probabilistic detection
        if random.random() < self.DETECTION_PROBABILITY:
            self.attack_detected = True
            self.detection_time = time.time()
            self.logger.info("Attack detected (90% probability hit)")
            
            # Simulate probabilistic blocking
            if random.random() < self.BLOCKING_SUCCESS_RATE:
                self.attack_blocked = True
                self._block_attacker()
        else:
            self.logger.info("Attack not detected (10% probability miss)")

    def _block_attacker(self):
        self.logger.info(f"Blocking attacker {self.ATTACKER_IP} (80% success)")
        for dp in self.datapaths.values():
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=self.ATTACKER_IP)
            mod = parser.OFPFlowMod(
                datapath=dp,
                command=dp.ofproto.OFPFC_ADD,
                priority=100,
                match=match,
                instructions=[]  # Drop packet
            )
            dp.send_msg(mod)

    def _client_monitor(self):
        while True:
            now = time.time()
            # Check clients in the attacked AP's subnet
            for client_ip in self.AP_PORTS[self.ATTACKED_AP_ID]['reroute_ports'].keys():
                last_heard = self.last_heard_time.get(client_ip, 0)
                if now - last_heard > self.CLIENT_DISCONNECT_TIMEOUT:
                    if client_ip not in self.disconnected_clients:
                        self.disconnected_clients.add(client_ip)
                        self.logger.info(f"Client {client_ip} disconnected")
                    if client_ip not in self.rerouted_clients and client_ip not in self.current_disconnections:
                        self.current_disconnections.add(client_ip)
                        self.last_disconnection_event = now
                        self.logger.info(f"Client {client_ip} added to current disconnections")
            
            # Reroute disconnected clients
            if self.current_disconnections:
                clients_to_reroute = set()
                for client in self.current_disconnections:
                    if client not in self.rerouted_clients:
                        clients_to_reroute.add(client)
                if clients_to_reroute:
                    self._reroute_clients(clients_to_reroute)
                    if not self.mitigation_start_time:
                        self.mitigation_start_time = time.time()
                        if self.detection_time:
                            self.mitigation_latency = self.mitigation_start_time - self.detection_time
            
            hub.sleep(0.5)  # Check twice per second

    def _reroute_clients(self, clients):
        for client in clients:
            if client not in self.rerouted_clients:
                out_port = self.AP_PORTS[self.ATTACKED_AP_ID]['reroute_ports'][client]
                self._install_reroute_flow(client, out_port)
                self.rerouted_clients.add(client)
                self.current_disconnections.remove(client)
                self.logger.info(f"Rerouted client {client} to backup AP port {out_port}")

    def _install_reroute_flow(self, client_ip, out_port):
        for dp in self.datapaths.values():
            ofproto = dp.ofproto
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=client_ip)
            actions = [parser.OFPActionOutput(out_port)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(
                datapath=dp,
                priority=90,
                match=match,
                instructions=inst
            )
            dp.send_msg(mod)

    def _restoration_monitor(self):
        while True:
            if not self.current_disconnections and self.rerouted_clients:
                if time.time() - self.last_disconnection_event >= self.RESTORATION_TRIGGER_TIME:
                    self._restore_clients()
            hub.sleep(1)

    def _restore_clients(self):
        self.logger.info("Restoring clients to original APs")
        for client in list(self.rerouted_clients):
            self._remove_reroute_flow(client)
            self.restored_clients.add(client)
            self.rerouted_clients.remove(client)
        self._log_results()

    def _remove_reroute_flow(self, client_ip):
        for dp in self.datapaths.values():
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=client_ip)
            mod = parser.OFPFlowMod(
                datapath=dp,
                command=dp.ofproto.OFPFC_DELETE,
                out_port=dp.ofproto.OFPP_ANY,
                out_group=dp.ofproto.OFPG_ANY,
                priority=90,
                match=match
            )
            dp.send_msg(mod)
            self.logger.info(f"Removed reroute flow for client {client_ip}")

    def _log_results(self):
        # Calculate metrics based on actual ping results
        total_sent = 0
        total_received = 0
        
        for client, results in self.ping_results.items():
            total_sent += results['sent']
            total_received += results['received']
        
        # Calculate packet loss
        if total_sent > 0:
            self.packet_loss_pct = 100.0 * (1 - total_received / total_sent)
        else:
            self.packet_loss_pct = 100.0
        
        # Estimate throughput based on packet activity
        active_clients = len([ip for ip, results in self.ping_results.items() if results['received'] > 0])
        self.throughput_mbps = active_clients * 1.5  # 1.5 Mbps per active client
        
        # Write results to CSV
        with open(self.csv_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                self.run_id,
                self.attack_detected,
                self.attack_blocked,
                list(self.disconnected_clients),
                list(self.rerouted_clients),
                list(self.restored_clients),
                round(self.mitigation_latency, 2),
                round(self.packet_loss_pct, 2),
                round(self.throughput_mbps, 2)
            ])
        self.logger.info("Results logged to CSV")