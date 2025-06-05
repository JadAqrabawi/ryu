from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
import time
import csv

# IEEE 802.11 frame types
DEAUTH_TYPE = 0x00C0
DISASSOC_TYPE = 0x00A0

class SDNWiFiDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(SDNWiFiDefense, self).__init__(*args, **kwargs)
        self.deauth_threshold = 50  # 50 frames/sec
        self.frame_counts = {}
        self.attack_detected = False
        self.mitigation_active = False
        
        # Metrics logging
        self.metrics_file = open("wifi_metrics.csv", "w")
        self.metrics_writer = csv.writer(self.metrics_file)
        self.metrics_writer.writerow([
            "runID", "detected", "blocked", "disconnected_clients",
            "rerouted", "restored", "packet_loss", "mitigation_latency", "throughput"
        ])
        self.run_id = 0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath, buffer_id=buffer_id,
                priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority,
                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        # Detect de-authentication or disassociation frames
        if eth.ethertype == DEAUTH_TYPE or eth.ethertype == DISASSOC_TYPE:
            src_mac = eth.src
            ap_id = msg.datapath.id
            
            # Update frame count
            if src_mac not in self.frame_counts:
                self.frame_counts[src_mac] = []
                
            self.frame_counts[src_mac].append(time.time())
            
            # Remove old entries (older than 1 second)
            self.frame_counts[src_mac] = [
                t for t in self.frame_counts[src_mac]
                if time.time() - t < 1.0
            ]
            
            # Check threshold
            if len(self.frame_counts[src_mac]) >= self.deauth_threshold:
                self.detect_attack(src_mac, ap_id)

    def detect_attack(self, attacker_mac, ap_id):
        if self.mitigation_active:
            return
            
        self.attack_detected = True
        self.mitigation_active = True
        start_time = time.time()
        
        # 1. Block attacker
        self.block_attacker(attacker_mac)
        
        # 2. Log metrics (assume 4 clients affected)
        mitigation_latency = time.time() - start_time
        self.log_metrics(4, mitigation_latency)
        
        # 3. Schedule restoration
        self.run_id += 1
        hub.spawn_after(30, self.restore_normal)

    def block_attacker(self, attacker_mac):
        for dp in self.datapaths.values():
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_src=attacker_mac)
            actions = []  # Drop packets
            self.add_flow(dp, 100, match, actions)
        self.logger.info("Blocked attacker: %s", attacker_mac)

    def log_metrics(self, affected_clients, latency):
        # Placeholder values - in real implementation, collect from stats
        packet_loss = 0.5
        throughput = 50.0
        
        self.metrics_writer.writerow([
            self.run_id, 
            1,  # detected
            1,  # blocked
            affected_clients,
            affected_clients,  # rerouted
            affected_clients,  # restored
            f"{packet_loss:.2f}",
            f"{latency:.4f}",
            f"{throughput:.2f}"
        ])
        self.metrics_file.flush()

    def restore_normal(self):
        self.mitigation_active = False
        self.attack_detected = False
        self.frame_counts = {}
        self.logger.info("Restored normal operation")

if __name__ == '__main__':
    from ryu.cmd import manager
    manager.main()