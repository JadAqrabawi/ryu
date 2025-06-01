#!/usr/bin/env python3
#
# MitigationController – SDN wireless attack detector / responder
#

import os
import time
import csv
import threading
import collections

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet
from ryu.ofproto import ofproto_v1_3


# ───────── Paths ─────────
RESULTS_DIR  = os.getenv("SDN_RESULTS_DIR",
                         "/home/ethical/sdn_project/scenario1/results")
RESULTS_FILE = f"{RESULTS_DIR}/scenario1_sdn.csv"

# ───────── Detection thresholds ─────────
PORT_DOWN_ALARM        = True          # raise alarm on AP port down
WINDOW_SEC             = 5             # sliding window length
SILENT_CLIENTS_THRESH  = 3             # quiet clients in window → alarm

SILENT_TIMEOUT_SEC     = 2             # one client quiet this long
SILENT_BACKOFF_SEC     = 8             # pause before re-checking same mac
RESTORE_TIMEOUT_SEC    = 10            # calm period → clear alarm
# ─────────────────────────────────────────


class MitigationController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # runtime maps
        self.mac_to_port   = {}           # {dpid: {mac: port}}
        self.last_seen     = {}           # {mac: ts}
        self.rerouted      = set()        # handled clients
        self.backoff_until = {}           # mac → next eligible ts
        self.silent_hits   = collections.deque()  # (ts, mac)

        self.alarm_ts      = None
        self.attacker_mac  = None         # first MAC we block
        self.attacker_dp   = None         # datapath holding the drop rule

        # CSV preparation
        os.makedirs(RESULTS_DIR, exist_ok=True)
        if not os.path.exists(RESULTS_FILE):
            with open(RESULTS_FILE, "w", newline="") as f:
                csv.writer(f).writerow(
                    ["timestamp", "event", "mac", "dpid", "detail"]
                )

        threading.Thread(target=self._watch_clients, daemon=True).start()

    # ───────── Switch hello ─────────
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_ready(self, ev):
        dpid = ev.msg.datapath.id
        self.mac_to_port[dpid] = {}
        self.logger.info("Switch joined: dpid=%s", dpid)

    # ───────── Packet-in ─────────
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg     = ev.msg
        dp      = msg.datapath
        dpid    = dp.id
        in_port = msg.match['in_port']
        parser  = dp.ofproto_parser
        ofp     = dp.ofproto

        eth = packet.Packet(msg.data).get_protocol(ethernet.ethernet)
        if eth is None:
            return
        src, dst = eth.src, eth.dst

        # learning switch
        self.mac_to_port[dpid][src] = in_port
        out_port = self.mac_to_port[dpid].get(dst, ofp.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=0,
                                        in_port=in_port, actions=actions,
                                        data=msg.data))

        now = time.time()
        self.last_seen[src] = now

        # if alarm active, block only the very first new MAC
        if self.alarm_ts and self.attacker_mac is None:
            self.attacker_mac = src
            self.attacker_dp  = dp
            self._block(dp, src)
            return

        # if alarm not active, update silent-burst detector
        self._record_silent_hits(now)

    # ───────── Port status ─────────
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status(self, ev):
        if not PORT_DOWN_ALARM:
            return
        msg  = ev.msg
        dp   = msg.datapath
        ofp  = dp.ofproto
        if msg.reason == ofp.OFPPR_DELETE:
            self._raise_alarm(f"port_down dpid={dp.id} port={msg.desc.port_no}")

    # ───────── Background monitor ─────────
    def _watch_clients(self):
        while True:
            time.sleep(1)
            now = time.time()

            if self.alarm_ts:
                # clear alarm after stable period
                if now - self.alarm_ts >= RESTORE_TIMEOUT_SEC:
                    self._clear_alarm()
                continue

            # count fresh silent clients
            hits_now = 0
            for mac, last in list(self.last_seen.items()):
                if now - last >= SILENT_TIMEOUT_SEC:
                    hits_now += 1
                    self.silent_hits.append((now, mac))
                    # push next check far enough to avoid double-count
                    self.last_seen[mac] = now + 60

            self._trim_window(now)
            if len(self.silent_hits) >= SILENT_CLIENTS_THRESH:
                self._raise_alarm("silent_clients_burst")

    # ───────── helpers ─────────
    def _trim_window(self, now):
        while self.silent_hits and now - self.silent_hits[0][0] > WINDOW_SEC:
            self.silent_hits.popleft()

    def _record_silent_hits(self, now):
        self._trim_window(now)  # keeps window fresh even without new hits

    def _raise_alarm(self, detail):
        self.alarm_ts = time.time()
        self.logger.warning("Attack detected: %s", detail)
        self._csv("attack_detected", "-", "-", detail)

    def _block(self, dp, mac):
        parser, ofp = dp.ofproto_parser, dp.ofproto
        match  = parser.OFPMatch(eth_src=mac)
        inst   = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [])]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=100,
                                      match=match, instructions=inst))
        self.logger.info("Blocking attacker %s", mac)
        self._csv("block", mac, dp.id, "")

    def _clear_alarm(self):
        # remove drop rule if installed
        if self.attacker_mac and self.attacker_dp:
            parser = self.attacker_dp.ofproto_parser
            ofp    = self.attacker_dp.ofproto
            match  = parser.OFPMatch(eth_src=self.attacker_mac)
            self.attacker_dp.send_msg(parser.OFPFlowMod(
                datapath=self.attacker_dp,
                command=ofp.OFPFC_DELETE,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                priority=100,
                match=match))
        # reset state
        self.logger.info("Restoration done")
        self._csv("restore", "-", "-", "")
        self.alarm_ts       = None
        self.attacker_mac   = None
        self.attacker_dp    = None
        self.silent_hits.clear()
        self.backoff_until.clear()
        self.rerouted.clear()

    def _csv(self, event, mac, dpid, detail):
        with open(RESULTS_FILE, "a", newline="") as f:
            csv.writer(f).writerow([
                time.strftime("%Y-%m-%d %H:%M:%S"),
                event, mac, dpid, detail
            ])
