"""
firewall_app.py  –  (Ryu) OpenFlow controller based on "simple switch 13"
Holds all firewall state and packet inspection logic.
"""

import json
import logging
import time
import struct
from collections import defaultdict
from enum import Enum
from collections import deque

from ryu.base import app_manager
from ryu.app.wsgi import WSGIApplication, rpc_public
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp, arp, ipv6, icmp
from ryu.ofproto import ofproto_v1_3


# Imported here so firewall_wsgi.py can reference it without a circular import
FIREWALL_INSTANCE = 'firewall_app'
WS_URL            = '/firewall/ws'

class CheckResult(Enum):
    # (level, msg_template, stat_key, extra_tag)
    ALLOWED           = ('allow', 'Packet allowed',              None,            'ALLOWED')
    IP_BLOCKED        = ('block', 'IP blocked: {src}',           'blocked',       'IP_BLOCK')
    IP_NOT_ALLOWLIST  = ('block', 'IP not in allowlist: {src}',  'blocked',       'IP_ALLOWLIST')
    PORT_BLOCKED      = ('block', '{proto} port {port} blocked', 'blocked',       'PORT_BLOCK')
    RATE_LIMITED      = ('block', 'Rate limit exceeded: {src}',  'rate_limited',  'RATE_LIMIT')
    ARP_SPOOF         = ('warn',  'ARP spoof: {src}',            'arp_spoof',     'ARP_SPOOF')
    XMAS_SCAN         = ('warn',  'Xmas scan from {src}',        'scan_detected', 'XMAS_SCAN')
    NULL_SCAN         = ('warn',  'NULL scan from {src}',        'scan_detected', 'NULL_SCAN')
    SYN_FIN           = ('warn',  'SYN+FIN from {src}',          'scan_detected', 'MALFORMED')
    SYN_RST           = ('warn',  'SYN+RST from {src}',          'scan_detected', 'MALFORMED')
    FIN_SCAN          = ('warn',  'FIN scan from {src}',         'scan_detected', 'MALFORMED')

    def __init__(self, level: str, msg_template: str, stat_key: str | None, extra_tag: str):
        self.level        = level
        self.msg_template = msg_template
        self.stat_key     = stat_key
        self.extra_tag    = extra_tag

    def resolve(self, **kwargs) -> str:
        """Render the message template with provided kwargs."""
        return self.msg_template.format(**kwargs)
    @property
    def is_blocked(self) -> bool:
        return self != CheckResult.ALLOWED

class FirewallApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS    = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(FirewallApp, self).__init__(*args, **kwargs)

        # actual routing information
        self.mac_to_port = defaultdict(dict)
        # ip  → mac  (ARP spoof detection)
        self.arp_table     = {}

        self.datapaths: dict[int, any] = {}


        # set of IPv4 src ips to block
        self.blocked_ips   = set()
        # set of (dst_port, proto_num) tuples to block
        self.blocked_ports = set()
        # if non-empty → default-deny for unlisted IPs
        self.allowed_ips   = set()
        # ip → deque of packet timestamps within the current rate window
        self.rate_tracker: dict[str, deque] = {}
        # max packets per window
        self.rate_limit    = 1000
        # window size in seconds
        self.rate_window   = 1.0

        # ── Event log (capped at 200) ────────────────────────────────────────
        self.event_log = []

        # ── Counters ─────────────────────────────────────────────────────────
        self.stats = {
            'allowed':       0,
            'blocked':       0,
            'arp_spoof':     0,
            'rate_limited':  0,
            'scan_detected': 0,
        }

        # ── Register the WSGI controller and wire routes ─────────────────────
        # Import here to avoid a top-level circular import
        from firewall_wsgi import FirewallWSGI

        wsgi = kwargs['wsgi']
        wsgi.register(FirewallWSGI, {FIREWALL_INSTANCE: self})
        self._ws_manager = wsgi.websocketmanager

        name   = FirewallWSGI
        mapper = wsgi.mapper

        mapper.connect('/',
            controller=name, action='index',
            conditions=dict(method=['GET']))
        mapper.connect('/firewall/rules',
            controller=name, action='get_rules',
            conditions=dict(method=['GET']))
        mapper.connect('/firewall/rules/ip/{ip}',
            controller=name, action='add_blocked_ip',
            conditions=dict(method=['POST']))
        mapper.connect('/firewall/rules/ip/{ip}',
            controller=name, action='del_blocked_ip',
            conditions=dict(method=['DELETE']))
        mapper.connect('/firewall/rules/port/{port}/{proto}',
            controller=name, action='add_blocked_port',
            conditions=dict(method=['POST']))
        mapper.connect('/firewall/rules/port/{port}/{proto}',
            controller=name, action='del_blocked_port',
            conditions=dict(method=['DELETE']))
        mapper.connect('/firewall/rules/ratelimit',
            controller=name, action='set_rate_limit',
            conditions=dict(method=['POST']))
        mapper.connect('/firewall/log',
            controller=name, action='get_log',
            conditions=dict(method=['GET']))
        mapper.connect('/firewall/stats',
            controller=name, action='get_stats',
            conditions=dict(method=['GET']))

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _log(self, level, msg, src=None, dst=None, extra=None):
        """Append to event log and broadcast to all WebSocket clients."""
        entry = {
            'ts':    time.strftime('%H:%M:%S'),
            'level': level,          # block | allow | warn | info
            'msg':   msg,
            'src':   src   or '',
            'dst':   dst   or '',
            'extra': extra or '',
        }
        self.event_log.append(entry)
        if len(self.event_log) > 200:
            self.event_log.pop(0)

        self.logger.info('[%s] %s', level.upper(), msg)
        self._ws_manager.broadcast(json.dumps({'type': 'event', 'data': entry}))
        self._ws_manager.broadcast(json.dumps({'type': 'stats', 'data': dict(self.stats)}))

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0, buffer_id=None):
        """
            Install the actual rule to save the 'flow' for next time
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        kw = dict(
            datapath=datapath, priority=priority,
            idle_timeout=idle_timeout, hard_timeout=hard_timeout,
            match=match, instructions=inst)
        if buffer_id is not None:
            kw['buffer_id'] = buffer_id
        mod = parser.OFPFlowMod(**kw)
        datapath.send_msg(mod)

    def _flush_flows_for_ip(self, ip_src):
        """
            Delete any active ip flow for the specified address source (used to block a previously allowed address)
        """
        self._log('info', f'flushing flows for {ip_src}, datapaths: {list(self.datapaths.keys())}')
        for datapath in self.datapaths.values():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match_src = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)                                               # flush flows where blocked IP is source
            match_dst = parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip_src)                                               # flush flows where blocked IP is destination

            for match in [match_src, match_dst]:
                mod = parser.OFPFlowMod(
                    datapath=datapath,
                    command=ofproto.OFPFC_DELETE,                                                                       # delete current flows
                    match=match,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY)
                datapath.send_msg(mod)

    def _check_ip_block(self, datapath, ip_src, ip_dst) -> CheckResult:
        """
            Check if the source of the ip(v4) packet:
                - is in blocked_ips -> return CheckResult.IP_BLOCKED
                - is not in allowed_ips (if not empty) -> return an IP_NOT_ALLOWLIST error
        """
        if ip_src in self.blocked_ips:                                                                                  # blacklist only on src ip (still enough to kill all the channels to/from it)
            return CheckResult.IP_BLOCKED

        if self.allowed_ips and ip_src not in self.allowed_ips:                                                         # inverse logic (whitelist) handler
            return CheckResult.IP_NOT_ALLOWLIST

        return CheckResult.ALLOWED

    def _check_ip_rate_limit(self, datapath, ip_src) -> CheckResult:
        """
            Check for time-rate ip packets from a same source
            Keep a timestamp dequeue 'tracker' associated to each source and check the number of timestamps in the time window 'rate_window'
        """
        now = time.time()
        self.rate_tracker.setdefault(ip_src, deque())                                                                   # using optimized deque
        tracker = self.rate_tracker[ip_src]                                                                             # get the associated deque object

        while tracker and now - tracker[0] >= self.rate_window:                                                         # keep the sliding window to the fixed TIME size
            tracker.popleft()

        if len(tracker) >= self.rate_limit:                                                                             # check if in the fixed TIME size the number of packets (their timestamps) is greater than allowed
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
            self.add_flow(datapath, priority=200, match=match, actions=[], idle_timeout=10)                             # expire after 10s to allow recovery
            return CheckResult.RATE_LIMITED

        tracker.append(now)                                                                                             # add a timestamp as the rate is small enough
        return CheckResult.ALLOWED

    def _check_port_block(self, datapath, proto_num, dst_port, ip_src) -> CheckResult:
        """
            Check if the port is defined as blocked in blocked_ports.
            If it is in blocked_ports -> add the rule to ignore other packets at the exact (port, protocol) combination and return a PORT_BLOCKED error

        """
        if (dst_port, proto_num) in self.blocked_ports:
            return CheckResult.PORT_BLOCKED
        else:
            return CheckResult.ALLOWED

    def _check_tcp_flags(self, datapath, tcp_pkt, ip_src) -> CheckResult:
        """
            Check for invalid TCP flags configurations
            return the specific flag error as CheckResult value or ALLOWED for valid configurations
        """
        flags_bits = tcp_pkt.bits
        # bit:  7    6    5    4    3    2    1    0
        # flag: CWR  ECE  URG  ACK  PSH  RST  SYN  FIN
        #                 0x20 0x10 0x08 0x04 0x02 0x01
        FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20                                               # saving position of each flag to filter "bits" value

        result = CheckResult.ALLOWED

        if flags_bits & (FIN | PSH | URG) == (FIN | PSH | URG):                                                         # all 3 flags up -> not valid configuration
            result = CheckResult.XMAS_SCAN                                                                              # XMAS cause they're "lit up"
        if flags_bits == 0:                                                                                             # no flag up -> not valid configuration
            result = CheckResult.NULL_SCAN                                                                              # NULL cause it's a null byte
        if flags_bits & (SYN | FIN) == (SYN | FIN):                                                                     # SYN and FIN both active ->  not valid configuration
            result = CheckResult.SYN_FIN
        if flags_bits & (SYN | RST) == (SYN | RST):                                                                     # like SYN and FIN
            result = CheckResult.SYN_RST
        if flags_bits == FIN:
            result = CheckResult.FIN_SCAN                                                                               # probably a scan

        return result

    def _check_arp_spoof(self, datapath, src_mac, ip_src) -> CheckResult:
        """
            Check for a new mac address associated to a previously associated ip
            return ARP_SPOOF if the ip-mac combination is not as expected
            return ALLOWED if a new ip-mac combination is found (and store it in 'arp_table')
        """
        if ip_src not in self.arp_table:
            self.arp_table[ip_src] = src_mac                                                                            # learn a new mac address
            return CheckResult.ALLOWED
        elif self.arp_table[ip_src] != src_mac:                                                                         # signal the changing mac address
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0806, arp_spa=ip_src)                                                    # drop ARP from the current ipv4 address
            self.add_flow(datapath, priority=200, match=match, actions=[], idle_timeout=10)                             # drop them (quick recovery)
            return CheckResult.ARP_SPOOF
        else:
            return CheckResult.ALLOWED

    def _apply_result(self, result: CheckResult, src, dst='', **kwargs):
        """Update stats and log based on CheckResult."""
        if result.stat_key:
            self.stats[result.stat_key] += 1

        self._log(
            result.level,
            result.resolve(src=src, dst=dst, **kwargs),
            src=src, dst=dst,
            extra=result.extra_tag
        )


    def icmp_packet_handler(self, msg, icmp_pkt) -> CheckResult:
        """
            TODO: GOON HERE @.@
        """
        # icmp packet:
        # {
        #   'type': 8,
        #   'code': 0,
        #   'csum': 2541,
        #   'data': echo(
        #     id=22013,
        #     seq=1,
        #     data=b'0A\xb4i\x00\x00\x00\x00\xef\x96\x05\x00\x00\x00\x00\x00'
        #          b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'
        #          b' !"#$%&\'()*+,-./01234567'
        #   )
        # }

        return CheckResult.ALLOWED

    def udp_packet_handler(self, datapath, ip_src, ip_dst, udp_pkt) -> CheckResult:
        """
            No specific check for now, only blocked port usage
        """
        result = self._check_port_block(datapath, 17, udp_pkt.dst_port, ip_src)
        return result

    def tcp_packet_handler(self, datapath, ip_src, ip_dst, tcp_pkt) -> CheckResult:
        """
            Check for blocked port usage and TCP flags misusage
        """
        checks = [
            lambda: self._check_port_block(datapath, 6, tcp_pkt.dst_port, ip_src),
            lambda: self._check_tcp_flags(datapath, tcp_pkt, ip_src),
        ]
        for check in checks:                                                                                            # python magic, for loop to run 2 functions
            result = check()
            if result != CheckResult.ALLOWED:
                return result
        return CheckResult.ALLOWED

    def ipv4_packet_handler(self, msg, ip_pkt) -> CheckResult:
        # example dump got from icmp packet
        # {
        #   'protocols': ['ethernet', 'ipv4', 'icmp'],
        #   'eth': {
        #     'dst':       'ce:2a:19:a0:b0:00',
        #     'src':       '96:31:b6:f6:8e:f4',
        #     'ethertype': 2048
        #   },
        #   'ip': {
        #     'version':       4,
        #     'header_length': 5,
        #     'tos':           0,
        #     'total_length':  84,
        #     'identification': 1717,
        #     'flags':         2,
        #     'offset':        0,
        #     'ttl':           64,
        #     'proto':         1,
        #     'csum':          8178,
        #     'src':           '10.0.0.1',
        #     'dst':           '10.0.0.2',
        #     'option':        None
        #   }
        # }
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        ip_src = ip_pkt.src
        ip_dst = ip_pkt.dst
        result = CheckResult.ALLOWED

        # IP-packet level checks:
        # - blocked addresses (static blacklist)
        # - packet rate limit
        # (using lambda expressions to avoid if-else tree)
        checks = [
            lambda: self._check_ip_block(datapath, ip_src, ip_dst),
            lambda: self._check_ip_rate_limit(datapath, ip_src),
        ]

        for check in checks:
            result = check()
            if result != CheckResult.ALLOWED:
                return result

        # checks divided into multiple helper functions to be more readable
        if ip_pkt.proto == 1:                                                                                           # ICMP protocol -> IP packet>protocol field = 1
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            result = self.icmp_packet_handler(msg, icmp_pkt)
        elif ip_pkt.proto == 6:                                                                                         # TCP protocol -> IP packet>protocol field = 6
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            result = self.tcp_packet_handler(datapath, ip_src, ip_dst, tcp_pkt)
        elif ip_pkt.proto == 17:                                                                                        # UDP protocol -> IP packet>protocol field = 17
            udp_pkt = pkt.get_protocol(udp.udp)
            result = self.udp_packet_handler(datapath, ip_src, ip_dst, udp_pkt)
        else:                                                                                                           # other packets are free to be transmitted (not inspected)
            result = CheckResult.ALLOWED
        return result

    def arp_packet_handler(self, msg, arp_pkt) -> CheckResult:
        """
            Check only for ARP spoof for now
            return value depend only the function _check_arp_spoof
        """
        # {
        #   'protocols': ['ethernet', 'arp'],
        #   'eth': {
        #     'dst':       'ff:ff:ff:ff:ff:ff',
        #     'src':       '96:31:b6:f6:8e:f4',
        #     'ethertype': 2054
        #   },
        #   'arp': {
        #     'hwtype':  1,
        #     'proto':   2048,
        #     'hlen':    6,
        #     'plen':    4,
        #     'opcode':  1,
        #     'src_mac': '96:31:b6:f6:8e:f4',
        #     'src_ip':  '10.0.0.1',
        #     'dst_mac': '00:00:00:00:00:00',
        #     'dst_ip':  '10.0.0.2'
        #   },
        # }
        result = self._check_arp_spoof(msg.datapath, arp_pkt.src_mac, arp_pkt.src_ip)
        return result

    # ── Handshake handler ────────────────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_handshake_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath

        # install only a table-miss flow entry (rest of the logic here in the controller)
        match = parser.OFPMatch()  # match everything
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 65535)]
        self.arp_table.clear()  # avoid old data issues
        self.add_flow(datapath, 0, match, actions)  # priority 0, ignore if there's something else

        match_ip = parser.OFPMatch(eth_type=0x0800)
        self.add_flow(datapath, priority=300, match=match_ip, actions=actions)                                          # IPv4 → ALWAYS to controller, no flow ever installed


    # ── Packet-in handler ────────────────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if not ev.msg or not ev.msg.data:
            self.logger.warn(f"packet with no msg or data: even context: {ev}")
            return
        elif ev.msg.msg_len < ev.msg.total_len:                                                                         # base ignored case
            self.logger.warn(f"packet truncated: only {ev.msg.msg_len} of {ev.msg.total_len} bytes")
            return

        msg = ev.msg                                                                                                    # data extraction from ev object
        datapath = msg.datapath
        ofproto = datapath.ofproto
        dpid = format(datapath.id, "d").zfill(16)
        parser = datapath.ofproto_parser

        # ------ filtering area ------
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        result = CheckResult.ALLOWED                                                                                    # sanity check section (initially set as ALLOWED)
        self.logger.debug(f"packet in with ethernet protcol: {eth_pkt.ethertype}")

        if eth_pkt.ethertype == 2048:                                                                                   # IPv4 ethernet frame: 0x0800 -> 2048
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            result = self.ipv4_packet_handler(msg, ip_pkt)
        elif eth_pkt.ethertype == 2054:                                                                                 # ARP ethernet frame: 0x806 -> 2054
            arp_pkt = pkt.get_protocol(arp.arp)
            result = self.arp_packet_handler(msg, arp_pkt)
        elif eth_pkt.ethertype == 34525:                                                                                # IPv6 ethernet frame: 0x86DD -> 34525
            # ipv6_pkt = pkt.get_protocol(ipv6.ipv6)                                                                    # analysis of IPv6 packets is not implemented
            self.logger.warn(f"ipv6 packet ignored")
            return
        elif eth_pkt.ethertype == 35020:                                                                                # DataLink-Layer-Discovery (periodic, multicast) frame: 0x88CC -> 35020
            self.logger.warn(f"DLLD packet ignored")                                                                    # analysis of DLLD is not implemented
            return
        else:
            self.logger.warn(f"Ethertype {eth_pkt.ethertype} ignored")
            return

        # ------ filter outcome application area ------

        eth_dst = getattr(eth_pkt, 'dst', None)
        eth_src = getattr(eth_pkt, 'src', None)
        in_port = msg.match['in_port']
        out_port = None
        self.mac_to_port[dpid][eth_src] = in_port                                                                       # learn MAC (store the combo (eth_src, in_port) to the specific datapath id)

        if result != CheckResult.ALLOWED:                                                                               # (single) exit point for blocked packets
            log_proto = ''
            log_port = 0
            if eth_pkt.ethertype != 2048:
                log_src = eth_src
                log_dst = eth_dst
            else:
                ip_pkt = pkt.get_protocol(ipv4.ipv4)                                                                    # refetch data from ip_pkt, less efficient but more readable
                ip_src = getattr(ip_pkt, 'src', None)
                ip_dst = getattr(ip_pkt, 'dst', None)
                log_src = ip_src
                log_dst = ip_dst
                if result == CheckResult.PORT_BLOCKED:
                    if ip_pkt.proto == 6:
                        log_port = pkt.get_protocol(tcp.tcp).dst_port                                                   # too much python-like but it works
                        log_proto = 'TCP'
                    elif ip_pkt.proto == 17:
                        log_port = pkt.get_protocol(udp.udp).dst_port
                        log_proto = 'UDP'
                    else:
                        log_proto = f'{ip_pkt.proto}'
            self._apply_result(result, src=log_src, dst=log_dst, proto=log_proto, port=log_port)
        else:                                                                                                           # routing for allowed packets
            if eth_dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][eth_dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            if (eth_pkt.ethertype != 0x0800) and (out_port != ofproto.OFPP_FLOOD):                                      # check if it's a known path (and not an IPV4 packet)
                match = parser.OFPMatch(in_port=in_port, eth_dst=eth_dst, eth_src=eth_src)                              # install the new flow
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, priority=1, match=match, actions=actions, buffer_id=msg.buffer_id, idle_timeout=0, hard_timeout=0)  # specify the buffer in which this message is stored in the switch
                    return
                else:
                    self.add_flow(datapath, priority=1, match=match, actions=actions, buffer_id=None, idle_timeout=0, hard_timeout=0)           # flow-only rule

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:                                                                  # send back the entire message (no buffer == no copy in the switch)
                data = msg.data

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=data,
            )
            datapath.send_msg(out)                                                                                      # send the message with data and action of the current (inspected) packet



    # ── WebSocket RPC (callable from JS via JSON-RPC over WS) ───────────────

    @rpc_public
    def get_stats(self):
        return self.stats

    @rpc_public
    def get_log(self):
        return self.event_log[-50:]

    @rpc_public
    def get_rules(self):
        return {
            'blocked_ips':   list(self.blocked_ips),
            'blocked_ports': list(self.blocked_ports),
            'allowed_ips':   list(self.allowed_ips),
            'rate_limit':    self.rate_limit,
            'rate_window':   self.rate_window,
        }
