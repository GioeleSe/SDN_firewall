"""
firewall_app.py  –  Ryu OpenFlow application
Holds all firewall state, packet inspection logic, and RPC methods.
The WSGI/REST layer lives in firewall_wsgi.py.
"""

import json
import time

from ryu.app import simple_switch_13
from ryu.app.wsgi import WSGIApplication, rpc_public
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, arp
from ryu.ofproto import ofproto_v1_3

# Imported here so firewall_wsgi.py can reference it without a circular import
FIREWALL_INSTANCE = 'firewall_app'
WS_URL            = '/firewall/ws'


class FirewallApp(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS    = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(FirewallApp, self).__init__(*args, **kwargs)

        # ── Firewall state ───────────────────────────────────────────────────
        self.blocked_ips   = set()
        self.blocked_ports = set()   # TCP/UDP dst ports to drop
        self.allowed_ips   = set()   # if non-empty → default-deny for unlisted IPs
        self.arp_table     = {}      # ip  → mac  (ARP spoof detection)
        self.rate_tracker  = {}      # ip  → [timestamps]
        self.rate_limit    = 100     # max packets per window
        self.rate_window   = 10      # window size in seconds

        # ── Event log (capped at 200) ────────────────────────────────────────
        self.event_log = []

        # ── Counters ─────────────────────────────────────────────────────────
        self.stats = {
            'total':         0,
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
        mapper.connect('/firewall/rules/port/{port}',
            controller=name, action='add_blocked_port',
            conditions=dict(method=['POST']))
        mapper.connect('/firewall/rules/port/{port}',
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

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod  = parser.OFPFlowMod(
            datapath=datapath, priority=priority,
            idle_timeout=idle_timeout,
            match=match, instructions=inst)
        datapath.send_msg(mod)

    # ── Firewall checks ──────────────────────────────────────────────────────

    def _check_ip_block(self, datapath, src_ip, dst_ip):
        if src_ip in self.blocked_ips:
            parser = datapath.ofproto_parser
            match  = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            self.add_flow(datapath, priority=100, match=match, actions=[])
            self.stats['blocked'] += 1
            self._log('block', f'IP blocked: {src_ip}', src=src_ip, dst=dst_ip)
            return True
        if self.allowed_ips and src_ip not in self.allowed_ips:
            self.stats['blocked'] += 1
            self._log('block', f'IP not in allowlist: {src_ip}', src=src_ip)
            return True
        return False

    def _check_port_block(self, datapath, proto_num, dst_port, src_ip):
        if dst_port in self.blocked_ports:
            parser = datapath.ofproto_parser
            kw     = {'tcp_dst': dst_port} if proto_num == 6 else {'udp_dst': dst_port}
            match  = parser.OFPMatch(eth_type=0x0800, ip_proto=proto_num, **kw)
            self.add_flow(datapath, priority=200, match=match, actions=[])
            self.stats['blocked'] += 1
            proto = 'TCP' if proto_num == 6 else 'UDP'
            self._log('block', f'{proto} port {dst_port} blocked',
                      src=src_ip, extra=f'port={dst_port}')
            return True
        return False

    def _check_rate_limit(self, src_ip):
        now = time.time()
        self.rate_tracker.setdefault(src_ip, [])
        self.rate_tracker[src_ip] = [
            t for t in self.rate_tracker[src_ip] if now - t < self.rate_window]
        self.rate_tracker[src_ip].append(now)
        if len(self.rate_tracker[src_ip]) > self.rate_limit:
            self.stats['rate_limited'] += 1
            self._log('block', f'Rate limit exceeded: {src_ip}', src=src_ip,
                      extra=f'{len(self.rate_tracker[src_ip])} pkts/{self.rate_window}s')
            return True
        return False

    def _check_arp_spoof(self, src_mac, src_ip):
        if src_ip not in self.arp_table:
            self.arp_table[src_ip] = src_mac
            return False
        if self.arp_table[src_ip] != src_mac:
            self.stats['arp_spoof'] += 1
            self._log('warn',
                      f'ARP spoof: {src_ip} claimed by {src_mac} '
                      f'(known: {self.arp_table[src_ip]})',
                      src=src_mac, extra='ARP_SPOOF')
            return True
        return False

    def _check_tcp_flags(self, tcp_pkt, src_ip):
        f = tcp_pkt.bits
        FIN, SYN, PSH, URG = 0x01, 0x02, 0x08, 0x20
        if f & (FIN | PSH | URG) == (FIN | PSH | URG):
            self.stats['scan_detected'] += 1
            self._log('warn', f'Xmas scan from {src_ip}',  src=src_ip, extra='XMAS_SCAN')
            return True
        if f == 0:
            self.stats['scan_detected'] += 1
            self._log('warn', f'NULL scan from {src_ip}',  src=src_ip, extra='NULL_SCAN')
            return True
        if f & (SYN | FIN) == (SYN | FIN):
            self.stats['scan_detected'] += 1
            self._log('warn', f'SYN+FIN from {src_ip}',   src=src_ip, extra='MALFORMED')
            return True
        return False

    # ── Packet-in handler ────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        super(FirewallApp, self)._packet_in_handler(ev)

        msg      = ev.msg
        datapath = msg.datapath
        pkt      = packet.Packet(msg.data)

        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt  = pkt.get_protocol(ipv4.ipv4)

        self.stats['total'] += 1

        if arp_pkt:
            if self._check_arp_spoof(eth_pkt.src, arp_pkt.src_ip):
                return

        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

            if self._check_ip_block(datapath, src_ip, dst_ip):
                return
            if self._check_rate_limit(src_ip):
                return

            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt:
                if self._check_tcp_flags(tcp_pkt, src_ip):
                    return
                if self._check_port_block(datapath, 6, tcp_pkt.dst_port, src_ip):
                    return

            udp_pkt = pkt.get_protocol(udp.udp)
            if udp_pkt:
                if self._check_port_block(datapath, 17, udp_pkt.dst_port, src_ip):
                    return

            self.stats['allowed'] += 1

        self._ws_manager.broadcast(json.dumps({
            'type': 'packet',
            'data': str(pkt)[:120],
        }))

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
