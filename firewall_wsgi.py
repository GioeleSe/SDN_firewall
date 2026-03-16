"""
firewall_wsgi.py  –  WSGI/REST controller + WebSocket handler
Handles all HTTP routes and WebSocket connections.
All firewall state lives in FirewallApp (firewall_app.py).
"""

import json
import os

from ryu.app.wsgi import ControllerBase, WebSocketRPCServer, websocket
from webob import Response

from firewall_app import FIREWALL_INSTANCE, WS_URL

# Absolute path to the GUI HTML file (same directory as this file)
GUI_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'GUI/firewall_gui.html')


class FirewallWSGI(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(FirewallWSGI, self).__init__(req, link, data, **config)
        self.app = data[FIREWALL_INSTANCE]   # reference to FirewallApp instance

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _json(self, data, status=200):
        body = json.dumps(data).encode('utf-8')
        return Response(status=status, content_type='application/json', body=body)

    # ── Static GUI ───────────────────────────────────────────────────────────

    def index(self, req, **_kw):
        with open(GUI_PATH, 'rb') as f:
            body = f.read()
        return Response(content_type='text/html', body=body)

    # ── Rules ─────────────────────────────────────────────────────────────────

    def get_rules(self, req, **_kw):
        app = self.app
        return self._json({
            'blocked_ips':   list(app.blocked_ips),
            'blocked_ports': list(app.blocked_ports),
            'allowed_ips':   list(app.allowed_ips),
            'rate_limit':    app.rate_limit,
            'rate_window':   app.rate_window,
        })

    def add_blocked_ip(self, req, ip, **_kw):
        self.app.blocked_ips.add(ip)
        # self.app._flush_flows_for_ip(ip)                                                                              # not needed with no ip flows installed
        self.app._log('info', f'Rule added: block IP {ip}', src=ip)
        return self._json({'status': 'ok', 'blocked_ips': list(self.app.blocked_ips)})

    def del_blocked_ip(self, req, ip, **_kw):
        self.app.blocked_ips.discard(ip)
        self.app._log('info', f'Rule removed: unblock IP {ip}', src=ip)
        return self._json({'status': 'ok', 'blocked_ips': list(self.app.blocked_ips)})

    def add_blocked_port(self, req, port, proto, **_kw):
        self.app.blocked_ports.add((int(port), int(proto)))
        self.app._log('info', f'Rule added: block protocol {proto} at port {port}')
        return self._json({'status': 'ok', 'blocked_ports': list(self.app.blocked_ports)})

    def del_blocked_port(self, req, port, proto, **_kw):
        self.app.blocked_ports.discard((int(port), int(proto)))
        self.app._log('info', f'Rule removed: unblock protocol {proto} at port {port}')
        return self._json({'status': 'ok', 'blocked_ports': list(self.app.blocked_ports)})

    def set_rate_limit(self, req, **_kw):
        body = json.loads(req.body)
        self.app.rate_limit  = int(body.get('limit',  self.app.rate_limit))
        self.app.rate_window = int(body.get('window', self.app.rate_window))
        self.app._log('info',
            f'Rate limit updated: {self.app.rate_limit} pkts/{self.app.rate_window}s')
        return self._json({'status': 'ok'})

    # ── Stats & log ───────────────────────────────────────────────────────────

    def get_stats(self, req, **_kw):
        return self._json(self.app.stats)

    def get_log(self, req, **_kw):
        return self._json(self.app.event_log[-100:])

    # ── WebSocket ─────────────────────────────────────────────────────────────

    @websocket('firewall', WS_URL)
    def _ws_handler(self, ws):
        self.app.logger.debug('WebSocket connected: %s', ws)
        rpc = WebSocketRPCServer(ws, self.app)
        rpc.serve_forever()
        self.app.logger.debug('WebSocket disconnected: %s', ws)
