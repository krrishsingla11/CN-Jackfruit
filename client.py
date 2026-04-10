#!/usr/bin/env python3
"""
client.py - Subscriber Client for Reliable Group Notification System
======================================================================
  * Opens an SSL/TCP control connection to subscribe/unsubscribe/list groups
  * Listens on a local UDP port for incoming NOTIFY packets
  * Sends ACKs immediately upon receipt
  * Tracks sequence numbers to detect duplicates (due to retransmission)
  * Displays received notifications with timestamp and metadata
  * [NEW] Registers with a display name on the server
  * [NEW] Can send direct messages (DMs) to other named clients
  * [NEW] Can query who is online with the 'who' command
"""

import os, sys, ssl, socket, threading, time, json, argparse, logging

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from protocol import (MsgType, parse_packet, ack_packet, build_packet,
                      HEADER_SIZE, MAX_PAYLOAD)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(threadName)s] %(levelname)s: %(message)s'
)
log = logging.getLogger('client')

# ── Defaults ───────────────────────────────────────────────────────────────────
SERVER_HOST = '127.0.0.1'
TCP_PORT    = 55000
UDP_PORT    = 55001
CERT_FILE   = os.path.join(os.path.dirname(__file__), 'certs', 'server.crt')


class NotifyClient:
    def __init__(self, server_host=SERVER_HOST, tcp_port=TCP_PORT,
                 udp_port=UDP_PORT, local_udp_port=0, cert=CERT_FILE,
                 client_name='client'):
        self.server_host    = server_host
        self.tcp_port       = tcp_port
        self.udp_port       = udp_port
        self.cert           = cert
        self.name           = client_name
        self.seen_seqs: set = set()

        # Bind local UDP port (OS assigns if local_udp_port=0)
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.bind(('', local_udp_port))
        self.local_udp_port = self.udp_sock.getsockname()[1]
        log.info(f"[{self.name}] UDP receiver on :{self.local_udp_port}")

        # SSL control connection
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cert)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ssl_conn = ctx.wrap_socket(raw, server_hostname=server_host)
        self.ssl_conn.connect((server_host, tcp_port))
        log.info(f"[{self.name}] SSL control channel connected to {server_host}:{tcp_port}")

        # Start UDP listener thread
        self._running = True
        self._udp_thread = threading.Thread(
            target=self._udp_listener, daemon=True, name='udp-rx')
        self._udp_thread.start()

        # Heartbeat thread
        self._hb_thread = threading.Thread(
            target=self._heartbeat, daemon=True, name='heartbeat')
        self._hb_thread.start()

        # [NEW] Auto-register name with server right after connecting
        self._register()

    # ── Internal helpers ─────────────────────────────────────────────────────
    def _send_ctrl(self, payload: dict) -> dict:
        self.ssl_conn.sendall(json.dumps(payload).encode())
        raw = self.ssl_conn.recv(4096)
        return json.loads(raw.decode())

    def _register(self):
        """[NEW] Tell the server our display name so DMs can reach us."""
        resp = self._send_ctrl({
            'cmd':      'register',
            'name':     self.name,
            'udp_port': self.local_udp_port,
        })
        if resp.get('status') == 'ok':
            log.info(f"[{self.name}] Registered as '{resp.get('registered_as')}'")
        else:
            log.warning(f"[{self.name}] Registration failed: {resp}")

    def _udp_listener(self):
        log.info(f"[{self.name}] UDP listener started")
        while self._running:
            try:
                self.udp_sock.settimeout(1.0)
                data, addr = self.udp_sock.recvfrom(HEADER_SIZE + MAX_PAYLOAD)
            except socket.timeout:
                continue
            except OSError:
                break

            pkt = parse_packet(data)
            if pkt is None:
                continue

            if pkt['msg_type'] == MsgType.NOTIFY:
                seq      = pkt['seq']
                group_id = pkt['group_id']
                message  = pkt['payload'].decode(errors='replace')
                is_retx  = pkt['is_retx']

                # Always ACK even duplicates
                self.udp_sock.sendto(
                    ack_packet(seq, group_id),
                    (self.server_host, 55001)
                )

                if seq in self.seen_seqs:
                    log.debug(f"[{self.name}] Duplicate seq={seq} suppressed")
                    continue
                self.seen_seqs.add(seq)

                retx_tag = " [RETX]" if is_retx else ""

                # group_id == 0 means it is a Direct Message
                if group_id == 0:
                    print(f"\n{'='*60}")
                    print(f"  [{self.name}] *** DIRECT MESSAGE ***{retx_tag}")
                    print(f"  Seq Num  : {seq}")
                    print(f"  Time     : {time.strftime('%H:%M:%S')}")
                    print(f"  Message  : {message}")
                    print(f"{'='*60}\n")
                else:
                    print(f"\n{'='*60}")
                    print(f"  [{self.name}] GROUP NOTIFICATION{retx_tag}")
                    print(f"  Group ID : {group_id}")
                    print(f"  Seq Num  : {seq}")
                    print(f"  Time     : {time.strftime('%H:%M:%S')}")
                    print(f"  Message  : {message}")
                    print(f"{'='*60}\n")

            elif pkt['msg_type'] == MsgType.HEARTBEAT:
                pass

    def _heartbeat(self):
        seq = 0
        while self._running:
            time.sleep(10)
            try:
                pkt = build_packet(MsgType.HEARTBEAT, seq, 0)
                self.udp_sock.sendto(pkt, (self.server_host, self.udp_port))
                seq = (seq + 1) & 0xFFFFFFFF
            except OSError:
                break

    # ── Public API ───────────────────────────────────────────────────────────
    def subscribe(self, group: str) -> dict:
        resp = self._send_ctrl({
            'cmd':      'subscribe',
            'group':    group,
            'udp_port': self.local_udp_port,
        })
        if resp.get('status') == 'ok':
            log.info(f"[{self.name}] Subscribed to '{group}' (id={resp.get('group_id')})")
        else:
            log.error(f"[{self.name}] Subscribe failed: {resp}")
        return resp

    def unsubscribe(self, group: str) -> dict:
        resp = self._send_ctrl({'cmd': 'unsubscribe', 'group': group})
        log.info(f"[{self.name}] Unsubscribed from '{group}'")
        return resp

    def list_groups(self) -> list:
        resp = self._send_ctrl({'cmd': 'list'})
        return resp.get('groups', [])

    def who_is_online(self) -> list:
        """[NEW] Ask server for list of registered (named) online clients."""
        resp = self._send_ctrl({'cmd': 'who'})
        return resp.get('online', [])

    def send_dm(self, to_name: str, message: str) -> dict:
        """[NEW] Send a direct message to another named client via the server."""
        resp = self._send_ctrl({
            'cmd':     'dm',
            'to':      to_name,
            'message': message,
        })
        if resp.get('status') == 'ok':
            log.info(f"[{self.name}] DM sent to '{to_name}'")
        else:
            log.error(f"[{self.name}] DM failed: {resp.get('msg')}")
        return resp

    def close(self):
        self._running = False
        self.ssl_conn.close()
        self.udp_sock.close()
        log.info(f"[{self.name}] Disconnected")


# ── Interactive CLI ────────────────────────────────────────────────────────────
def interactive(client: NotifyClient):
    print(f"\nCommands:")
    print(f"  subscribe <group>       — subscribe to a group (alerts/updates/critical)")
    print(f"  unsubscribe <group>     — unsubscribe from a group")
    print(f"  list                    — show available groups")
    print(f"  who                     — show online named clients")
    print(f"  dm <name> <message>     — send a direct message to a named client")
    print(f"  quit\n")

    while True:
        try:
            line = input(f"[{client.name}]> ").strip()
        except EOFError:
            break
        if not line:
            continue
        parts = line.split(None, 2)
        cmd   = parts[0]
        arg1  = parts[1] if len(parts) > 1 else ''
        arg2  = parts[2] if len(parts) > 2 else ''

        if cmd == 'subscribe':
            client.subscribe(arg1)

        elif cmd == 'unsubscribe':
            client.unsubscribe(arg1)

        elif cmd == 'list':
            print("Available groups:", client.list_groups())

        elif cmd == 'who':
            online = client.who_is_online()
            if online:
                print("Online clients:", ', '.join(online))
            else:
                print("No other named clients online.")

        elif cmd == 'dm':
            if not arg1 or not arg2:
                print("  Usage: dm <name> <message>")
            else:
                resp = client.send_dm(arg1, arg2)
                if resp.get('status') != 'ok':
                    print(f"  Error: {resp.get('msg')}")

        elif cmd == 'quit':
            client.close()
            break

        else:
            print("  Unknown command.")


def main():
    ap = argparse.ArgumentParser(description='Group Notification Client')
    ap.add_argument('--host',   default=SERVER_HOST)
    ap.add_argument('--port',   type=int, default=TCP_PORT)
    ap.add_argument('--name',   default='client1', help='Your display name (used for DMs)')
    ap.add_argument('--cert',   default=CERT_FILE)
    ap.add_argument('--groups', nargs='*', default=[],
                    help='Groups to auto-subscribe on start')
    args = ap.parse_args()

    c = NotifyClient(server_host=args.host, tcp_port=args.port,
                     cert=args.cert, client_name=args.name)

    for g in args.groups:
        c.subscribe(g)

    interactive(c)


if __name__ == '__main__':
    main()
