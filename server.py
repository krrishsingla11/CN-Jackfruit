#!/usr/bin/env python3
"""
server.py - Reliable Group Notification Server
===============================================
Deliverable 2 Improvements:
  * Admin HTTP metrics endpoint (port 55002) for real-time monitoring
  * Per-client delivery statistics tracking
  * Graceful shutdown on SIGINT/SIGTERM
  * Rate limiting: max notifications per second per group
  * Client health tracking: remove after N consecutive delivery failures
  * New admin commands: stats, broadcast, kick, dm, who
  * Configurable ACK_TIMEOUT and MAX_RETRIES via environment variables
  * Thread-safe metrics counters (total sent, acked, failed, retransmitted)
  * [NEW] Client name registry: clients register with a name on connect
  * [NEW] Direct message: admin/clients can send a private message to a named client
"""

import os, sys, ssl, socket, threading, time, logging, json, signal, http.server
from collections import defaultdict, deque

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from protocol import (MsgType, build_packet, parse_packet, HEADER_SIZE, MAX_PAYLOAD)

# ── Configuration (env-overridable) ────────────────────────────────────────────
TCP_HOST      = '0.0.0.0'
TCP_PORT      = 55000
UDP_PORT      = 55001
METRICS_PORT  = 55002
CERT_FILE     = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'certs', 'server.crt')
KEY_FILE      = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'certs', 'server.key')
ACK_TIMEOUT   = float(os.environ.get('ACK_TIMEOUT',  '2.0'))
MAX_RETRIES   = int(os.environ.get('MAX_RETRIES',    '5'))
RATE_LIMIT    = int(os.environ.get('RATE_LIMIT',     '100'))
SEQ_COUNTER   = 0
SEQ_LOCK      = threading.Lock()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(threadName)s] %(levelname)s: %(message)s'
)
log = logging.getLogger('server')

# ── Global state ────────────────────────────────────────────────────────────────
groups       = defaultdict(set)
group_names  = {'alerts': 1, 'updates': 2, 'critical': 3}
name_by_id   = {v: k for k, v in group_names.items()}
groups_lock  = threading.Lock()

pending_acks = {}
pending_lock = threading.Lock()

udp_sock = None
_shutdown = threading.Event()

# ── [NEW] Client name registry ──────────────────────────────────────────────────
# Maps client_name (str) -> (ip, udp_port)
client_registry      = {}
client_registry_lock = threading.Lock()

# ── D2: Metrics ─────────────────────────────────────────────────────────────────
metrics = {
    'total_sent':       0,
    'total_acked':      0,
    'total_failed':     0,
    'total_retransmit': 0,
    'clients_ever':     0,
    'start_time':       time.time(),
}
metrics_lock = threading.Lock()

client_failures      = defaultdict(int)
client_failures_lock = threading.Lock()
MAX_CLIENT_FAILURES  = 10

rate_buckets = defaultdict(lambda: {'tokens': float(RATE_LIMIT), 'last': time.time()})
rate_lock    = threading.Lock()

notif_log      = deque(maxlen=200)
notif_log_lock = threading.Lock()


def next_seq():
    global SEQ_COUNTER
    with SEQ_LOCK:
        SEQ_COUNTER = (SEQ_COUNTER + 1) & 0xFFFFFFFF
        return SEQ_COUNTER


def _inc(key, amount=1):
    with metrics_lock:
        metrics[key] += amount


def _check_rate(group_id) -> bool:
    with rate_lock:
        bucket  = rate_buckets[group_id]
        now     = time.time()
        elapsed = now - bucket['last']
        bucket['tokens'] = min(float(RATE_LIMIT), bucket['tokens'] + elapsed * RATE_LIMIT)
        bucket['last']   = now
        if bucket['tokens'] >= 1:
            bucket['tokens'] -= 1
            return True
        return False


def send_reliable(pkt, addr, seq):
    ack_event = threading.Event()
    key = (seq, addr)
    with pending_lock:
        pending_acks[key] = ack_event

    retries     = 0
    current_pkt = pkt
    delivered   = False

    while retries <= MAX_RETRIES:
        try:
            udp_sock.sendto(current_pkt, addr)
            _inc('total_sent')
        except OSError as e:
            log.error(f"UDP send error to {addr}: {e}")
            break

        if ack_event.wait(timeout=ACK_TIMEOUT):
            _inc('total_acked')
            with client_failures_lock:
                client_failures[addr] = 0
            delivered = True
            break

        retries += 1
        _inc('total_retransmit')
        if retries <= MAX_RETRIES:
            current_pkt = current_pkt[:14] + bytes([current_pkt[14] | 0x02]) + current_pkt[15:]
            log.warning(f"  Retransmit seq={seq} -> {addr} (retry {retries})")

    if not delivered:
        _inc('total_failed')
        log.error(f"  Delivery FAILED seq={seq} to {addr} after {MAX_RETRIES} retries")
        with client_failures_lock:
            client_failures[addr] += 1
            fails = client_failures[addr]
        if fails >= MAX_CLIENT_FAILURES:
            log.warning(f"  Removing unresponsive client {addr} (failures={fails})")
            with groups_lock:
                for gid in groups:
                    groups[gid].discard(addr)
            with client_failures_lock:
                client_failures.pop(addr, None)
            with client_registry_lock:
                to_del = [n for n, a in client_registry.items() if a == addr]
                for n in to_del:
                    del client_registry[n]

    with pending_lock:
        pending_acks.pop(key, None)


def notify_group(group_id, message, sender_name=None):
    if not _check_rate(group_id):
        log.warning(f"Rate limit hit for group {group_id} — notification dropped")
        return

    prefix   = f"[{sender_name}] " if sender_name else ""
    full_msg = prefix + message
    payload  = full_msg.encode()[:MAX_PAYLOAD]

    with groups_lock:
        members = list(groups.get(group_id, []))

    gname = name_by_id.get(group_id, str(group_id))
    if not members:
        log.info(f"Group '{gname}' has no subscribers.")
        return

    log.info(f"Notifying group '{gname}' ({len(members)} members): {full_msg!r}")
    with notif_log_lock:
        notif_log.append({
            'ts':      time.strftime('%H:%M:%S'),
            'group':   gname,
            'message': full_msg,
            'members': len(members),
        })

    for addr in members:
        seq = next_seq()
        pkt = build_packet(MsgType.NOTIFY, seq, group_id, payload)
        t = threading.Thread(
            target=send_reliable, args=(pkt, addr, seq),
            daemon=True, name=f"retx-{seq}"
        )
        t.start()


# ── [NEW] Direct message to a named client ─────────────────────────────────────
def direct_message(target_name, message, sender_name=None):
    """
    Send a reliable UDP NOTIFY directly to one named client.
    group_id = 0 is used as the special 'direct message' channel.
    Returns True if the target was found, False if not online.
    """
    with client_registry_lock:
        addr = client_registry.get(target_name)

    if addr is None:
        log.warning(f"DM failed: '{target_name}' is not connected / not registered.")
        return False

    prefix   = f"[DM from {sender_name}] " if sender_name else "[DM] "
    full_msg = prefix + message
    payload  = full_msg.encode()[:MAX_PAYLOAD]
    seq      = next_seq()
    pkt      = build_packet(MsgType.NOTIFY, seq, 0, payload)   # group_id=0 means DM

    log.info(f"DM -> '{target_name}' ({addr}): {full_msg!r}")
    t = threading.Thread(
        target=send_reliable, args=(pkt, addr, seq),
        daemon=True, name=f"dm-{seq}"
    )
    t.start()
    return True


def udp_listener():
    log.info(f"UDP listener on :{UDP_PORT}")
    while not _shutdown.is_set():
        try:
            udp_sock.settimeout(1.0)
            data, addr = udp_sock.recvfrom(HEADER_SIZE + MAX_PAYLOAD)
        except socket.timeout:
            continue
        except OSError:
            break

        pkt = parse_packet(data)
        if pkt is None:
            continue

        if pkt['msg_type'] == MsgType.ACK:
            seq = pkt['seq']
            key = (seq, addr)
            with pending_lock:
                event = pending_acks.get(key)
                if event:
                    event.set()
                    log.debug(f"  ACK seq={seq} from {addr}")

        elif pkt['msg_type'] == MsgType.HEARTBEAT:
            try:
                udp_sock.sendto(build_packet(MsgType.HEARTBEAT, pkt['seq'], 0), addr)
            except OSError:
                pass


def handle_client(conn, addr):
    log.info(f"Control connection from {addr}")
    _inc('clients_ever')
    client_udp_port = None
    registered_name = None

    try:
        while True:
            raw = conn.recv(4096)
            if not raw:
                break
            try:
                msg = json.loads(raw.decode())
            except Exception:
                conn.sendall(json.dumps({'status': 'error', 'msg': 'bad JSON'}).encode())
                continue

            cmd        = msg.get('cmd', '')
            group_name = msg.get('group', '')
            udp_port   = msg.get('udp_port', None)

            if udp_port:
                client_udp_port = int(udp_port)

            group_id = group_names.get(group_name)

            # ── [NEW] register ─────────────────────────────────────────────────
            if cmd == 'register':
                name = msg.get('name', '').strip()
                if not name:
                    resp = {'status': 'error', 'msg': 'name cannot be empty'}
                elif client_udp_port is None:
                    resp = {'status': 'error', 'msg': 'send udp_port with register command'}
                else:
                    with client_registry_lock:
                        client_registry[name] = (addr[0], client_udp_port)
                    registered_name = name
                    log.info(f"  Registered '{name}' -> {addr[0]}:{client_udp_port}")
                    resp = {'status': 'ok', 'registered_as': name}

            # ── [NEW] dm (client-to-client) ────────────────────────────────────
            elif cmd == 'dm':
                to_name = msg.get('to', '').strip()
                dm_msg  = msg.get('message', '').strip()
                if not to_name or not dm_msg:
                    resp = {'status': 'error', 'msg': 'dm requires to and message fields'}
                else:
                    found = direct_message(
                        to_name, dm_msg,
                        sender_name=registered_name or f"{addr[0]}:{client_udp_port}"
                    )
                    if found:
                        resp = {'status': 'ok', 'msg': f'DM sent to {to_name}'}
                    else:
                        resp = {'status': 'error', 'msg': f'{to_name} is not online'}

            # ── [NEW] who: list online named clients ───────────────────────────
            elif cmd == 'who':
                with client_registry_lock:
                    online = list(client_registry.keys())
                resp = {'status': 'ok', 'online': online}

            elif cmd == 'subscribe':
                if group_id is None:
                    resp = {'status': 'error', 'msg': f'unknown group: {group_name}'}
                elif client_udp_port is None:
                    resp = {'status': 'error', 'msg': 'send udp_port first'}
                else:
                    member_addr = (addr[0], client_udp_port)
                    with groups_lock:
                        groups[group_id].add(member_addr)
                    log.info(f"  {member_addr} subscribed to '{group_name}'")
                    resp = {'status': 'ok', 'group': group_name, 'group_id': group_id}

            elif cmd == 'unsubscribe':
                if group_id and client_udp_port:
                    with groups_lock:
                        groups[group_id].discard((addr[0], client_udp_port))
                resp = {'status': 'ok'}

            elif cmd == 'list':
                resp = {'status': 'ok', 'groups': list(group_names.keys())}

            elif cmd == 'members':
                if group_id is None:
                    resp = {'status': 'error', 'msg': 'unknown group'}
                else:
                    with groups_lock:
                        mems = [list(m) for m in groups[group_id]]
                    resp = {'status': 'ok', 'members': mems}

            elif cmd == 'ping':
                resp = {'status': 'ok', 'pong': time.time()}

            else:
                resp = {'status': 'error', 'msg': f'unknown cmd: {cmd}'}

            conn.sendall(json.dumps(resp).encode())

    except (ConnectionResetError, ssl.SSLError, OSError) as e:
        log.warning(f"Client {addr} disconnected: {e}")
    finally:
        if client_udp_port:
            member_addr = (addr[0], client_udp_port)
            with groups_lock:
                for gid in groups:
                    groups[gid].discard(member_addr)
        if registered_name:
            with client_registry_lock:
                client_registry.pop(registered_name, None)
            log.info(f"  '{registered_name}' unregistered (disconnected)")
        conn.close()
        log.info(f"Control connection closed: {addr}")


def tcp_server():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw.bind((TCP_HOST, TCP_PORT))
    raw.listen(50)
    log.info(f"SSL control server on {TCP_HOST}:{TCP_PORT}")

    with ctx.wrap_socket(raw, server_side=True) as srv:
        srv.settimeout(1.0)
        while not _shutdown.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except ssl.SSLError as e:
                log.warning(f"SSL handshake failed: {e}")
                continue
            t = threading.Thread(target=handle_client, args=(conn, addr),
                                 daemon=True, name=f"client-{addr[1]}")
            t.start()


class MetricsHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        with metrics_lock:
            m = dict(metrics)
        m['uptime_s'] = round(time.time() - m.pop('start_time'), 1)
        with groups_lock:
            m['group_sizes'] = {
                name_by_id.get(gid, str(gid)): len(members)
                for gid, members in groups.items()
            }
        with client_registry_lock:
            m['online_clients'] = list(client_registry.keys())
        with notif_log_lock:
            m['recent_notifications'] = list(notif_log)[-10:]
        body = json.dumps(m, indent=2).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)


def metrics_server():
    srv = http.server.HTTPServer(('0.0.0.0', METRICS_PORT), MetricsHandler)
    log.info(f"Metrics endpoint at http://0.0.0.0:{METRICS_PORT}/")
    while not _shutdown.is_set():
        srv.handle_request()


def admin_console():
    print("\n[Admin] Commands:")
    print("  notify <group> <message>     — send notification to a group")
    print("  broadcast <message>          — send to ALL groups")
    print("  dm <name> <message>          — send direct message to a named client")
    print("  who                          — list online named clients")
    print("  list                         — show subscribers per group")
    print("  stats                        — delivery metrics")
    print("  kick <ip>:<port>             — forcibly remove a client")
    print("  quit\n")

    while not _shutdown.is_set():
        try:
            line = input("admin> ").strip()
        except EOFError:
            break
        if not line:
            continue

        parts = line.split(None, 2)
        cmd   = parts[0]

        if cmd == 'quit':
            _shutdown.set()
            os._exit(0)

        elif cmd == 'who':
            with client_registry_lock:
                online = list(client_registry.items())
            if online:
                print("  Online named clients:")
                for name, addr in online:
                    print(f"    {name:20s}  ->  {addr[0]}:{addr[1]}")
            else:
                print("  No named clients online.")

        elif cmd == 'dm' and len(parts) >= 3:
            target, msg = parts[1], parts[2]
            found = direct_message(target, msg, sender_name='[Admin]')
            if not found:
                print(f"  '{target}' not found. Use 'who' to see online clients.")

        elif cmd == 'list':
            with groups_lock:
                for gid, members in groups.items():
                    print(f"  {name_by_id.get(gid, gid)}: {members}")

        elif cmd == 'stats':
            with metrics_lock:
                m = dict(metrics)
            uptime = time.time() - m['start_time']
            print(f"  Uptime        : {uptime:.1f}s")
            print(f"  Total sent    : {m['total_sent']}")
            print(f"  ACKed         : {m['total_acked']}")
            print(f"  Failed        : {m['total_failed']}")
            print(f"  Retransmitted : {m['total_retransmit']}")
            print(f"  Clients ever  : {m['clients_ever']}")
            if m['total_sent'] > 0:
                pct = m['total_acked'] / m['total_sent'] * 100
                print(f"  Delivery rate : {pct:.1f}%")

        elif cmd == 'notify' and len(parts) >= 3:
            gname, msg = parts[1], parts[2]
            gid = group_names.get(gname)
            if gid is None:
                print(f"  Unknown group: {gname}")
            else:
                notify_group(gid, msg)

        elif cmd == 'broadcast' and len(parts) >= 2:
            msg = parts[1]
            for gname, gid in group_names.items():
                notify_group(gid, msg)
            print(f"  Broadcast sent to {len(group_names)} groups")

        elif cmd == 'kick' and len(parts) >= 2:
            try:
                target = parts[1]
                if ':' in target:
                    ip, port_s = target.rsplit(':', 1)
                else:
                    ip, port_s = target, parts[2]
                addr = (ip, int(port_s))
                with groups_lock:
                    for gid in groups:
                        groups[gid].discard(addr)
                print(f"  Kicked {addr}")
            except Exception:
                print("  Usage: kick <ip>:<port>  e.g.  kick 127.0.0.1:54321")

        else:
            print("  Unknown command.")


def _signal_handler(sig, frame):
    print("\n[!] Shutdown signal received. Exiting cleanly...")
    _shutdown.set()
    time.sleep(0.3)
    os._exit(0)


def main():
    global udp_sock

    signal.signal(signal.SIGINT,  _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((TCP_HOST, UDP_PORT))

    threading.Thread(target=udp_listener,   daemon=True, name='udp-listener').start()
    threading.Thread(target=tcp_server,     daemon=True, name='tcp-server').start()
    threading.Thread(target=metrics_server, daemon=True, name='metrics').start()

    admin_console()


if __name__ == '__main__':
    main()
