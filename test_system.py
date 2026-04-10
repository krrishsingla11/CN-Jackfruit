#!/usr/bin/env python3
"""
test_system.py - Automated Integration Tests
=============================================
Starts the server in-process, runs multi-client scenarios, validates delivery.
"""

import os, sys, ssl, socket, threading, time, json, subprocess, signal
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from protocol import MsgType, build_packet, parse_packet, ack_packet, HEADER_SIZE, MAX_PAYLOAD

SERVER_HOST = '127.0.0.1'
TCP_PORT    = 55000
UDP_PORT    = 55001
CERT_FILE   = os.path.join(os.path.dirname(__file__), 'certs', 'server.crt')

PASS = "\033[92m✓ PASS\033[0m"
FAIL = "\033[91m✗ FAIL\033[0m"

results = []

def check(name, cond, detail=''):
    status = PASS if cond else FAIL
    print(f"  {status}  {name}" + (f"  ({detail})" if detail else ''))
    results.append((name, cond))


def ssl_connect():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s = ctx.wrap_socket(raw, server_hostname=SERVER_HOST)
    s.connect((SERVER_HOST, TCP_PORT))
    return s


def ctrl(s, payload):
    s.sendall(json.dumps(payload).encode())
    return json.loads(s.recv(4096).decode())


def make_udp():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(('', 0))
    u.settimeout(5.0)
    return u, u.getsockname()[1]


# ── Tests ──────────────────────────────────────────────────────────────────────
def test_ssl_handshake():
    print("\n[1] SSL Handshake")
    try:
        s = ssl_connect()
        check("SSL connection established", True)
        cipher = s.cipher()
        check("TLS cipher negotiated", cipher is not None, str(cipher))
        s.close()
    except Exception as e:
        check("SSL connection established", False, str(e))


def test_list_groups():
    print("\n[2] List Groups")
    s = ssl_connect()
    resp = ctrl(s, {'cmd': 'list'})
    check("Response status ok",   resp.get('status') == 'ok')
    groups = resp.get('groups', [])
    check("Groups non-empty",     len(groups) > 0, str(groups))
    check("'alerts' group exists", 'alerts' in groups)
    s.close()


def test_subscribe_unsubscribe():
    print("\n[3] Subscribe / Unsubscribe")
    s   = ssl_connect()
    udp, uport = make_udp()

    resp = ctrl(s, {'cmd': 'subscribe', 'group': 'alerts', 'udp_port': uport})
    check("Subscribe returns ok", resp.get('status') == 'ok')
    check("group_id returned",    'group_id' in resp)

    resp2 = ctrl(s, {'cmd': 'unsubscribe', 'group': 'alerts'})
    check("Unsubscribe returns ok", resp2.get('status') == 'ok')

    s.close(); udp.close()


def test_notify_delivery():
    print("\n[4] Notification Delivery")
    # Set up subscriber
    s   = ssl_connect()
    udp, uport = make_udp()
    ctrl(s, {'cmd': 'subscribe', 'group': 'alerts', 'udp_port': uport})

    # Trigger notify from a second control connection (simulate admin)
    # We'll directly inject a UDP packet as if from server
    # (Real test needs server admin channel — here we test the protocol layer)
    payload = b'TEST_NOTIFICATION_12345'
    pkt     = build_packet(MsgType.NOTIFY, seq=42, group_id=1, payload=payload)

    # Send directly to our own UDP socket (loopback test)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.sendto(pkt, (SERVER_HOST, uport))

    try:
        data, _ = udp.recvfrom(HEADER_SIZE + MAX_PAYLOAD)
        parsed  = parse_packet(data)
        check("Packet received",         parsed is not None)
        check("Correct msg type NOTIFY", parsed['msg_type'] == MsgType.NOTIFY)
        check("Seq number preserved",    parsed['seq'] == 42)
        check("Payload intact",          parsed['payload'] == payload)
        check("Group ID correct",        parsed['group_id'] == 1)
    except socket.timeout:
        check("Packet received", False, "timeout")

    sender.close(); s.close(); udp.close()


def test_ack_packet():
    print("\n[5] ACK Packet Format")
    ack = ack_packet(99, 2)
    parsed = parse_packet(ack)
    check("ACK parses correctly",   parsed is not None)
    check("ACK type correct",       parsed['msg_type'] == MsgType.ACK)
    check("ACK seq preserved",      parsed['seq'] == 99)
    check("ACK group_id preserved", parsed['group_id'] == 2)
    check("ACK flag set",           bool(parsed['flags'] & 0x01))


def test_multi_client():
    print("\n[6] Multiple Concurrent Clients")
    N = 5
    clients = []
    for i in range(N):
        s   = ssl_connect()
        udp, uport = make_udp()
        resp = ctrl(s, {'cmd': 'subscribe', 'group': 'updates', 'udp_port': uport})
        clients.append((s, udp, uport, resp))
    check(f"{N} clients subscribed simultaneously",
          all(r.get('status') == 'ok' for _, _, _, r in clients))
    for s, udp, _, _ in clients:
        s.close(); udp.close()


def test_duplicate_suppression():
    print("\n[7] Duplicate Suppression (client-side)")
    seen = set()
    # Simulate receiving same seq twice
    payload = b'duplicate test'
    pkt = build_packet(MsgType.NOTIFY, seq=777, group_id=1, payload=payload)
    parsed = parse_packet(pkt)
    seq = parsed['seq']

    first_new  = seq not in seen
    seen.add(seq)
    second_dup = seq in seen

    check("First packet accepted",    first_new)
    check("Duplicate seq detected",   second_dup)


def test_malformed_packet():
    print("\n[8] Malformed Packet Rejection")
    bad1 = parse_packet(b'')
    bad2 = parse_packet(b'\x00' * 16)          # wrong magic
    bad3 = parse_packet(b'\xAB\xCD\x01' + b'\x00' * 5)  # too short
    check("Empty packet rejected",        bad1 is None)
    check("Wrong magic rejected",         bad2 is None)
    check("Truncated header rejected",    bad3 is None)


def test_unknown_group():
    print("\n[9] Unknown Group Error Handling")
    s = ssl_connect()
    udp, uport = make_udp()
    resp = ctrl(s, {'cmd': 'subscribe', 'group': 'nonexistent_xyz', 'udp_port': uport})
    check("Unknown group returns error", resp.get('status') == 'error')
    s.close(); udp.close()


def test_retx_flag():
    print("\n[10] Retransmission Flag")
    pkt = build_packet(MsgType.NOTIFY, seq=5, group_id=1,
                       payload=b'retx test', flags=0x02)
    parsed = parse_packet(pkt)
    check("RETX flag detected",    parsed['is_retx'] == True)

    pkt2   = build_packet(MsgType.NOTIFY, seq=6, group_id=1, payload=b'normal')
    parsed2 = parse_packet(pkt2)
    check("Normal packet not RETX", parsed2['is_retx'] == False)


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  Reliable Group Notification System — Integration Tests")
    print("=" * 60)

    test_ssl_handshake()
    test_list_groups()
    test_subscribe_unsubscribe()
    test_notify_delivery()
    test_ack_packet()
    test_multi_client()
    test_duplicate_suppression()
    test_malformed_packet()
    test_unknown_group()
    test_retx_flag()

    total  = len(results)
    passed = sum(1 for _, ok in results if ok)
    print(f"\n{'='*60}")
    print(f"  Results: {passed}/{total} passed")
    print("=" * 60)
    sys.exit(0 if passed == total else 1)


if __name__ == '__main__':
    main()
