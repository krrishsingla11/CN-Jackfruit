# Reliable Group Notification System
**Project 18 — CN Jackfruit Mini Project**

Team Members - 
Krrish Singla - PES1UG24AM141
Kshama - PES1UG24AM142
Bilal - PES1UG24AM162

A UDP-based group notification system that reliably delivers alerts to multiple subscribers with acknowledgement, retransmission, timeout handling, and direct messaging. All control communication is secured with SSL/TLS.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    SERVER                            │
│  TCP/SSL :55000  →  subscribe / unsubscribe / dm    │
│  UDP     :55001  →  NOTIFY out, ACK in              │
│  HTTP    :55002  →  metrics JSON endpoint           │
└─────────────────────────────────────────────────────┘
         ↕ SSL/TCP (control)   ↕ UDP (data)
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│  Client A    │   │  Client B    │   │  Client C    │
│  (Alice)     │   │  (Bob)       │   │  (Carol)     │
└──────────────┘   └──────────────┘   └──────────────┘
```

**Groups available:** `alerts` (id 1) · `updates` (id 2) · `critical` (id 3)

**Direct Messages:** group_id = 0 is reserved for DMs — a private reliable UDP packet to a single named client.

---

## Files

| File | Description |
|---|---|
| `server.py` | Main server — SSL/TCP control + UDP notifier + metrics + admin console |
| `client.py` | Subscriber client with SSL control channel, UDP receiver, and DM support |
| `protocol.py` | Custom 16-byte packet format (magic, seq, group_id, flags) |
| `perf_test.py` | Performance benchmarking (latency, throughput, scalability, packet loss) |
| `failure_test.py` | Failure scenario tests (disconnect, SSL fail, flood, bad input) |
| `test_system.py` | Original D1 automated system tests |
| `certs/` | Self-signed SSL certificate and private key |
| `HOW_TO_RUN.txt` | Quick reference guide |

---

## Requirements

- Python 3.8 or higher
- No external packages needed (uses only standard library)
- Both machines on the **same WiFi or hotspot**

---

## Running on Two Laptops

### Laptop 1 — Server

**Step 1.** Open a terminal and go to the project folder:
```bash
cd CN_Submission_D2
```

**Step 2.** Find your IP address:
```bash
# Windows
ipconfig
# Look for "IPv4 Address" under your WiFi adapter

# Linux / Mac
ip addr show
# or: ifconfig
```
Note your IP — e.g. `192.168.1.10`. You will give this to the client laptops.

**Step 3.** (Windows only) Allow the firewall ports — run CMD as Administrator:
```cmd
netsh advfirewall firewall add rule name="PORT55000" protocol=TCP dir=in localport=55000 action=allow
netsh advfirewall firewall add rule name="PORT55001" protocol=UDP dir=in localport=55001 action=allow
netsh advfirewall firewall add rule name="PORT55002" protocol=TCP dir=in localport=55002 action=allow
```

**Step 4.** Start the server:
```bash
python server.py
```

Expected output:
```
UDP listener on :55001
SSL control server on 0.0.0.0:55000
Metrics endpoint at http://0.0.0.0:55002/
admin>
```

---

### Laptop 2 (and 3, 4, ...) — Clients

**Step 1.** Copy the entire `CN_Submission_D2` folder to the client laptop (USB, Google Drive, or `scp`).

**Step 2.** Open a terminal in the project folder.

**Step 3.** Start the client — replace `<SERVER_IP>` with Laptop 1's IP:
```bash
python client.py --name Alice --host 192.168.1.10 --groups alerts critical
```

Expected output:
```
[Alice] UDP receiver on :54321
[Alice] SSL control channel connected to 192.168.1.10:55000
[Alice] Registered as 'Alice'
[Alice] Subscribed to 'alerts' (id=1)
[Alice] Subscribed to 'critical' (id=3)
[Alice]>
```

Start another client on a third laptop (or a second terminal on Laptop 2):
```bash
python client.py --name Bob --host 192.168.1.10 --groups alerts updates
```

---

## Sending Notifications (from the `admin>` prompt on Laptop 1)

### Group notification
```
notify alerts "Server going down in 5 minutes"
notify critical "CRITICAL: Database failure detected"
```

### Broadcast to all groups
```
broadcast "Emergency evacuation — please exit the building"
```

### Direct message to a specific person
```
# First check who is online
who

# Then send a DM by name
dm Alice "Hi Alice, this is a private message just for you"
dm Bob "Bob, please check your email urgently"
```

### Other admin commands
```
list      — show all subscribers per group
stats     — delivery statistics (sent / acked / failed / retransmitted)
kick 192.168.1.11:54321   — forcibly remove a specific client
quit      — graceful shutdown
```

---

## Client Commands (from the `[Name]>` prompt)

```
subscribe alerts          — subscribe to a group
unsubscribe alerts        — leave a group
list                      — show available groups
who                       — see who else is online
dm Bob "Hey Bob!"         — send a direct message to Bob
quit                      — disconnect and exit
```

---

## Performance Testing

Run on Laptop 1 while server is running:

```bash
# Basic benchmark with 10 concurrent clients
python perf_test.py --host 127.0.0.1 --clients 10

# With 30% simulated packet loss (demonstrates retransmission)
python perf_test.py --host 127.0.0.1 --clients 10 --loss 0.3
```

Output includes SSL round-trip latency (mean, median, p95, p99), packet throughput, best-effort vs reliable UDP comparison, concurrent scalability table, and delivery rate under varying packet loss.

---

## Failure Scenario Testing

```bash
python failure_test.py --host 127.0.0.1
```

Tests 8 scenarios automatically:
1. Abrupt client disconnect
2. Malformed JSON control message
3. Plain TCP connection to TLS port (SSL handshake failure)
4. Unknown group name in subscribe
5. Duplicate subscription
6. Packet loss + retransmission detection
7. Rapid connect/disconnect flood (50 connections)
8. Subscribe without sending udp_port

---

## Metrics Endpoint

While the server is running, open in a browser or use curl:
```bash
curl http://192.168.1.10:55002/
```

Returns a JSON object with:
- `total_sent`, `total_acked`, `total_failed`, `total_retransmit`
- `uptime_s`
- `group_sizes` — subscriber count per group
- `online_clients` — list of registered client names
- `recent_notifications` — last 10 notifications sent

---

## Custom Packet Format (`protocol.py`)

16-byte fixed header:

| Bytes | Field | Description |
|---|---|---|
| 0–1 | Magic | `0xAB 0xCD` — frame validation |
| 2 | Version | `0x01` |
| 3 | Msg Type | NOTIFY=0x10, ACK=0x20, HEARTBEAT=0x30, etc. |
| 4–7 | Seq Num | uint32 big-endian — for reliable delivery |
| 8–11 | Group ID | uint32 — group (0 = direct message) |
| 12–13 | Payload Len | uint16 |
| 14 | Flags | ACK=0x01, RETX=0x02, LAST=0x04 |
| 15 | Reserved | `0x00` |

Payload follows the header, max 1400 bytes (safe under standard MTU).

---

## Environment Variables (optional tuning)

```bash
ACK_TIMEOUT=2.0   # seconds to wait for ACK before retransmit
MAX_RETRIES=5     # maximum retransmit attempts per packet
RATE_LIMIT=100    # max notifications per second per group
```

Example:
```bash
ACK_TIMEOUT=1.0 MAX_RETRIES=3 python server.py
```

---

## SSL Certificates

The `certs/` folder contains a self-signed certificate for demo purposes. The client connects with `verify_mode = ssl.CERT_NONE` to accept self-signed certs. In production, replace with a CA-signed certificate and enable hostname verification.
