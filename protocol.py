"""
protocol.py - Custom Packet Format for Reliable Group Notification System
==========================================================================
Packet Header (fixed 16 bytes):
  [0-1]  Magic     : 0xAB 0xCD
  [2]    Version   : 0x01
  [3]    Msg Type  : see MsgType enum
  [4-7]  Seq Num   : uint32, big-endian
  [8-11] Group ID  : uint32, big-endian
  [12-13] Payload Len: uint16, big-endian
  [14]   Flags     : bitfield (ACK=0x01, RETX=0x02, LAST=0x04)
  [15]   Reserved  : 0x00
"""

import struct
from enum import IntEnum

MAGIC        = b'\xAB\xCD'
VERSION      = 0x01
HEADER_SIZE  = 16
MAX_PAYLOAD  = 1400   # safe UDP payload under typical MTU

class MsgType(IntEnum):
    SUBSCRIBE    = 0x01   # client -> server: join a group
    UNSUBSCRIBE  = 0x02   # client -> server: leave a group
    NOTIFY       = 0x10   # server -> client: notification/alert
    ACK          = 0x20   # client -> server: acknowledge a NOTIFY
    HEARTBEAT    = 0x30   # bidirectional keepalive
    LIST_GROUPS  = 0x40   # client -> server: list available groups
    GROUP_LIST   = 0x41   # server -> client: response with group names
    ERROR        = 0xFF

class Flags(IntEnum):
    ACK_FLAG  = 0x01
    RETX_FLAG = 0x02   # this packet is a retransmission
    LAST_FLAG = 0x04   # last fragment

def build_packet(msg_type: int, seq: int, group_id: int,
                 payload: bytes = b'', flags: int = 0) -> bytes:
    """Construct a protocol packet."""
    pay_len = len(payload)
    if pay_len > MAX_PAYLOAD:
        raise ValueError(f"Payload too large: {pay_len} > {MAX_PAYLOAD}")
    header = struct.pack('!2sBBIIHBB',
        MAGIC, VERSION, msg_type,
        seq, group_id, pay_len, flags, 0)
    return header + payload

def parse_packet(data: bytes):
    """
    Parse raw bytes into a dict.
    Returns None if the packet is malformed.
    """
    if len(data) < HEADER_SIZE:
        return None
    magic, version, msg_type, seq, group_id, pay_len, flags, _ = \
        struct.unpack('!2sBBIIHBB', data[:HEADER_SIZE])
    if magic != MAGIC or version != VERSION:
        return None
    payload = data[HEADER_SIZE: HEADER_SIZE + pay_len]
    return {
        'msg_type':  msg_type,
        'seq':       seq,
        'group_id':  group_id,
        'pay_len':   pay_len,
        'flags':     flags,
        'payload':   payload,
        'is_retx':   bool(flags & Flags.RETX_FLAG),
        'is_last':   bool(flags & Flags.LAST_FLAG),
    }

def ack_packet(seq: int, group_id: int) -> bytes:
    """Build a bare ACK packet."""
    return build_packet(MsgType.ACK, seq, group_id, flags=Flags.ACK_FLAG)
