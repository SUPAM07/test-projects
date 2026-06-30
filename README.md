<div align="center">

```
     █████████   █████ █████  █████  █████████
  ███░░░░░███ ░░███ ░░███  ░░███  ███░░░░░███
 ░███    ░███  ░███  ░███   ░███ ░███    ░░░
 ░███████████  ░███  ░███   ░███ ░░█████████
 ░███░░░░░███  ░███  ░███   ░███  ░░░░░░░░███
 ░███    ░███  ░███  ░███   ░███  ███    ░███
 █████   █████ █████ ░░████████  ░░█████████
░░░░░   ░░░░░ ░░░░░   ░░░░░░░░    ░░░░░░░░░       v1.0
```

# AIUS v1.0 — Attack & Intrusion Utility Suite

**IEC 61850 / MMS Passive PCAP Editor + Live MITM Engine**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20x86__64-orange?style=flat-square&logo=linux)](https://kernel.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Root Required](https://img.shields.io/badge/MITM%20Features-Root%20Required-red?style=flat-square)]()
[![IEC 61850](https://img.shields.io/badge/Protocol-IEC%2061850--8--1-blueviolet?style=flat-square)]()

*A research tool for cybersecurity testing of IEC 61850 substations — developed at IISc under PGCoE sponsorship.*

</div>

---

## ⚠️ Disclaimer

> **AIUS is a research and academic tool developed for authorized cybersecurity testing of IEC 61850 substation automation systems.**
>
> Use of this tool against systems you do not own or have explicit written authorization to test is **illegal** and **unethical**. The authors and affiliated institutions accept no responsibility for misuse. This tool is intended strictly for:
> - Academic research
> - Authorized penetration testing of your own lab/testbed environments
> - IEC 61850 protocol security research

---

## About

AIUS (Attack & Intrusion Utility Suite) is an open-source cybersecurity research tool targeting **IEC 61850** — the international standard for communication in electrical substations. IEC 61850 uses the **MMS (Manufacturing Message Specification)** protocol over TCP/102 for communication between IEDs (Intelligent Electronic Devices), RTUs, and SCADA systems.

AIUS provides two core capabilities in a single PyQt5 GUI:

| Mode | Description |
|------|-------------|
| **Passive PCAP Editor** | Load captured `.pcap`/`.pcapng` files, inspect and modify TLV fields at the BER layer, forge specific packet fields, and save back — supports MMS, GOOSE, and SV |
| **Live MMS MITM Engine** | ARP poisoning → NFQueue intercept → real-time TLV field forging → replay. 7 configurable attack operations on live MMS streams |


## Architecture

```
AIUS v1.0 — High-Level Architecture
─────────────────────────────────────────────────────────────────────────

  Victim IED ──── ARP poison ────► Kali Attacker ──── ARP poison ────► MMS Server
                                         │
                               iptables FORWARD
                              --dport/sport 102
                              -j NFQUEUE --queue-num 1
                                         │
                                 nfqueue_handler()
                                         │
                          ┌──────────────┼──────────────┐
                          ▼              ▼               ▼
                     JSON Store      Redis TS       Attack Engine
                 live_packets.json   TS.ADD          ┌─ forward
                                                     ├─ forward_copy
                                                     ├─ delay_forward
                                                     ├─ drop
                                                     ├─ shuffle
                                                     ├─ keepalive
                                                     ├─ replace  (old_pcap ref)
                                                     └─ modify   (TLV forge)
```

---

## Features

### Passive PCAP Editor
- **Streaming PCAP loader** — reads `.pcap`/`.pcapng` files of any size using `PcapReader` (no full-file RAM load). Progress bar with live packet count. Tested on 300MB+ captures without freezing.
- **Protocol-aware TLV parser** — full BER TLV parse with human-readable tag names for MMS (Confirmed-RequestPDU, Confirmed-ServiceRequest, etc.), GOOSE, SV, and universal ASN.1 types
- **Layer editing** — modify Ethernet (src/dst MAC), IP (src/dst/TTL), TCP (ports/seq/ack/flags/window), AppID, and Length fields
- **TLV modification** — select any tag by number and occurrence index, replace its value (hex or ASCII)
- **TLV insertion** — insert a new TLV tag at any position using Before/After anchor tags with occurrence selection
- **Auto/Manual length mode** — length field auto-recalculated on save or manually overridden
- **IP/TCP greyout** — automatically disabled for GOOSE and SV (Ethernet-level) protocols
- **Save options** — save full PCAP, whole TCP session, or modified packets only

### Live MMS MITM Engine
- **One-click MITM setup** — establishes ARP poisoning, enables IP forwarding, inserts iptables NFQUEUE rule, binds NFQueue handler — all from the GUI
- **7 attack operations** (switchable live without restarting):

| Operation | Effect | Wireshark indicator |
|-----------|--------|---------------------|
| `forward` | Transparent passthrough | Clean sequential SEQ |
| `forward_copy` | Pass + mirror copy to tap interface | Duplicate packets on tap iface |
| `delay_forward` | Accept immediately + send OOB copy after N ms | `[TCP Retransmission]` N ms later |
| `drop` | Discard MMS data packets (DoS) | `[TCP Retransmission]` → RST/timeout |
| `shuffle` | Accept + buffer N copies, re-inject shuffled | `[TCP Out-Of-Order]` |
| `keepalive` | Inject synthetic MMS keepalive on silence | Extra PSH+ACK from victim IP |
| `replace` | Swap TLV values with historical reference (Redis) | Normal SEQ, different TLV value |
| `modify` | Forge any TLV field value in real-time | Normal SEQ, forged TLV value |

- **Redis TimeSeries integration** — per-tag time series storage for replay, anomaly detection, and sparkline analysis (auto-starts `redis-stack-server`)
- **Live tag refresh** — TLV tag dropdown auto-populated from intercepted packets
- **Old PCAP reference** — load a passive capture as historical reference for the `replace` attack
- **Live packet log** — auto-scrolling terminal showing every intercepted packet action

---

## Project Structure

```
aius/
├── app/
│   ├── ui_wiring.py            ← (starting point, main file) MainWindow, streaming PCAP loader, signal wiring
│   ├── gui_mitm_tab.py         ← Live MITM tab widget + MitmWorker QThread
│   ├── attack_engine.py        ← All 7 attack operations (NFQueue dispatch)
│   ├── json_writer.py          ← Packet → JSON store (thread-safe, fcntl.flock)
│   ├── redis_ts.py             ← Redis TimeSeries integration (auto-start server)
│   ├── aius_v1.ui              ← Qt Designer UI file
│   ├── tlv_parser1.py          ← Parse / encode / modify / insert — all protocols
|   ├── tlv_parser2.py          ← Contains parse functions for live MMS traffic
│   ├── mitm.py                 ← NFQueue handler + MITM orchestrator
│   ├── arp_poison.py           ← ARP poisoning + iptables + ip_forward setup
│   ├── main_sniffer.py         ← (your protocol sniffers)
│   ├── goose_handler.py        ← (your GOOSE handler)
│   ├── mms_handler.py          ← (your MMS handler)
│   └── sv_handler.py           ← (your SV handler)
|
├── build_installer.sh              ← Builds installer files
├── install.sh                      ← Distro-aware installer
└── uninstall.sh                    ← Clean removal
```

---

## Requirements

### System
- Linux x86_64 (Kali, Parrot, Ubuntu 20.04+, Debian 11+)
- Python 3.10 or higher
- Root / sudo (for NFQueue, iptables, ARP — passive editor works without root)

### Python packages
```
scapy >= 2.5.0
netfilterqueue >= 1.1.0
redis[hiredis] >= 5.0.0
PyQt5 >= 5.15.0
```

### System packages
```
libnetfilter-queue-dev   # NFQueue binding
iptables                 # NFQUEUE rules
dsniff                   # arpspoof (fallback ARP method)
redis-stack-server       # Redis with TimeSeries module (auto-installed)
```

---

## Installation

### Method 1 — Installer script (recommended)

```bash
git clone https://github.com/KishanDESE/Attack-TooL.git
cd Attack-TooL
sudo bash build_installer.sh
```
First build the files using build_installer.sh 'sudo bash build_installer.sh ./app'.
Then a .tar.gz file will be generated, extract it then run installer(install.sh) within it.

The installer will:
1. Detect your distro (Kali / Ubuntu / Debian / Parrot)
2. Install all system packages via `apt`
3. Add the Redis Stack repository and install `redis-stack-server`
4. Create a Python virtualenv at `/opt/aius/venv` with all pip packages
5. Install a `/usr/local/bin/aius` launcher (works from any directory)
6. Add a desktop entry (AIUS appears in your app menu)
7. Configure `sudoers` so no password prompt for AIUS
8. Set `cap_net_admin,cap_net_raw` capabilities on the venv Python

**Then just run:**
```bash
aius
```

### Method 2 — Manual (for development)

```bash
git clone https://github.com/KishanDESE/Attack-TooL.git
cd Attack-TooL

# System packages
sudo apt install libnetfilter-queue-dev iptables python3-pyqt5 dsniff

# Redis Stack (for TimeSeries)
curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/redis.list
sudo apt update && sudo apt install redis-stack-server

# Python deps
pip install scapy netfilterqueue "redis[hiredis]" PyQt5

# Run
sudo python3 run.py
```

### Uninstall

```bash
sudo bash install.sh --remove
OR
sudo bash uninstall.sh
```

---

## Usage

### Passive PCAP Editor

1. **Browse** — select your `.pcap` or `.pcapng` file
2. **Load Packet** — streams the file in the background (progress bar shown). File is never fully loaded into RAM — works on any size.
3. **Select protocol type** — MMS / GOOSE / SV (auto-detected). IP and TCP fields are greyed out for GOOSE/SV.
4. **Select Packet No.** — switch between captured packets
5. **Edit fields** — modify MAC, IP, TCP, AppID, Length, or TLV values
6. **TLV section** — use Tag No. + Occurrence dropdowns (auto-populated from the packet) to target specific fields
7. **Save** — output to a new `.pcap` file

### Live MMS MITM

1. Go to the **Live MITM** tab
2. Fill in **Victim IP**, **Server IP**, **Target Interface**
3. Click **▶ Establish MITM** — ARP poisoning starts, iptables rule added, NFQueue bound
4. Select **Attack Mode** and set parameters
5. Click **⚡ Apply Attack Params** — takes effect immediately on next packet
6. Click **🔌 Connect Redis** — auto-starts `redis-stack-server` if not running
7. Click **■ Stop MITM** — restores ARP tables, removes iptables rule, disables IP forwarding

---

## TLV Parser

The unified `tlv_parser1.py` handles all BER TLV operations across every protocol and mode:

```python
from tlv_parser1 import (
    parse_all,          # bytes → list[TLVNode]
    encode_all,         # list[TLVNode] → bytes
    find_tlv_by_tag,    # search by int tag number OR string name
    modify_tlv_value,   # in-place value replacement (int or bytes)
    insert_tlv_after,   # byte-level insert, handles nested ancestors
    extract_mms_pdu,    # strip TPKT+COTP → raw BER
    rebuild_tpkt,       # re-wrap modified PDU with original headers
    all_unique_tags,    # list all unique tags in tree (for GUI dropdowns)
    pretty_print,       # human-readable tree dump
)

# Example: parse, modify, re-encode
nodes = parse_all(raw_pdu_bytes)
matches = find_tlv_by_tag(nodes, 0x85)        # by tag number
modify_tlv_value(matches[0], b'\x0F\xA0')     # 4000 decimal
new_bytes = encode_all(nodes)

# Or search by name
integers = find_tlv_by_tag(nodes, "INTEGER")
```

---

## Viewing Redis Data

AIUS stores per-tag time series in Redis. To inspect:

**RedisInsight (GUI):** Download from [redis.com/redis-enterprise/redis-insight](https://redis.com/redis-enterprise/redis-insight/) → connect to `127.0.0.1:6379` → browse the TimeSeries and Browser tabs.

**CLI:**
```bash
redis-cli
> KEYS mms:*                              # all live keys
> TS.RANGE mms:default:0x85:value - +    # full history for tag 0x85
> GET mms:index:1                         # full JSON blob for packet #1
> KEYS old:*                              # reference PCAP values (replace attack)
```

**Key schema:**
```
mms:{flow_id}:{tag_hex}:value    — live tag values (float, TS)
mms:{flow_id}:{tag_hex}:length   — live tag lengths (TS)
mms:index:{seq}                  — full packet JSON blob (expires 1hr)
old:{tag_hex}:value              — reference PCAP values for replace attack
```

---

## Wireshark — Verifying Attacks

Filter: `tcp.port == 102` or `mms`

| Attack | What to look for in Wireshark |
|--------|-------------------------------|
| `forward` | Clean sequential SEQ, no retransmissions |
| `delay_forward` | `[TCP Retransmission]` arriving N ms after original |
| `drop` | `[TCP Retransmission]` × 3-5 → `[TCP RST]` or timeout |
| `shuffle` | `[TCP Out-Of-Order]` packets, same SEQ reordered |
| `keepalive` | Extra PSH+ACK from victim IP during silence window |
| `replace` / `modify` | Normal SEQ continuity, different TLV value in MMS dissector |

For `replace` and `modify`: open the MMS dissector tree in Wireshark. The forged value appears in the data field while TCP headers look completely normal — this is what makes these attacks hard to detect at the network layer.

---

## Research Context

This tool was developed as part of cybersecurity research on **IEC 61850 substation communication security** at the **Indian Institute of Science (IISc), Bangalore**, under the supervision of **Prof. Haresh Dagale**, sponsored by **PGCoE (PowerGrid Centre of Excellence in Cybersecurity)**.

A research paper describing the attack methodology, experimental results, and proposed detection mechanisms is currently under preparation. This repository will be linked from the paper upon publication.


---

## Contributing

Contributions are welcome after the paper is published. Until then, feel free to open issues for bugs.

When contributing:
- Follow the existing package structure
- New protocol handlers go in `mms_handler.py, sv_handler.py, goose_hander.py`
- GUI-only changes go in `.ui`

---

## Credits

| Role | Name |
|------|------|
| Developer | Supam Roy |
| Sponsor | PGCoE — PowerGrid Centre of Excellence in Cybersecurity |
| Institution | Indian Institute of Science (IISc), Bangalore |

---

## License

MIT License — see [LICENSE](LICENSE) for details.

The MIT license applies to the source code in this repository. It does not grant permission to use this tool against systems you do not own or have written authorization to test.

---


