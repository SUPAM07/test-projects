import sys
import io
import os
import contextlib
import argparse
import textwrap

from PyQt5 import uic
from PyQt5.QtWidgets import (
    QMainWindow, QApplication, QFileDialog, QMessageBox,
    QScrollArea, QWidget, QVBoxLayout
)
from PyQt5.QtCore import Qt, QCoreApplication

# ── Backend imports ────────────────────────────────────────────────────────────
from scapy.all import PcapReader, PcapWriter, Ether, IP, TCP, Dot1Q, Raw

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from gui_mitm_tab import inject_mitm_tab
from tlv_parser1 import parse_all, encode_tlv, modify_tlv_value
from mms_handler   import extract_mms_pdu
from goose_handler import extract_goose_pdu
from sv_handler    import extract_sv_pdu

MMS_PORT = 102


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def collect_tlv_nodes(tlvs):
    
    # Returns dict covering every node in the entire TLV tree (depth-first).
    result = {}

    def _walk(node):
        if isinstance(node, list):
            for n in node:
                _walk(n)
            return
        tag = node["tag_number"]
        result.setdefault(tag, []).append(node)
        if node["constructed"]:
            for child in node["value"]:
                _walk(child)

    _walk(tlvs)
    return result


def extract_pdu_from_packet(pkt):
    # Return (pdu_bytes, type_str) or (None, None).
    if not pkt.haslayer(Raw):
        return None, None

    payload = bytes(pkt[Raw].load)

    if pkt.haslayer(TCP):
        if pkt[TCP].sport == MMS_PORT or pkt[TCP].dport == MMS_PORT:
            pdu = extract_mms_pdu(payload)
            return pdu, "MMS"

    if pkt.haslayer(Ether):
        if pkt.haslayer(Dot1Q):
            vtype = pkt[Dot1Q].type
            if vtype == 0x88B8:
                return extract_goose_pdu(bytes(pkt)), "GOOSE"
            if vtype == 0x88BA:
                return extract_sv_pdu(bytes(pkt)),   "SV"
        eth_type = pkt[Ether].type
        if eth_type == 0x88B8:
            return extract_goose_pdu(bytes(pkt)), "GOOSE"
        if eth_type == 0x88BA:
            return extract_sv_pdu(bytes(pkt)),   "SV"

    return None, None


def node_value_display(node) -> str:
    
    if node["constructed"]:
        # Re-encode children back to bytes and show as hex
        raw = b"".join(encode_tlv(c) for c in node["value"])
        return raw.hex(" ").upper()

    val = node["value"]
    if isinstance(val, (bytes, bytearray)):
        # Try integer first
        try:
            return str(int.from_bytes(val, "big"))
        except Exception:
            pass
        # Try printable ASCII
        try:
            s = val.decode("ascii")
            if s.isprintable():
                return s
        except Exception:
            pass
        return val.hex(" ").upper()

    return str(val)


# ══════════════════════════════════════════════════════════════════════════════
class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        ui_path = os.path.join(os.path.dirname(__file__), "aius_v1.ui")
        uic.loadUi(ui_path, self)
        self._apply_scroll_area()

        # ── Inject Live MITM tab ──────────────────────────────────────────
        self.mitm_tab = inject_mitm_tab(self)
        
        # ── Runtime state ──────────────────────────────────────────────────
        self._pcap_path: str        = ""
        self._packets:   list       = []
        self._current_pkt_idx: int  = 0

        # TLV state for the currently loaded packet
        self._tlv_nodes: dict  = {}    # { tag_int : [node, ...] }
        self._pdu_bytes: bytes = b""
        self._pdu_type:  str   = ""

        self._wire_passive_editor()
        self._log("[IEC61850 Tool] Ready. Load a PCAP file to begin.")

    # ══════════════════════════════════════════════════════════════════════
    # SCROLL AREA WRAPPER
    # ══════════════════════════════════════════════════════════════════════
    def _apply_scroll_area(self):
        original = self.centralWidget()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(original)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        container = QWidget()
        container.setStyleSheet("background-color: #0d1117;")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(scroll)
        self.setCentralWidget(container)

    # ══════════════════════════════════════════════════════════════════════
    # SIGNAL WIRING
    # ══════════════════════════════════════════════════════════════════════
    def _wire_passive_editor(self):

        # Top bar
        self.btnBrowse.clicked.connect(self._on_browse)
        self.btnLoad.clicked.connect(self._on_load_packet)
        self.comboPacketType.currentTextChanged.connect(self._on_packet_type_changed)
        self._on_packet_type_changed(self.comboPacketType.currentText())

        # TLV edit — tag selection drives occurrence AND value AND type
        self.comboTagNo.currentIndexChanged.connect(self._on_tag_no_changed)
        self.comboPositionNo.currentIndexChanged.connect(self._on_occurrence_changed)

        # Add-new-TLV — Before combo drives its occurrence dropdown only
        self.comboBeforeTagNo.currentIndexChanged.connect(
            lambda: self._refresh_anchor_occurrences(
                self.comboBeforeTagNo, self.comboBeforeOccurrence))

        self.btnAddTLV.clicked.connect(self._on_add_tlv)

        # Length radio buttons
        self.radioLengthAuto.toggled.connect(self._on_length_mode_changed)
        self.radioLengthManual.toggled.connect(self._on_length_mode_changed)
        self._on_length_mode_changed()

        # Output / Save tab
        self.btnSavePcap.clicked.connect(self._on_save_pcap)
        self.btnSaveWholeTCP.clicked.connect(self._on_save_whole_tcp)
        self.btnPrintTLV.clicked.connect(self._on_print_tlv)
        self.btnClearTerminal.clicked.connect(self.terminalBox.clear)

        # Length Range
        self.btnLengthRange.clicked.connect(self._on_length_range_clicked)

        # Menu bar
        self.actionOpen.triggered.connect(self._on_browse)
        self.actionSave.triggered.connect(self._on_save_pcap)
        self.actionExit.triggered.connect(self.close)
        self.actionPrintTLV.triggered.connect(self._on_print_tlv)
        self.actionClearLog.triggered.connect(self.terminalBox.clear)
        self.actionAbout.triggered.connect(self._on_about)

    # ══════════════════════════════════════════════════════════════════════
    # LOGGING
    # ══════════════════════════════════════════════════════════════════════
    def _log(self, msg: str):
        self.terminalBox.append(msg)

    def _qlog(self, msg: str):
        self.quickTerminal.append(msg)
        self._log(msg)

    # ══════════════════════════════════════════════════════════════════════
    # BROWSE
    # ══════════════════════════════════════════════════════════════════════
    def _on_browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open PCAP file", "",
            "PCAP files (*.pcap *.pcapng);;All files (*)"
        )
        if path:
            self.lineEditFilePath.setText(path)
            self._pcap_path = path
            self._populate_packet_numbers(path)
            self._qlog(f"[Browse] File: {path}")

    def _populate_packet_numbers(self, path: str):
        try:
            count = 0
            with PcapReader(path) as r:
                for _ in r:
                    count += 1
            self.comboPacketNo.blockSignals(True)
            self.comboPacketNo.clear()
            self.comboPacketNo.addItems([str(i) for i in range(1, count + 1)])
            self.comboPacketNo.blockSignals(False)
            self._qlog(f"[Info] {count} packet(s) in file.")
        except Exception as exc:
            self._qlog(f"[ERROR] {exc}")

    # ══════════════════════════════════════════════════════════════════════
    # LOAD PACKET
    # ══════════════════════════════════════════════════════════════════════
    def _on_load_packet(self):
        path = self.lineEditFilePath.text().strip()
        if not path:
            self._qlog("[Load] No file selected.")
            return

        pkt_no_text = self.comboPacketNo.currentText().strip()
        pkt_no = int(pkt_no_text) if pkt_no_text.isdigit() else 1

        try:
            all_pkts = []
            with PcapReader(path) as r:
                for p in r:
                    all_pkts.append(p)
        except Exception as exc:
            self._qlog(f"[Load ERROR] {exc}")
            return

        if not all_pkts:
            self._qlog("[Load] File is empty.")
            return

        self._packets = all_pkts
        idx = max(0, min(pkt_no - 1, len(all_pkts) - 1))
        self._current_pkt_idx = idx
        pkt = all_pkts[idx]

        # Ethernet
        if pkt.haslayer(Ether):
            self.lineEditSrcMAC.setText(pkt[Ether].src)
            self.lineEditDstMAC.setText(pkt[Ether].dst)

        # IP
        if pkt.haslayer(IP):
            self.lineEditIPSrc.setText(pkt[IP].src)
            self.lineEditIPDst.setText(pkt[IP].dst)
            self.lineEditTTL.setText(str(pkt[IP].ttl))

        # TCP
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            self.lineEditSrcPort.setText(str(tcp.sport))
            self.lineEditDstPort.setText(str(tcp.dport))
            self.lineEditSeqNo.setText(str(tcp.seq))
            self.lineEditAckNo.setText(str(tcp.ack))
            self.lineEditFlags.setText(hex(int(tcp.flags)))
            self.lineEditWindowSize.setText(str(tcp.window))
            ws = next((v for k, v in (tcp.options or []) if k == "WScale"), None)
            self.lineEditWindowScale.setText(str(ws) if ws is not None else "")

        # Auto-detect type
        detected = self._detect_packet_type(pkt)
        idx_type = self.comboPacketType.findText(detected)
        if idx_type >= 0:
            self.comboPacketType.setCurrentIndex(idx_type)

        # App ID / Length header
        app_id, length = self._parse_app_header(pkt)
        if app_id is not None:
            self.lineEditAppID.setText(hex(app_id))
        if length is not None and self.radioLengthManual.isChecked():
            self.lineEditLength.setText(str(length))

        # TLV parse
        pdu, pdu_type = extract_pdu_from_packet(pkt)
        if pdu:
            self._pdu_bytes = pdu
            self._pdu_type  = pdu_type
            self._tlv_nodes = collect_tlv_nodes(parse_all(pdu))
            self._populate_tlv_dropdowns()
            self._qlog(
                f"[Load] Packet #{pkt_no} ({pdu_type}) — "
                f"{len(self._tlv_nodes)} unique tag(s)."
            )
        else:
            self._pdu_bytes = b""
            self._pdu_type  = ""
            self._tlv_nodes = {}
            self._populate_tlv_dropdowns()
            self._qlog(f"[Load] Packet #{pkt_no} — no IEC-61850 PDU detected.")

    def _detect_packet_type(self, pkt) -> str:
        if pkt.haslayer(TCP):
            if pkt[TCP].sport == MMS_PORT or pkt[TCP].dport == MMS_PORT:
                return "MMS"
        if pkt.haslayer(Ether):
            etype = pkt[Dot1Q].type if pkt.haslayer(Dot1Q) else pkt[Ether].type
            if etype == 0x88B8: return "GOOSE"
            if etype == 0x88BA: return "SV"
        return "None"

    def _parse_app_header(self, pkt):
        try:
            raw    = bytes(pkt)
            offset = 18 if pkt.haslayer(Dot1Q) else 14
            app_id = int.from_bytes(raw[offset:offset+2],   "big")
            length = int.from_bytes(raw[offset+2:offset+4], "big")
            return app_id, length
        except Exception:
            return None, None

    # ══════════════════════════════════════════════════════════════════════
    # PACKET TYPE TOGGLE
    # ══════════════════════════════════════════════════════════════════════
    def _on_packet_type_changed(self, pkt_type: str):
        is_mms = (pkt_type == "MMS")
        self.grpIP.setEnabled(is_mms)
        self.grpTCP.setEnabled(is_mms)
        self.btnSaveWholeTCP.setEnabled(is_mms)
        self._qlog(f"[Type] {pkt_type} selected.")

    # ══════════════════════════════════════════════════════════════════════
    # TLV DROPDOWNS — Edit Existing
    # ══════════════════════════════════════════════════════════════════════
    _KNOWN_TAGS = {
        0x61: "PDU",        0x80: "MmsString",  0xa0: "List",
        0x83: "Boolean",    0x84: "BitString",   0x85: "Integer",
        0x86: "Unsigned",   0x91: "UtcTime",
        # extend with your own tags here
    }

    def _tag_label(self, tag_int: int) -> str:
        name = self._KNOWN_TAGS.get(tag_int, "")
        return f"0x{tag_int:02X} ({name})" if name else f"0x{tag_int:02X}"

    def _current_tag_int(self, combo) -> int | None:
        text = combo.currentText().strip()
        if not text:
            return None
        try:
            return int(text.split()[0], 16)
        except (ValueError, IndexError):
            return None

    def _populate_tlv_dropdowns(self):
        
        labels = [self._tag_label(t) for t in sorted(self._tlv_nodes)]

        for combo in (self.comboTagNo, self.comboBeforeTagNo):
            combo.blockSignals(True)
            combo.clear()
            combo.addItems(labels)
            combo.blockSignals(False)

        # Trigger initial refresh for each
        self._on_tag_no_changed()
        self._refresh_anchor_occurrences(self.comboBeforeTagNo,
                                          self.comboBeforeOccurrence)

    def _on_tag_no_changed(self):
        
        tag_int = self._current_tag_int(self.comboTagNo)
        nodes   = self._tlv_nodes.get(tag_int, [])
        count   = len(nodes)

        # Occurrence dropdown
        self.comboPositionNo.blockSignals(True)
        self.comboPositionNo.clear()
        self.comboPositionNo.addItems([str(i) for i in range(1, count + 1)])
        self.comboPositionNo.blockSignals(False)

        # Now load the value / type for occurrence 1
        self._load_tlv_value_for_current_occurrence()

    def _on_occurrence_changed(self):
        self._load_tlv_value_for_current_occurrence()

    def _load_tlv_value_for_current_occurrence(self):
        
        tag_int = self._current_tag_int(self.comboTagNo)
        if tag_int is None:
            return

        nodes = self._tlv_nodes.get(tag_int, [])
        if not nodes:
            return

        occ_text = self.comboPositionNo.currentText().strip()
        occ      = int(occ_text) if occ_text.isdigit() else 1
        occ      = max(1, min(occ, len(nodes)))
        node     = nodes[occ - 1]

        # Type combo
        type_str = "Constructed" if node["constructed"] else "Primitive"
        idx = self.comboTLVType.findText(type_str)
        if idx >= 0:
            self.comboTLVType.setCurrentIndex(idx)

        # Value field
        self.lineEditTLVValue.setText(node_value_display(node))

    def _refresh_anchor_occurrences(self, tag_combo, occ_combo):
        tag_int = self._current_tag_int(tag_combo)
        count   = len(self._tlv_nodes.get(tag_int, [])) if tag_int is not None else 0
        occ_combo.clear()
        occ_combo.addItems([str(i) for i in range(1, count + 1)])

    # ══════════════════════════════════════════════════════════════════════
    # LENGTH MODE RADIO
    # ══════════════════════════════════════════════════════════════════════
    def _on_length_mode_changed(self):
        manual = self.radioLengthManual.isChecked()
        self.lineEditLength.setEnabled(manual)
        if not manual:
            self.lineEditLength.setPlaceholderText("Auto-computed")
            self.lineEditLength.clear()
        else:
            self.lineEditLength.setPlaceholderText("Enter length (decimal or 0xHEX)")

    # ══════════════════════════════════════════════════════════════════════
    # LENGTH RANGE  (acts as a button via checkbox stateChanged)
    # ══════════════════════════════════════════════════════════════════════

    def _on_length_range_clicked(self):
 
        if not self._packets:
            self._qlog("[LengthRange] No packets loaded.")
            return
 
        # tag_int → list of lengths (one entry per node across all packets)
        tag_lengths = {}
 
        # tag_int → list of per-packet occurrence counts
        # e.g. if tag 0x85 appears 3 times in pkt1 and 5 times in pkt2
        #      → tag_occ_per_pkt[0x85] = [3, 5]
        tag_occ_per_pkt = {}
 
        def _collect(tlv_nodes_dict):
            for tag_int, nodes in tlv_nodes_dict.items():
                # Per-packet occurrence count for this tag
                tag_occ_per_pkt.setdefault(tag_int, []).append(len(nodes))
 
                # Length of each individual node
                for node in nodes:
                    val = node["value"]
                    if node["constructed"]:
                        length = sum(len(encode_tlv(c)) for c in val)
                    elif isinstance(val, (bytes, bytearray)):
                        length = len(val)
                    else:
                        length = node.get("length", 0)
                    tag_lengths.setdefault(tag_int, []).append(length)
 
        for pkt in self._packets:
            pdu, _ = extract_pdu_from_packet(pkt)
            if pdu:
                _collect(collect_tlv_nodes(parse_all(pdu)))
 
        if not tag_lengths:
            self._log("[LengthRange] No IEC-61850 PDUs found in loaded packets.")
            return
 
        # ── Print table ────────────────────────────────────────────────────────
        self._log("\n[LengthRange] ══ Tag Length & Occurrence Range ══")
        self._log(
            f"  {'Tag':<16}  {'MinLen':>6}  {'MaxLen':>6}  "
            f"{'MinOcc':>6}  {'MaxOcc':>6}  {'TotalFreq':>9}"
        )
        self._log(
            f"  {'-'*16}  {'-'*6}  {'-'*6}  {'-'*6}  {'-'*6}  {'-'*9}"
        )
 
        for tag_int in sorted(tag_lengths):
            lengths   = tag_lengths[tag_int]
            occ_list  = tag_occ_per_pkt.get(tag_int, [1])
            label     = self._tag_label(tag_int)
 
            self._log(
                f"  {label:<16}  {min(lengths):>6}  {max(lengths):>6}  "
                f"  {min(occ_list):>6}  {max(occ_list):>6}  {sum(occ_list):>9}"
            )
 
        self._log("[LengthRange] ══ End ══\n")
        self._qlog("[LengthRange] Done — see terminal for full report.")
    # ══════════════════════════════════════════════════════════════════════
    # ADD NEW TLV TAG  (Before-only anchor)
    # ══════════════════════════════════════════════════════════════════════
    def _on_add_tlv(self):
    
        new_tag_text = self.lineEditNewTagNo.text().strip()
        new_val_text = self.lineEditNewValue.text().strip()
        before_tag   = self._current_tag_int(self.comboBeforeTagNo)
 
        occ_text   = self.comboBeforeOccurrence.currentText().strip()
        before_occ = int(occ_text) if occ_text.isdigit() else 1
  
        if not new_tag_text:
            self._qlog("[AddTLV] Enter a New Tag No. (e.g. 0x85).")
            return
        try:
            new_tag_int = int(new_tag_text, 16) if new_tag_text.startswith("0x") else int(new_tag_text)
        except ValueError:
            self._qlog(f"[AddTLV] Invalid tag number: '{new_tag_text}'")
            return
 
        if not self._pdu_bytes:
            self._qlog("[AddTLV] Load a packet first.")
            return
        if before_tag is None:
            self._qlog("[AddTLV] No anchor tag selected.")
            return
 
        # Encode value
        clean = new_val_text.replace(" ", "").replace("0x", "").replace("0X", "")
        try:
            new_val_bytes = bytes.fromhex(clean)
        except ValueError:
            new_val_bytes = new_val_text.encode("ascii", errors="replace")
 
        # Tag class from anchor node
        anchor_nodes  = self._tlv_nodes.get(before_tag, [])
        new_tag_class = anchor_nodes[0]["tag_class"] if anchor_nodes else 2
 
        from tlv_parser1 import insert_tlv_after
 
        old_pdu  = self._pdu_bytes          # save reference BEFORE modifying
        old_size = len(old_pdu)
 
        try:
            new_pdu = insert_tlv_after(
                pdu             = old_pdu,
                after_tag       = before_tag,
                after_occ       = before_occ,
                new_tag         = new_tag_int,
                new_tag_class   = new_tag_class,
                new_constructed = False,
                new_value       = new_val_bytes,
            )
        except ValueError as exc:
            self._qlog(f"[AddTLV ERROR] {exc}")
            return
 
        new_size = len(new_pdu)
        if new_size == old_size:
            self._qlog("[AddTLV WARNING] PDU size unchanged — insertion had no effect.")
            return
 
        # Write back into scapy packet BEFORE updating self._pdu_bytes
        # so _splice_pdu_into_packet can still find the old bytes
        self._splice_pdu_into_packet(old_pdu, new_pdu)
 
        # Now update state
        
        self._pdu_bytes = new_pdu
        self._tlv_nodes = collect_tlv_nodes(parse_all(new_pdu))
        self._populate_tlv_dropdowns()
 
        self._qlog(
            f"[AddTLV] ✓ Inserted 0x{new_tag_int:02X} "
            f"(val={new_val_bytes.hex().upper()}) "
            f"after 0x{before_tag:02X}[occ={before_occ}]. "
        )
        self._qlog("[AddTLV] Tag inserted — dropdowns refreshed.")

    def _splice_pdu_into_packet(self, old_pdu: bytes, new_pdu: bytes):

        from scapy.all import Raw, IP, TCP
 
        if not self._packets:
            return
 
        pkt      = self._packets[self._current_pkt_idx]
        raw_load = bytes(pkt[Raw].load)
 
        pos = raw_load.find(old_pdu)
        if pos == -1:
            self._qlog(
                "[AddTLV WARNING] Could not locate old PDU inside Raw.load — "
                "packet not updated. Try reloading."
            )
            return
 
        # Splice: everything before PDU + new PDU + everything after PDU
        new_raw = raw_load[:pos] + new_pdu + raw_load[pos + len(old_pdu):]
        pkt[Raw].load = new_raw
 
        # Force checksum recalculation on save
        if pkt.haslayer(IP):
            del pkt[IP].chksum
        if pkt.haslayer(TCP):
            del pkt[TCP].chksum
 
        # Update the packet in the list
        self._packets[self._current_pkt_idx] = pkt
        self._qlog(
            f"[AddTLV] Raw.load updated: {len(raw_load)} → {len(new_raw)} bytes."
        )

    # ══════════════════════════════════════════════════════════════════════
    # BUILD args NAMESPACE from UI fields
    # ══════════════════════════════════════════════════════════════════════
    def _build_args_from_ui(self) -> argparse.Namespace:
        pkt_no_text = self.comboPacketNo.currentText().strip()
        pkt_list    = [int(pkt_no_text)] if pkt_no_text.isdigit() else []

        tag_int  = self._current_tag_int(self.comboTagNo)
        val_text = self.lineEditTLVValue.text().strip()
        occ_text = self.comboPositionNo.currentText().strip()

        try:
            val_parsed = (
                int(val_text, 16) if val_text.startswith("0x")
                else int(val_text) if val_text.lstrip("-").isdigit()
                else int.from_bytes(val_text.encode(), "big") if val_text
                else None
            )
        except (ValueError, OverflowError):
            val_parsed = None

        return argparse.Namespace(
            src_ip  = self.lineEditIPSrc.text().strip()  or None,
            dst_ip  = self.lineEditIPDst.text().strip()  or None,
            src_mac = self.lineEditSrcMAC.text().strip() or None,
            dst_mac = self.lineEditDstMAC.text().strip() or None,
            app_id  = self.lineEditAppID.text().strip() or None,
            t       = tag_int,
            v       = val_parsed,
            occ     = int(occ_text) if occ_text.isdigit() else 1,
            pkt     = pkt_list,
            s       = None,
            mod     = self.chkSaveModifiedOnly.isChecked(),
            prt     = False,
            len     = False,   # length-range is now a standalone button
        )

    def _apply_tcp_fields(self, pkt):
        if not pkt.haslayer(TCP):
            return pkt
        tcp = pkt[TCP]

        def _si(text, base=10):
            t = text.strip()
            if not t: return None
            try:
                return int(t, base) if base != 10 else int(t)
            except ValueError:
                return None

        seq   = _si(self.lineEditSeqNo.text())
        ack   = _si(self.lineEditAckNo.text())
        flags = _si(self.lineEditFlags.text(), 16)
        win   = _si(self.lineEditWindowSize.text())
        sport = _si(self.lineEditSrcPort.text())
        dport = _si(self.lineEditDstPort.text())

        if seq   is not None: tcp.seq    = seq
        if ack   is not None: tcp.ack    = ack
        if flags is not None: tcp.flags  = flags
        if win   is not None: tcp.window = win
        if sport is not None: tcp.sport  = sport
        if dport is not None: tcp.dport  = dport

        del pkt[TCP].chksum
        if pkt.haslayer(IP):
            del pkt[IP].chksum
        return pkt

    # ══════════════════════════════════════════════════════════════════════
    # SAVE PCAP  — main thread only, no QThread
    # ══════════════════════════════════════════════════════════════════════
    def _on_save_pcap(self):
        if not self._packets:
            self._qlog("[Save] No packets loaded.")
            return

        out_name = self.lineEditOutputFile.text().strip() or "output.pcap"
        out_path, _ = QFileDialog.getSaveFileName(
            self, "Save PCAP", out_name,
            "PCAP files (*.pcap);;All files (*)"
        )
        if not out_path:
            return
        # Ensure .pcap extension so Wireshark recognises it
        if not out_path.lower().endswith((".pcap", ".pcapng")):
            out_path += ".pcap"

        args     = self._build_args_from_ui()
        mod_only = self.chkSaveModifiedOnly.isChecked()
        pkt_nos  = set(args.pkt) if args.pkt else set(range(1, len(self._packets) + 1))

        self._log(f"[Save] Writing → {out_path} ...")
        QCoreApplication.processEvents()   # let the UI repaint before blocking

        try:
            writer = PcapWriter(out_path, sync=True)

            for idx, pkt in enumerate(self._packets, start=1):
                should_mod = idx in pkt_nos

                if should_mod:
                    pkt = self._apply_tcp_fields(pkt)
                    # Apply IP / MAC / TLV changes via backend
                    from main_sniffer import process_packet
                    pkt = process_packet(pkt, args, {})

                if mod_only and not should_mod:
                    continue

                writer.write(pkt)

            writer.close()
            self._log(f"[Save] ✓ Saved {out_path}")
            self._qlog(f"[Save] Done → {out_path}")

        except Exception as exc:
            self._qlog(f"[Save ERROR] {exc}")

    # ══════════════════════════════════════════════════════════════════════
    # SAVE WHOLE TCP  — main thread only
    # ══════════════════════════════════════════════════════════════════════
    def _on_save_whole_tcp(self):
        if not self._packets:
            self._qlog("[SaveTCP] No packets loaded.")
            return
        if self.comboPacketType.currentText() != "MMS":
            self._qlog("[SaveTCP] MMS only.")
            return
 
        out_name = self.lineEditOutputFile.text().strip() or "output_tcp.pcap"
        out_path, _ = QFileDialog.getSaveFileName(
            self, "Save Whole TCP Structure", out_name,
            "PCAP files (*.pcap);;All files (*)"
        )
        if not out_path:
            return
        if not out_path.lower().endswith((".pcap", ".pcapng")):
            out_path += ".pcap"
 
        ref = self._packets[self._current_pkt_idx]
        if not (ref.haslayer(IP) and ref.haslayer(TCP)):
            self._qlog("[SaveTCP] Selected packet has no TCP layer.")
            return
 
        # ── Original 4-tuple of the session (BEFORE any UI edits) ─────────────
        orig_src_ip  = ref[IP].src
        orig_dst_ip  = ref[IP].dst
        orig_sport   = ref[TCP].sport
        orig_dport   = ref[TCP].dport
 
        orig_fwd_key = (orig_src_ip, orig_dst_ip, orig_sport, orig_dport)
        orig_rev_key = (orig_dst_ip, orig_src_ip, orig_dport, orig_sport)
 
        # ── New values from UI (None = no change) ─────────────────────────────
        def _safe_int(text):
            t = text.strip()
            return int(t) if t.isdigit() else None
 
        new_src_ip = self.lineEditIPSrc.text().strip()   or None
        new_dst_ip = self.lineEditIPDst.text().strip()   or None
        new_sport  = _safe_int(self.lineEditSrcPort.text())
        new_dport  = _safe_int(self.lineEditDstPort.text())
        new_src_mac = self.lineEditSrcMAC.text().strip() or None
        new_dst_mac = self.lineEditDstMAC.text().strip() or None
        new_ttl     = _safe_int(self.lineEditTTL.text())
 
        # ── TLV / args (only applied to the selected packet number) ───────────
        args    = self._build_args_from_ui()
        pkt_nos = set(args.pkt) if args.pkt else set()
 
        self._log(f"[SaveTCP] Extracting + forging session → {out_path} ...")
        QCoreApplication.processEvents()
 
        try:
            writer = PcapWriter(out_path, sync=True)
            count  = 0
 
            for idx, pkt in enumerate(self._packets, start=1):
                if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                    continue
 
                pkt_key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
 
                # Determine direction: forward (same as ref) or reverse
                is_fwd = (pkt_key == orig_fwd_key)
                is_rev = (pkt_key == orig_rev_key)
 
                if not (is_fwd or is_rev):
                    continue   # not part of this TCP session
 
                # ── Clone so we don't mutate self._packets ─────────────────────
                from scapy.all import Ether
                pkt = pkt.copy()
 
                # ── MAC (same on every packet regardless of direction) ─────────
                if pkt.haslayer(Ether):
                    if new_src_mac:
                        pkt[Ether].src = new_src_mac
                    if new_dst_mac:
                        pkt[Ether].dst = new_dst_mac
 
                # ── IP fields — mirror direction ───────────────────────────────
                # Forward packet:  src→new_src_ip,  dst→new_dst_ip
                # Reverse packet:  src→new_dst_ip,  dst→new_src_ip  (flipped)
                if is_fwd:
                    if new_src_ip: pkt[IP].src = new_src_ip
                    if new_dst_ip: pkt[IP].dst = new_dst_ip
                else:  # reverse direction
                    if new_dst_ip: pkt[IP].src = new_dst_ip   # reversed
                    if new_src_ip: pkt[IP].dst = new_src_ip   # reversed
 
                if new_ttl is not None:
                    pkt[IP].ttl = new_ttl
 
                # ── TCP ports — mirror direction ───────────────────────────────
                if is_fwd:
                    if new_sport is not None: pkt[TCP].sport = new_sport
                    if new_dport is not None: pkt[TCP].dport = new_dport
                else:  # reverse direction
                    if new_dport is not None: pkt[TCP].sport = new_dport  # reversed
                    if new_sport is not None: pkt[TCP].dport = new_sport  # reversed
 
                # ── TCP control fields — only on selected packet ───────────────
                if idx in pkt_nos:
                    pkt = self._apply_tcp_fields(pkt)
 
                # ── TLV / payload changes — only on selected packet ────────────
                if idx in pkt_nos and (args.t is not None and args.v is not None):
                    from main_sniffer import process_packet
                    pkt = process_packet(pkt, args, {})
 
                # ── Recompute checksums ────────────────────────────────────────
                del pkt[IP].chksum
                del pkt[TCP].chksum
 
                writer.write(pkt)
                count += 1
 
            writer.close()
            self._log(f"[SaveTCP] ✓ {count} packet(s) → {out_path}")
            self._qlog(f"[SaveTCP] Done → {out_path}")
 
        except Exception as exc:
            self._qlog(f"[SaveTCP ERROR] {exc}")
    # ══════════════════════════════════════════════════════════════════════
    # PRINT TLV
    # ══════════════════════════════════════════════════════════════════════
    def _on_print_tlv(self):
        if not self._pdu_bytes:
            self._qlog("[PrintTLV] Load a packet first.")
            return

        pkt = self._packets[self._current_pkt_idx] if self._packets else None

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            try:
                if self._pdu_type == "MMS" and pkt:
                    from mms_handler import handle_mms
                    handle_mms(pkt)
                elif self._pdu_type == "GOOSE" and pkt:
                    from goose_handler import handle_goose
                    handle_goose(pkt)
                elif self._pdu_type == "SV" and pkt:
                    from sv_handler import handle_sv
                    handle_sv(pkt)
                else:
                    self._print_tlv_tree(parse_all(self._pdu_bytes))
            except Exception as exc:
                print(f"[PrintTLV ERROR] {exc}")

        out = buf.getvalue()
        if out.strip():
            self._log(out)
        else:
            self._log("[PrintTLV] --- TLV Tree ---")
            self._print_tlv_tree(parse_all(self._pdu_bytes))
            self._log("[PrintTLV] --- End ---")

        self._qlog(f"[PrintTLV] Printed {self._pdu_type} PDU.")

    def _print_tlv_tree(self, tlvs, indent: int = 0):
        prefix = "  " * indent
        nodes  = tlvs if isinstance(tlvs, list) else [tlvs]
        for node in nodes:
            tag  = node["tag_number"]
            cons = node["constructed"]
            if cons:
                self._log(f"{prefix}[0x{tag:02X}] <constructed>")
                self._print_tlv_tree(node["value"], indent + 1)
            else:
                self._log(f"{prefix}[0x{tag:02X}] = {node_value_display(node)}")

    # ══════════════════════════════════════════════════════════════════════
    # ABOUT
    # ══════════════════════════════════════════════════════════════════════
    def _on_about(self):
        QMessageBox.information(
            self, "About",
            textwrap.dedent("""\
                AIUS v1.0 — [Attack & Intrusion Utility Suite - IEC61850]
                ─────────────────────────────────────────────────────
                Developed by:
                Ayush Chand Ramola

                Concept Designer:
                Kishan Baranwal

                Co-Guide:
                Rakshit R.

                Under Supervision of:
                Prof. Haresh Dagale

                Sponsored by PGCoE — POWERGRID Centre of Excellence in Cybersecurity
            """)
        )

def closeEvent(self, event):
    # Clean up Redis server + any running MITM worker on window close.
    import redis_ts
 
    # Stop auto-started Redis server (no-op if we didn't start it)
    redis_ts.stop_server()
 
    # Stop MITM worker if running
    if hasattr(self, "mitm_tab") and self.mitm_tab._worker:
        try:
            self.mitm_tab._worker.stop()
            self.mitm_tab._worker.wait(2000)   # wait up to 2s
        except Exception:
            pass
 
    event.accept()
    
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import sys
    import redis_ts
    from PyQt5.QtWidgets import QApplication
 
    app = QApplication(sys.argv)
 
    # Ensure Redis server is stopped even if the window is closed
    # via the OS (Alt-F4, taskbar close, etc.) rather than the X button
    app.aboutToQuit.connect(redis_ts.stop_server)
 
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
