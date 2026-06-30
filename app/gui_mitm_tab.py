
from __future__ import annotations
import os
import subprocess
import threading
from pathlib import Path
from typing import Optional

from PyQt5 import QtCore, QtWidgets, uic
from PyQt5.QtWidgets import (
    QMainWindow, QApplication, QFileDialog, QMessageBox,
    QScrollArea, QWidget, QVBoxLayout
)
from PyQt5.QtCore import Qt, QCoreApplication, QThread, pyqtSignal


# ─────────────────────────────────────────────────────────────────────────────
# Log signal bridge — emits from any thread to GUI thread
# ─────────────────────────────────────────────────────────────────────────────

class LogEmitter(QtCore.QObject):
    log_signal = QtCore.pyqtSignal(str)

# ─────────────────────────────────────────────────────────────────────────────
# Old pcap loading thread- Qthread worker
# ─────────────────────────────────────────────────────────────────────────────

class PcapLoaderThread(QThread):
        log_signal = pyqtSignal(str)

        def __init__(self, path):
            super().__init__()
            self.path = path

        def run(self):
            try:
                import json_writer, redis_ts
                from scapy.all import rdpcap, TCP

                records = []
                pkts = rdpcap(self.path)

                for pkt in pkts:
                    if not pkt.haslayer(TCP):
                        continue

                    tcp = pkt[TCP]
                    if tcp.sport != 102 and tcp.dport != 102:
                        continue

                    raw_payload = bytes(tcp.payload)

                    rec = json_writer.pkt_to_json(
                        raw_payload,
                        str(pkt["IP"].src) if pkt.haslayer("IP") else "0.0.0.0",
                        str(pkt["IP"].dst) if pkt.haslayer("IP") else "0.0.0.0",
                        tcp.sport, tcp.dport,
                    )

                    if rec:
                        rec["ts_ms"] = int(float(pkt.time) * 1000)
                        records.append(rec)

                logs = redis_ts.store_old_pcap_values(records)

                self.log_signal.emit(logs)

            except Exception as e:
                self.log_signal.emit(f"[Redis] Old PCAP load error: {e}")
                
# ─────────────────────────────────────────────────────────────────────────────
# MITM Worker — runs start_mitm() in a QThread (blocking NFQ loop)
# ─────────────────────────────────────────────────────────────────────────────

class MitmWorker(QtCore.QThread):
    log_signal = QtCore.pyqtSignal(str)
    finished = QtCore.pyqtSignal()

    def __init__(self, victim_ip: str, server_ip: str, iface: str,
                 queue_num: int = 1, mms_port: int = 102, parent=None):
        super().__init__(parent)
        self.victim_ip = victim_ip
        self.server_ip = server_ip
        self.iface = iface
        self.queue_num = queue_num
        self.mms_port = mms_port
        self._running = True

    def _log(self, msg: str) -> None:
        self.log_signal.emit(msg)

    def run(self) -> None:
        try:
            import mitm
            mitm.start_mitm(
                victim_ip=self.victim_ip,
                server_ip=self.server_ip,
                iface=self.iface,
                queue_num=self.queue_num,
                mms_port=self.mms_port,
                log_cb=self._log,
            )
        except Exception as e:
            self._log(f"[MITM] Worker error: {e}")
        finally:
            self.finished.emit()

    def stop(self) -> None:
        try:
            import mitm
            mitm.stop_mitm(
                queue_num=self.queue_num,
                mms_port=self.mms_port,
                log_cb=self._log,
            )
        except Exception as e:
            self._log(f"[MITM] Stop error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Live MITM Tab Widget
# ─────────────────────────────────────────────────────────────────────────────

class LiveMitmTab(QWidget):
    #Self-contained 'Live MITM' tab — added to existing tabWidget.

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker: Optional[MitmWorker] = None
        self._build_ui()
        self._connect_signals()
        self._refresh_interfaces()

    # ── UI construction ──────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QtWidgets.QVBoxLayout(self)
        root.setSpacing(8)
        root.setContentsMargins(8, 8, 8, 8)

        # ── Top: Controls + Log side by side ──
        top_row = QtWidgets.QHBoxLayout()
        top_row.setSpacing(8)
        top_row.addWidget(self._build_controls_group(), stretch=0)
        top_row.addWidget(self._build_attack_group(), stretch=0)
        top_row.addWidget(self._build_log_group(), stretch=1)
        root.addLayout(top_row)

    def _build_controls_group(self) -> QtWidgets.QGroupBox:
        grp = QtWidgets.QGroupBox("MITM Controls")
        form = QtWidgets.QFormLayout(grp)
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(8)

        # Interface
        self.comboIface = QtWidgets.QComboBox()
        self.comboIface.setToolTip("Network interface for ARP poisoning + packet replay")
        form.addRow("Target Interface", self.comboIface)

        # Victim IP
        self.lineVictimIP = QtWidgets.QLineEdit()
        self.lineVictimIP.setPlaceholderText("e.g. 192.168.1.10")
        self.lineVictimIP.setToolTip("IP address of the IED (victim)")
        form.addRow("Victim IP", self.lineVictimIP)

        # Server IP
        self.lineServerIP = QtWidgets.QLineEdit()
        self.lineServerIP.setPlaceholderText("e.g. 192.168.1.1")
        self.lineServerIP.setToolTip("IP address of the MMS server / RTU")
        form.addRow("Server IP", self.lineServerIP)

        # MMS Port
        self.spinMmsPort = QtWidgets.QSpinBox()
        self.spinMmsPort.setRange(1, 65535)
        self.spinMmsPort.setValue(102)
        self.spinMmsPort.setToolTip("MMS TCP port (default 102)")
        form.addRow("MMS Port", self.spinMmsPort)

        # NFQueue number
        self.spinQueueNum = QtWidgets.QSpinBox()
        self.spinQueueNum.setRange(0, 65535)
        self.spinQueueNum.setValue(1)
        self.spinQueueNum.setToolTip("NFQUEUE queue number (must match iptables rule)")
        form.addRow("Queue No.", self.spinQueueNum)

        # Separator
        form.addRow(self._hsep())

        # Establish / Stop buttons
        btn_row = QtWidgets.QHBoxLayout()
        self.btnEstablish = QtWidgets.QPushButton("▶  Establish MITM")
        self.btnEstablish.setObjectName("btnEstablishMITM")
        self.btnEstablish.setToolTip(
            "Enables IP forwarding, starts ARP poisoning, inserts iptables rule, binds NFQueue"
        )
        self.btnStop = QtWidgets.QPushButton("■  Stop MITM")
        self.btnStop.setObjectName("btnStopMITM")
        self.btnStop.setEnabled(False)
        btn_row.addWidget(self.btnEstablish)
        btn_row.addWidget(self.btnStop)
        form.addRow(btn_row)

        # Redis
        form.addRow(self._hsep())
        redis_row = QtWidgets.QHBoxLayout()
        self.lineRedis = QtWidgets.QLineEdit("127.0.0.1:6379")
        self.lineRedis.setToolTip("Redis host:port")
        self.btnRedis = QtWidgets.QPushButton("🔌  Connect Redis")
        self.btnRedis.setObjectName("btnConnectRedis")
        redis_row.addWidget(self.lineRedis)
        redis_row.addWidget(self.btnRedis)
        form.addRow("Redis Host:Port", redis_row)

        # Redis status label
        self.lblRedisStatus = QtWidgets.QLabel("Not connected")
        self.lblRedisStatus.setStyleSheet("color: #da3633; font-size: 10px;")
        form.addRow("", self.lblRedisStatus)

        return grp

    def _build_attack_group(self) -> QtWidgets.QGroupBox:
        grp = QtWidgets.QGroupBox("Attack Mode")
        form = QtWidgets.QFormLayout(grp)
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(8)

        # Attack mode combo
        self.comboAttackMode = QtWidgets.QComboBox()
        self.comboAttackMode.addItems([
            "forward", "forward_copy", "delay_forward",
            "drop", "shuffle", "keepalive", "replace", "modify",
        ])
        self.comboAttackMode.setToolTip("Attack operation applied to each intercepted MMS packet")
        form.addRow("Attack Mode", self.comboAttackMode)

        # Delay
        self.spinDelay = QtWidgets.QSpinBox()
        self.spinDelay.setRange(0, 5000)
        self.spinDelay.setSuffix(" ms")
        self.spinDelay.setToolTip("Delay before replay (delay_forward mode only)")
        form.addRow("Delay", self.spinDelay)

        # Shuffle buffer N
        self.spinShuffleN = QtWidgets.QSpinBox()
        self.spinShuffleN.setRange(2, 50)
        self.spinShuffleN.setValue(5)
        self.spinShuffleN.setToolTip("Buffer this many packets before shuffling (shuffle mode only)")
        form.addRow("Shuffle Buffer N", self.spinShuffleN)

        form.addRow(self._hsep())

        # Target Tag No (live-populated from JSON store)
        self.comboTargetTag = QtWidgets.QComboBox()
        self.comboTargetTag.setEditable(True)
        self.comboTargetTag.setToolTip(
            "TLV tag to target. Populated from live_packets.json after packets arrive. "
            "Also manually editable (hex e.g. 0x85)."
        )
        self.btnRefreshTags = QtWidgets.QPushButton("↻")
        self.btnRefreshTags.setMaximumWidth(30)
        self.btnRefreshTags.setToolTip("Refresh tag list from live_packets.json")
        tag_row = QtWidgets.QHBoxLayout()
        tag_row.addWidget(self.comboTargetTag)
        tag_row.addWidget(self.btnRefreshTags)
        form.addRow("Target Tag No.", tag_row)

        # Occurrence
        self.spinTargetOcc = QtWidgets.QSpinBox()
        self.spinTargetOcc.setRange(1, 999)
        self.spinTargetOcc.setValue(1)
        self.spinTargetOcc.setToolTip("Which occurrence of the target tag to forge (1-based)")
        form.addRow("Occurrence", self.spinTargetOcc)

        # New value
        self.lineNewValue = QtWidgets.QLineEdit()
        self.lineNewValue.setPlaceholderText("hex value e.g. 0x0FA0 or 03E8")
        self.lineNewValue.setToolTip("Replacement value for modify / forge (hex string)")
        form.addRow("New Value", self.lineNewValue)

        form.addRow(self._hsep())

        # Old PCAP (for replace mode)
        old_pcap_row = QtWidgets.QHBoxLayout()
        self.lineOldPcap = QtWidgets.QLineEdit()
        self.lineOldPcap.setPlaceholderText("Path to reference .pcap")
        self.lineOldPcap.setToolTip("Passive PCAP used as historical reference for 'replace' attack")
        self.btnOldPcap = QtWidgets.QPushButton("Browse")
        self.btnOldPcap.setMaximumWidth(60)
        old_pcap_row.addWidget(self.lineOldPcap)
        old_pcap_row.addWidget(self.btnOldPcap)
        form.addRow("Old PCAP (replace)", old_pcap_row)

        self.btnLoadOldPcap = QtWidgets.QPushButton("Load Old PCAP → Redis")
        self.btnLoadOldPcap.setToolTip("Parse old PCAP and store TLV values in Redis old:* keys")
        form.addRow("", self.btnLoadOldPcap)

        form.addRow(self._hsep())

        # Apply button
        self.btnApply = QtWidgets.QPushButton("⚡  Apply Attack Params")
        self.btnApply.setObjectName("btnApplyAttack")
        self.btnApply.setToolTip("Push current mode + params to the live NFQueue handler")
        form.addRow(self.btnApply)

        return grp

    def _build_log_group(self) -> QtWidgets.QGroupBox:
        grp = QtWidgets.QGroupBox("Live Packet Log")
        vbox = QtWidgets.QVBoxLayout(grp)

        hdr = QtWidgets.QHBoxLayout()
        hdr.addStretch()
        self.btnClearMitmLog = QtWidgets.QPushButton("Clear")
        self.btnClearMitmLog.setMaximumWidth(60)
        self.btnClearMitmLog.setObjectName("btnClearMitmLog")
        hdr.addWidget(self.btnClearMitmLog)
        vbox.addLayout(hdr)

        self.mitmLog = QtWidgets.QTextEdit()
        self.mitmLog.setObjectName("terminalBox")   # picks up existing terminal stylesheet
        self.mitmLog.setReadOnly(True)
        self.mitmLog.setPlaceholderText(
            "[IEC61850 MITM] Idle. Configure MITM Controls and click Establish MITM.\n"
        )
        vbox.addWidget(self.mitmLog)
        return grp

    @staticmethod
    def _hsep() -> QtWidgets.QFrame:
        line = QtWidgets.QFrame()
        line.setFrameShape(QtWidgets.QFrame.Shape.HLine)
        line.setStyleSheet("color: #30363d;")
        return line

    # ── Signal wiring ────────────────────────────────────────────────────────

    def _connect_signals(self) -> None:
        self.btnEstablish.clicked.connect(self._on_establish)
        self.btnStop.clicked.connect(self._on_stop)
        self.btnRedis.clicked.connect(self._on_connect_redis)
        self.btnApply.clicked.connect(self._on_apply_attack)
        self.btnRefreshTags.clicked.connect(self._refresh_live_tags)
        self.btnClearMitmLog.clicked.connect(self.mitmLog.clear)
        self.btnOldPcap.clicked.connect(self._browse_old_pcap)
        self.btnLoadOldPcap.clicked.connect(self._load_old_pcap_to_redis)

    # ── Interface list ────────────────────────────────────────────────────────

    def _refresh_interfaces(self) -> None:
        #Populate interface combo from /sys/class/net.
        self.comboIface.clear()
        try:
            ifaces = os.listdir("/sys/class/net")
            self.comboIface.addItems(sorted(ifaces))
        except Exception:
            self.comboIface.addItems(["eth0", "eth1", "wlan0"])

    # ── MITM Establish / Stop ─────────────────────────────────────────────────

    def _on_establish(self) -> None:
        victim = self.lineVictimIP.text().strip()
        server = self.lineServerIP.text().strip()
        iface = self.comboIface.currentText().strip()

        if not victim or not server or not iface:
            QtWidgets.QMessageBox.warning(
                self, "Missing fields",
                "Please fill Victim IP, Server IP, and select an interface."
            )
            return

        self._log(f"[MITM] Establishing MITM: victim={victim} server={server} iface={iface}")
        self.btnEstablish.setEnabled(False)
        self.btnStop.setEnabled(True)

        self._worker = MitmWorker(
            victim_ip=victim,
            server_ip=server,
            iface=iface,
            queue_num=self.spinQueueNum.value(),
            mms_port=self.spinMmsPort.value(),
            parent=self,
        )
        self._worker.log_signal.connect(self._log)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.start()

    def _on_stop(self) -> None:
        if self._worker:
            self._worker.stop()
        self.btnStop.setEnabled(False)
        self.btnEstablish.setEnabled(True)

    def _on_worker_finished(self) -> None:
        self._log("[MITM] Worker thread finished")
        self.btnStop.setEnabled(False)
        self.btnEstablish.setEnabled(True)

    # ── Redis ─────────────────────────────────────────────────────────────────

    def _on_connect_redis(self) -> None:
        addr = self.lineRedis.text().strip()
        try:
            host, port_s = addr.rsplit(":", 1)
            port = int(port_s)
        except ValueError:
            host, port = "127.0.0.1", 6379

        import redis_ts
        ok, msg = redis_ts.connect(host, port)
        self._log(f"[Redis] {msg}")
        if ok:
            self.lblRedisStatus.setText(f"● Connected — {host}:{port}")
            self.lblRedisStatus.setStyleSheet("color: #3fb950; font-size: 10px;")
        else:
            self.lblRedisStatus.setText("✗ Not connected")
            self.lblRedisStatus.setStyleSheet("color: #da3633; font-size: 10px;")

    # ── Attack params apply ───────────────────────────────────────────────────

    def _on_apply_attack(self) -> None:
        import attack_engine

        tag_text = self.comboTargetTag.currentText().strip().replace("0x", "")
        try:
            tag_int = int(tag_text, 16)
        except ValueError:
            tag_int = 0x85

        new_val = self.lineNewValue.text().strip().replace("0x", "").replace(" ", "")

        attack_engine.update_params(
            mode=self.comboAttackMode.currentText(),
            delay_ms=self.spinDelay.value(),
            shuffle_n=self.spinShuffleN.value(),
            target_tag=tag_int,
            target_occurrence=self.spinTargetOcc.value(),
            new_value_hex=new_val,
            iface=self.comboIface.currentText(),
        )
        self._log(
            f"[ATTACK] Mode={self.comboAttackMode.currentText()} "
            f"tag=0x{tag_int:02X} occ={self.spinTargetOcc.value()} "
            f"new_value={new_val or '(n/a)'} "
            f"delay={self.spinDelay.value()}ms "
            f"shuffle_n={self.spinShuffleN.value()}"
        )

    # ── Tag refresh from live JSON ────────────────────────────────────────────

    def _refresh_live_tags(self) -> None:
        try:
            import json_writer
            records = json_writer.load_json_store()
            tags = json_writer.unique_tags_from_records(records)
            current = self.comboTargetTag.currentText()
            self.comboTargetTag.clear()
            self.comboTargetTag.addItems(tags)
            # restore previous selection if still valid
            idx = self.comboTargetTag.findText(current)
            if idx >= 0:
                self.comboTargetTag.setCurrentIndex(idx)
            self._log(f"[GUI] Tag list refreshed — {len(tags)} unique tags from live_packets.json")
        except Exception as e:
            self._log(f"[GUI] Tag refresh error: {e}")

    # ── Old PCAP browse + load ────────────────────────────────────────────────

    def _browse_old_pcap(self) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select Reference PCAP", "", "PCAP Files (*.pcap *.pcapng);;All Files (*)"
        )
        if path:
            self.lineOldPcap.setText(path)
            
            
    def _load_old_pcap_to_redis(self) -> None:
        path = self.lineOldPcap.text().strip()
        if not path:
            self._log("[Redis] No old PCAP path set")
            return

        self._log(f"[Redis] Loading old PCAP: {path}")
        
        self.loader_thread = PcapLoaderThread(path)
        self.loader_thread.log_signal.connect(self._log)
        self.loader_thread.start()
       
           
             

    # ── Log ───────────────────────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        #Append message to MITM log (thread-safe via queued connection).
        self.mitmLog.append(msg)
        self.mitmLog.verticalScrollBar().setValue(
            self.mitmLog.verticalScrollBar().maximum()
        )


# ─────────────────────────────────────────────────────────────────────────────
# Injection helper — call this after uic.loadUi()
# ─────────────────────────────────────────────────────────────────────────────

def inject_mitm_tab(main_window: QtWidgets.QMainWindow) -> LiveMitmTab:

    #Add the Live MITM tab to the existing tabWidget.
    #Returns the LiveMitmTab instance so you can reference it if needed.

    tab = LiveMitmTab()
    main_window.tabWidget.addTab(tab, "Live MITM")

    # Apply same dark stylesheet so it matches existing tabs
    tab.setStyleSheet(main_window.styleSheet())

    # Wire the quick log at the bottom to also show MITM messages
    if hasattr(main_window, "quickTerminal"):
        tab.mitmLog.textChanged.connect(
            lambda: main_window.quickTerminal.append(
                tab.mitmLog.toPlainText().split("\n")[-1]
            )
        )

    return tab
