#!/usr/bin/env python3
"""
gui/main_window.py — RubyFi Main Window (clean orchestrator only).

Attack logic lives in:
    gui/deauth_dialog.py    → DeauthMixin    (DeauthThread, ClientScanThread, DeauthDialog, ClientSelectionDialog)
    gui/evil_twin_dialog.py → EvilTwinMixin  (EvilTwinThread, EvilTwinDialog)
    gui/handshake_dialog.py → HandshakeCaptureThread, HandshakeModeDialog
    gui/wps_dialog.py       → WPSAttackThread, WPSModeDialog
"""

import sys
import os
import subprocess
import tempfile
import time
from datetime import datetime
from typing import Optional
from PyQt5.QtWidgets import QFrame, QGridLayout
from gui.beacon_flood_dialog import BeaconFloodMixin
from gui.wifi_phishing_dialog import WiFiPhishingMixin

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTextEdit, QProgressBar, QStatusBar,
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QDialog, QMessageBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QColor, QBrush

from gui.styles import DARK_THEME
from gui.interface_dialog import InterfaceDialog

# Attack-specific GUI modules (all stay inside gui/)
from gui.deauth_dialog import DeauthMixin
from gui.evil_twin_dialog import EvilTwinMixin
from gui.handshake_dialog import HandshakeCaptureThread, HandshakeModeDialog
from gui.wps_dialog import WPSAttackThread, WPSModeDialog
from gui.deauth_dialog import ClientSelectionDialog   # reused by handshake "manual" mode

# CLI attack back-ends
from attacks.deauth import DeauthAttack
from attacks.handshake import HandshakeCapture
from attacks.evil_twin_deauth import EvilTwinDeauth
from attacks.wps_attack import WPSAttack
from utils.scan_networks import WiFiScanner


# ═══════════════════════════════════════════════════════════════
# SCAN THREAD
# ═══════════════════════════════════════════════════════════════

class ScanThread(QThread):
    """Background thread for network scanning."""
    network_found   = pyqtSignal(dict)
    scan_complete   = pyqtSignal(int)
    progress_update = pyqtSignal(int, str)
    error_occurred  = pyqtSignal(str)

    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.running = True

    def run(self):
        try:
            self.progress_update.emit(10, "Starting airodump-ng...")
            temp_dir = tempfile.mkdtemp()
            output_file = os.path.join(temp_dir, "scan")

            cmd = [
                'airodump-ng',
                '--output-format', 'csv',
                '--write', output_file,
                '--band', 'abg',
                self.interface
            ]

            self.progress_update.emit(20, "Launching airodump-ng...")
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.progress_update.emit(30, "Scanning networks...")

            csv_file = f"{output_file}-01.csv"
            scan_count = 0
            found_networks = {} # Change to a dictionary to store the full network objects

            while self.running:
                time.sleep(2)
                if os.path.exists(csv_file):
                    networks = self.parse_csv(csv_file)
                    for network in networks:
                        bssid = network['bssid']
                        if bssid not in found_networks:
                            found_networks[bssid] = network
                            self.network_found.emit(network)
                    
                    progress = min(30 + (len(found_networks) * 2), 95)
                    self.progress_update.emit(progress, f"Scanning... {len(found_networks)} networks found")

            # Final check after stopping
            if os.path.exists(csv_file):
                final_nets = self.parse_csv(csv_file)
                for net in final_nets:
                    if net['bssid'] not in found_networks:
                        self.network_found.emit(net)
            
            self.scan_complete.emit(len(found_networks))
            self.progress_update.emit(100, f"✅ Scan stopped - {len(found_networks)} networks")
            os.system(f"rm -rf {temp_dir}")

        except Exception as e:
            self.error_occurred.emit(f"Scan error: {str(e)}")
            self.progress_update.emit(100, f"Error: {e}")

    def parse_csv(self, csv_file):
        networks = {}
        clients_per_ap = {}
        try:
            if not os.path.exists(csv_file):
                return []
            if os.path.getsize(csv_file) < 10:
                return []

            with open(csv_file, 'r', errors='ignore') as f:
                lines = f.readlines()

            if len(lines) < 5:
                return []

            ap_start = station_start = -1
            for i, line in enumerate(lines):
                if 'BSSID' in line and 'ESSID' in line and ap_start == -1:
                    ap_start = i + 1
                elif 'Station MAC' in line:
                    station_start = i + 1
                    break

            if ap_start == -1:
                return list(networks.values())

            for line in lines[ap_start:station_start if station_start != -1 else len(lines)]:
                if not line.strip() or 'Station MAC' in line:
                    break
                parts = [p.strip() for p in line.split(',')]
                if len(parts) < 14:
                    continue
                bssid = parts[0]
                if not bssid or ':' not in bssid or len(bssid) != 17:
                    continue
                if bssid in networks:
                    continue

                channel    = parts[3].strip() or "0"
                power      = parts[8].strip() or "-100"
                encryption = parts[5].strip()
                ssid       = parts[13].strip() if len(parts) > 13 else ""

                is_5ghz = False
                try:
                    is_5ghz = int(channel) > 14
                except Exception:
                    pass

                clients_per_ap.setdefault(bssid, 0)
                if ssid == "" or ssid.lower() == "<hidden>":
                    ssid = "<Hidden SSID>"
                networks[bssid] = {
                    'ssid': ssid, 'bssid': bssid,
                    'channel': channel, 'power': power,
                    'encryption': encryption, 'clients': '0',
                    'is_5ghz': is_5ghz, 'wps': 'WPS' in encryption
                }

            if station_start != -1:
                for line in lines[station_start:]:
                    if not line.strip():
                        continue
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) < 6:
                        continue
                    client_bssid = parts[5].strip()
                    if not client_bssid or client_bssid == '(not associated)' or ':' not in client_bssid:
                        continue
                    if client_bssid in clients_per_ap:
                        clients_per_ap[client_bssid] += 1

            for bssid, count in clients_per_ap.items():
                if bssid in networks:
                    networks[bssid]['clients'] = str(count)

            return list(networks.values())

        except Exception as e:
            print(f"Parse error: {e}")
            return []

    def stop(self):
        self.running = False


# ═══════════════════════════════════════════════════════════════
# MAIN WINDOW
# ═══════════════════════════════════════════════════════════════

class RubyFiWindow(DeauthMixin, EvilTwinMixin,BeaconFloodMixin, WiFiPhishingMixin, QMainWindow):
    """
    Main RubyFi GUI Window.

    Layout:  Header → Interface Status → Toolbar → [Table | Log] → ProgressBar
    Attacks: routed via show_attack_menu() → handle_attack_selection()
             Each attack delegates to its Mixin or helper module.
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔥 RubyFi - WiFi Security Toolkit")
        self.setGeometry(50, 50, 1400, 900)
        self.setStyleSheet(DARK_THEME)

        self.current_interface: Optional[str] = None
        self.current_mode = "None"
        self.selected_target = None
        self.scan_thread: Optional[ScanThread] = None

        self.init_ui()
        self._auto_detect_monitor_interface()

        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self.animate_progress)
        self.progress_value = 0

    # ── UI construction ──────────────────────────────────────────
    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(10)

        # Header
        header = QLabel("🔥 RUBYFI - Advanced Red Team WiFi Toolkit 🔥")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("""
font-size:24px; font-weight:bold; color:#ff006e;
margin:10px; padding:10px; border-bottom:2px solid #30363d;
""")
        main_layout.addWidget(header)

        main_layout.addWidget(self.create_interface_status())
        main_layout.addWidget(self.create_workflow_bar())
        main_layout.addWidget(self.create_stats_bar())
        main_layout.addLayout(self.create_toolbar())


        # Splitter: table (top) + log (bottom)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(3)
        splitter.setStyleSheet("QSplitter::handle { background:#30363d; }")

        table_widget = QWidget()
        table_layout = QVBoxLayout(table_widget)
        table_layout.setContentsMargins(0, 0, 0, 0)

        table_header = QHBoxLayout()
        table_label = QLabel("📡 Discovered Networks")
        table_label.setStyleSheet("color:#00ff88; font-weight:bold; font-size:14px;")
        table_header.addWidget(table_label)

        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.setMaximumWidth(100)
        self.refresh_btn.clicked.connect(self.start_scan)
        table_header.addWidget(self.refresh_btn)

        table_layout.addLayout(table_header)

        self.dashboard = self.create_dashboard()
        table_layout.addWidget(self.dashboard)

        self.network_table = self.create_network_table()
        table_layout.addWidget(self.network_table)

        splitter.addWidget(table_widget)

        log_widget = QWidget()
        log_layout = QVBoxLayout(log_widget)
        log_layout.setContentsMargins(0, 0, 0, 0)
        log_label = QLabel("📋 Live Activity Log")
        log_label.setStyleSheet("color:#00ff88; font-weight:bold; font-size:14px;")
        log_layout.addWidget(log_label)
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        log_layout.addWidget(self.log_view)
        splitter.addWidget(log_widget)
        splitter.setSizes([550, 200])
        main_layout.addWidget(splitter)

        # Progress bar
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setFormat("Ready")
        self.progress.setTextVisible(True)
        main_layout.addWidget(self.progress)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.update_status()

        self.log("✅ RubyFi GUI initialized successfully")
        self.log("🔧 Start: Manage Interface → Enable Monitor Mode")
        self.log("📡 Then: Scan Networks → Select Target → Launch Attack")

    def create_interface_status(self):
        widget = QWidget()
        widget.setStyleSheet("""
QWidget { background:#161b22; border:2px solid #30363d; border-radius:8px; padding:10px; }
""")
        layout = QHBoxLayout(widget)
        self.iface_label  = QLabel("🔌 Interface: Not Selected")
        self.target_label = QLabel("🎯 Target: None")
        for label in [self.iface_label, self.target_label]:
            label.setStyleSheet("color:#c9d1d9; font-size:13px; font-weight:bold;")
        layout.addWidget(self.iface_label)
        layout.addStretch()
        layout.addWidget(self.target_label)
        return widget

    def create_dashboard(self):
        """Startup dashboard shown before scanning"""
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background:#0a0f1a;
                border:2px solid #1a2640;
                border-radius:10px;
                padding:20px;
            }
        """)

        layout = QVBoxLayout(card)

        title = QLabel("📡 Welcome to RubyFi")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size:20px; font-weight:bold; color:#00ff88;")

        steps = QLabel(
            "Start your wireless assessment in 3 steps:\n\n"
            "1️⃣ Enable Monitor Mode\n"
            "2️⃣ Scan Networks\n"
            "3️⃣ Select Target → Launch Attack"
        )
        steps.setAlignment(Qt.AlignCenter)
        steps.setStyleSheet("color:#7a9bbf; font-size:13px;")

        layout.addWidget(title)
        layout.addWidget(steps)

        return card

    def create_stats_bar(self):
        widget = QWidget()
        layout = QHBoxLayout(widget)

        def make_card(title):
            card = QLabel(f"{title}\n0")
            card.setAlignment(Qt.AlignCenter)
            card.setStyleSheet("""
                background:#0f1724;
                border:1px solid #1a2640;
                border-radius:8px;
                padding:12px;
                font-size:14px;
                font-weight:bold;
                color:#00d4ff;
            """)
            card.setMinimumWidth(150)
            return card

        self.stat_networks = make_card("Networks Found")
        self.stat_clients = make_card("Clients Detected")
        self.stat_handshakes = make_card("Handshakes")

        layout.addWidget(self.stat_networks)
        layout.addWidget(self.stat_clients)
        layout.addWidget(self.stat_handshakes)
        layout.addStretch()

        return widget

    def create_workflow_bar(self):
        bar = QLabel("INTERFACE  →  SCAN  →  TARGET  →  ATTACK  →  CRACK")
        bar.setAlignment(Qt.AlignCenter)
        bar.setStyleSheet("""
            font-size:12px;
            font-weight:bold;
            letter-spacing:2px;
            color:#7a9bbf;
            padding:6px;
        """)
        return bar


    def create_toolbar(self):
        toolbar = QHBoxLayout()
        buttons = [
            ("🔧 Manage Interface", self.manage_interface, "#8338ec"),
            ("📡 Scan Networks",    self.start_scan,       "#00ff88"),
            ("⚔️ Launch Attack",   self.launch_attack,    "#ff006e"),
            ("🔓 Crack",           self.crack_password,   "#00b4d8"),
        ]
        for text, callback, color in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(callback)
            btn.setStyleSheet(f"""
QPushButton {{ background:#21262d; border:2px solid {color}; color:{color};
  font-weight:bold; padding:10px 15px; border-radius:8px; }}
QPushButton:hover {{ background:{color}; color:#0d1117; }}
""")
            toolbar.addWidget(btn)
        return toolbar

    def create_network_table(self):
        table = QTableWidget()
        table.setColumnCount(7)
        table.setHorizontalHeaderLabels(["NUM", "SSID", "BSSID", "CH", "PWR", "ENCRYPTION", "CLIENTS"])

        table.setRowCount(1)
        table.setSpan(0,0,1,7)

        placeholder = QTableWidgetItem("📡 No networks discovered yet — Click 'Scan Networks'")
        placeholder.setTextAlignment(Qt.AlignCenter)
        placeholder.setForeground(QBrush(QColor(120,140,160)))

        table.setItem(0,0,placeholder)


        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.itemSelectionChanged.connect(self.on_target_selected)
        return table

    # ── table helpers ────────────────────────────────────────────
    def add_network_to_table(self, network):
        row = self.network_table.rowCount()
        self.network_table.insertRow(row)

        if network['is_5ghz']:
            text_color = QColor(135, 206, 250)
        elif network['wps']:
            text_color = QColor(255, 190, 11)
        else:
            text_color = QColor(201, 209, 217)

        num_item = QTableWidgetItem(f"[{row + 1}]")
        num_item.setForeground(QBrush(QColor(139, 148, 158)))
        num_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.network_table.setItem(row, 0, num_item)

        ssid_item = QTableWidgetItem(network['ssid'])
        ssid_item.setForeground(QBrush(text_color))
        ssid_item.setFont(QFont("Ubuntu", 10, QFont.Weight.Bold))
        self.network_table.setItem(row, 1, ssid_item)

        bssid_item = QTableWidgetItem(network['bssid'])
        bssid_item.setForeground(QBrush(QColor(139, 148, 158)))
        self.network_table.setItem(row, 2, bssid_item)

        ch_item = QTableWidgetItem(network['channel'])
        ch_item.setForeground(QBrush(text_color))
        ch_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.network_table.setItem(row, 3, ch_item)

        pwr_item = QTableWidgetItem(network['power'])
        pwr_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        try:
            pwr_val = int(network['power'])
            if pwr_val > -50:
                pwr_color = QColor(0, 255, 136)
            elif pwr_val > -70:
                pwr_color = QColor(255, 190, 11)
            else:
                pwr_color = QColor(255, 0, 110)
            pwr_item.setForeground(QBrush(pwr_color))
        except Exception:
            pwr_item.setForeground(QBrush(QColor(139, 148, 158)))
        self.network_table.setItem(row, 4, pwr_item)

        enc_item = QTableWidgetItem(network['encryption'])
        enc_item.setForeground(QBrush(text_color))
        self.network_table.setItem(row, 5, enc_item)

        cli_item = QTableWidgetItem(network.get('clients', '0'))
        cli_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        cli_color = QColor(0, 255, 136) if network.get('clients', '0') != '0' else QColor(255, 0, 110)
        cli_item.setForeground(QBrush(cli_color))
        self.network_table.setItem(row, 6, cli_item)

        self.network_table.item(row, 0).setData(Qt.ItemDataRole.UserRole, network)

        count = self.network_table.rowCount()
        self.stat_networks.setText(f"Networks Found\n{count}")


    def on_target_selected(self):
        selected = self.network_table.selectedItems()
        if selected:
            row = selected[0].row()
            network = self.network_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
            self.selected_target = network
            self.target_label.setText(f"🎯 Target: {network['ssid']}")
            self.log(f"🎯 Target selected: {network['ssid']} ({network['bssid']}) on CH {network['channel']}")

    # ── logging / status ─────────────────────────────────────────
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_view.append(f"[{timestamp}] {message}")
        scrollbar = self.log_view.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def update_status(self):
        mode_text  = self.current_mode if self.current_mode != "None" else "Not Ready"
        iface_text = self.current_interface if self.current_interface else "None"
        self.status_bar.showMessage(f"Interface: {iface_text} │ Mode: {mode_text} │ Ready")

    def animate_progress(self):
        self.progress_value = (self.progress_value + 2) % 100
        self.progress.setValue(self.progress_value)

    # ── interface management ─────────────────────────────────────
    def manage_interface(self):
        dialog = InterfaceDialog(self)
        dialog.interface_changed.connect(self.on_interface_changed)
        dialog.exec()

    def on_interface_changed(self, interface, mode):
        self.current_interface = interface
        self.current_mode = mode
        self.iface_label.setText(f"🔌 Interface: {interface} ({mode})")
        self.update_status()
        self._apply_interface(interface, mode)
        self.log(f"✅ Interface: {interface} ({mode})")

    # ── scanning ─────────────────────────────────────────────────
    def start_scan(self):
        
        self.network_table.clearContents()
        self.network_table.setRowCount(0)

        if self.scan_thread and self.scan_thread.isRunning():
            self.log("🛑 Stopping scan...")
            self.scan_thread.stop()
            self.scan_thread.wait()
            self.scan_thread = None
            self._reset_refresh_btn()
            return

        if hasattr(self, "dashboard"):
            self.dashboard.hide()

        # Auto-detect BEFORE showing warning
        if not self.current_interface or self.current_mode != "Monitor":
            self._auto_detect_monitor_interface()

        if not self.current_interface or self.current_mode != "Monitor":
            self.log("❌ Enable monitor mode first!")
            QMessageBox.warning(self, "Monitor Mode Required",
                                "Please enable monitor mode via 'Manage Interface' first.")
            self.manage_interface()
            return

        self.log(f"🚀 Starting scan on {self.current_interface}...")
        self.log("💡 Click 'Stop Scanning' button to stop")
        self.network_table.setRowCount(0)
        self.progress.setValue(0)
        self.progress.setFormat("Scanning... 0%")

        self.refresh_btn.setText("⏹️ Stop Scanning")
        self.refresh_btn.setStyleSheet("""
QPushButton { background:#21262d; border:2px solid #ff006e; color:#ff006e;
  font-weight:bold; padding:8px 12px; border-radius:6px; }
QPushButton:hover { background:#ff006e; color:#0d1117; }
""")

        self.scan_thread = ScanThread(self.current_interface)
        self.scan_thread.network_found.connect(self.add_network_to_table)
        self.scan_thread.scan_complete.connect(self.on_scan_complete)
        self.scan_thread.progress_update.connect(self.on_scan_progress)
        self.scan_thread.error_occurred.connect(self.log)
        self.scan_thread.start()

    def on_scan_progress(self, value, message):
        self.progress.setValue(value)
        self.progress.setFormat(message)

    def on_scan_complete(self, count):
        self.progress.setValue(100)
        self.progress.setFormat(f"✅ Scan complete - {count} networks")
        self.log(f"✅ Found {count} networks. Select target then Launch Attack.")
        self._reset_refresh_btn()

    def _reset_refresh_btn(self):
        self.refresh_btn.setText("🔄 Refresh")
        self.refresh_btn.setStyleSheet("""
QPushButton { background:#21262d; border:2px solid #00ff88; color:#00ff88;
  font-weight:bold; padding:8px 12px; border-radius:6px; }
QPushButton:hover { background:#00ff88; color:#0d1117; }
""")

    # ── attack routing ────────────────────────────────────────────
    def launch_attack(self):
        if not self.selected_target:
            self.log("❌ Select a target network first!")
            QMessageBox.warning(self, "No Target",
                                "Please scan and select a target network first.")
            return
        # Auto-detect before rejecting
        if not self.current_interface or self.current_mode != "Monitor":
            self._auto_detect_monitor_interface()
            
        if not self.current_interface or self.current_mode != "Monitor":
            self.log("❌ Monitor mode required!")
            return
        self.show_attack_menu()

    def show_attack_menu(self):
        target = self.selected_target
        dialog = QDialog(self)
        dialog.setWindowTitle("⚔️ Select Attack Type")
        dialog.setModal(True)
        dialog.setMinimumSize(450, 300)
        dialog.setStyleSheet(DARK_THEME)

        layout = QVBoxLayout(dialog)

        header = QLabel("⚔️ ATTACK MENU")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("font-size:16px; font-weight:bold; color:#ff006e; margin:15px;")
        layout.addWidget(header)

        info_label = QLabel(
            f"Target: {target['ssid']}\nBSSID: {target['bssid']}\nChannel: {target['channel']}"
        )
        info_label.setStyleSheet(
            "color:#c9d1d9; margin:10px; padding:10px; background:#161b22; border-radius:6px;"
        )
        layout.addWidget(info_label)

        attacks = [
            ("1️⃣ Handshake Capture",    "handshake", "#ffbe0b"),
            ("2️⃣ Deauthentication",      "deauth",    "#ff006e"),
            ("3️⃣ Evil Twin + Deauth",    "evil_twin", "#8338ec"),
            ("4️⃣ WPS Attack",            "wps",       "#00b4d8"),
            ("5️⃣ Beacon Flood (SSID Chaos)", "beacon_flood", "#e040fb"),
            ("6️⃣ WiFi Phishing (Captive Portal)", "wifi_phishing", "#ff6b35"),
        ]

        for text, attack_id, color in attacks:
            btn = QPushButton(text)
            btn.setMinimumHeight(50)
            btn.setStyleSheet(f"""
QPushButton {{ background:#21262d; border:2px solid {color}; color:{color};
  font-size:13px; font-weight:bold; text-align:left; padding-left:20px; border-radius:6px; }}
QPushButton:hover {{ background:{color}; color:#0d1117; }}
""")
            btn.clicked.connect(lambda checked, aid=attack_id: self.handle_attack_selection(aid, dialog))
            layout.addWidget(btn)

        layout.addStretch()

        cancel_btn = QPushButton("❌ Cancel")
        cancel_btn.clicked.connect(dialog.reject)
        cancel_btn.setStyleSheet("""
QPushButton { background:#161b22; border:2px solid #8b949e; color:#8b949e; padding:10px; border-radius:6px; }
QPushButton:hover { background:#8b949e; color:#0d1117; }
""")
        layout.addWidget(cancel_btn)
        dialog.exec()

    def handle_attack_selection(self, attack_type, dialog):
        dialog.close()
        if attack_type == "deauth":
            self.execute_deauth()          # DeauthMixin
        elif attack_type == "handshake":
            self.execute_handshake()
        elif attack_type == "evil_twin":
            self.execute_evil_twin()       # EvilTwinMixin
        elif attack_type == "wps":
            self.execute_wps()
        elif attack_type == "beacon_flood":
            self.execute_beacon_flood()
        elif attack_type == "beacon_flood":
            self.execute_beacon_flood()
        elif attack_type == "wifi_phishing":
            self.execute_wifi_phishing()

    # ── handshake (panel + thread live here since they reference many self.* widgets) ──

    def execute_handshake(self):
        target = self.selected_target

        dialog = HandshakeModeDialog(
            target["ssid"], target["bssid"], target["channel"],
            self.current_interface, self,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        mode = dialog.selected_mode

        client_mac = None
        if mode == "manual":
            client_dialog = ClientSelectionDialog(
                target["bssid"], target["ssid"], target["channel"],
                self.current_interface, self,
            )
            if client_dialog.exec() != QDialog.DialogCode.Accepted:
                return
            client_mac = client_dialog.get_selected_client()

        self.perform_handshake_capture(target, mode, client_mac)

    def perform_handshake_capture(self, target, mode, client_mac=None):
        target_ssid    = target["ssid"]
        target_bssid   = target["bssid"]
        target_channel = target["channel"]

        self.log(f"Launching Handshake Capture on {target_ssid} ...")
        self.log(
            f"BSSID: {target_bssid} | Channel: {target_channel} | Mode: {mode.upper()}"
            + (f" | Client: {client_mac}" if client_mac else " | broadcast")
        )

        try:
            self.hs_panel    = self._create_hs_panel(target_ssid, target_bssid, target_channel, mode)
            self.hs_stop_btn = QPushButton("■ Stop Capture")
            self.hs_stop_btn.setStyleSheet("""
QPushButton { background:#21262d; border:2px solid #ffbe0b; color:#ffbe0b; font-weight:bold; padding:10px; border-radius:6px; }
QPushButton:hover { background:#ffbe0b; color:#0d1117; }
""")
            self.hs_stop_btn.clicked.connect(self.stop_handshake)

            layout = self.centralWidget().layout()
            layout.insertWidget(layout.count() - 2, self.hs_panel)
            layout.insertWidget(layout.count() - 2, self.hs_stop_btn)

            self.hs_thread = HandshakeCaptureThread(
                self.current_interface,
                target_bssid, target_ssid, target_channel,
                mode=mode, client_mac=client_mac,
            )
            self.hs_thread.statusupdate.connect(self._hs_on_status)
            self.hs_thread.phasechanged.connect(self._hs_on_phase)
            self.hs_thread.statsupdate.connect(self._hs_on_stats)
            self.hs_thread.handshakefound.connect(self._hs_on_found)
            self.hs_thread.attackcomplete.connect(self._hs_on_complete)
            self.hs_thread.start()

        except Exception as e:
            self.log(f"! Error starting handshake capture: {e}")
            QMessageBox.critical(self, "Error", str(e))

    def _create_hs_panel(self, ssid, bssid, channel, mode):
        panel = QWidget()
        panel.setStyleSheet("""
QWidget { background:#161b22; border:2px solid #ffbe0b; border-radius:8px; padding:10px; }
""")
        layout = QVBoxLayout(panel)
        layout.setSpacing(6)

        title = QLabel("🤝 HANDSHAKE CAPTURE — LIVE")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color:#ffbe0b; font-weight:bold; font-size:16px; border:none;")
        layout.addWidget(title)

        info = QLabel(f" {ssid} · {bssid} · Ch {channel} · {mode.upper()} mode")
        info.setStyleSheet("color:#8b949e; font-size:11px; border:none; margin-bottom:2px;")
        layout.addWidget(info)

        self.hs_phase_label = QLabel("⚙ SETTING UP")
        self.hs_phase_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.hs_phase_label.setStyleSheet(
            "color:#00b4d8; font-size:22px; font-weight:bold;"
            "background:#0d1117; border-radius:6px; padding:10px;"
            "margin:4px 0; border:1px solid #30363d;"
        )
        layout.addWidget(self.hs_phase_label)

        stats_row = QHBoxLayout()

        def _stat(attr, label_text, colour, init="—"):
            w = QWidget()
            vl = QVBoxLayout(w)
            vl.setContentsMargins(5, 5, 5, 5)
            val = QLabel(init)
            val.setAlignment(Qt.AlignmentFlag.AlignCenter)
            val.setStyleSheet(f"color:{colour}; font-size:26px; font-weight:bold; border:none;")
            desc = QLabel(label_text)
            desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
            desc.setStyleSheet("color:#8b949e; font-size:10px; border:none;")
            vl.addWidget(val)
            vl.addWidget(desc)
            setattr(self, attr, val)
            return w

        stats_row.addWidget(_stat("hs_time_lbl",   "Time Elapsed",   "#ffbe0b", "0s"))
        stats_row.addWidget(_stat("hs_cycles_lbl", "Deauth Cycles",  "#ff006e", "0"))
        stats_row.addWidget(_stat("hs_size_lbl",   "Cap File (KB)",  "#00b4d8", "0.0"))
        layout.addLayout(stats_row)

        self.hs_countdown = QProgressBar()
        self.hs_countdown.setRange(0, 300)
        self.hs_countdown.setValue(0)
        self.hs_countdown.setFormat("Elapsed: 0s | Remaining: 5:00")
        self.hs_countdown.setStyleSheet("""
QProgressBar { border:1px solid #30363d; border-radius:4px; background:#0d1117;
  color:#c9d1d9; height:18px; text-align:center; font-size:11px; }
QProgressBar::chunk { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
  stop:0 #ffbe0b,stop:0.5 #ff006e,stop:1 #8338ec); border-radius:4px; }
""")
        layout.addWidget(self.hs_countdown)

        self.hs_spinner = QProgressBar()
        self.hs_spinner.setRange(0, 0)
        self.hs_spinner.setTextVisible(False)
        self.hs_spinner.setStyleSheet("""
QProgressBar { border:1px solid #30363d; border-radius:4px; background:#0d1117; height:6px; }
QProgressBar::chunk { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
  stop:0 #ffbe0b,stop:0.4 #ff006e,stop:1 #00ff88); border-radius:4px; }
""")
        layout.addWidget(self.hs_spinner)

        log_hdr = QLabel(" ACTIVITY LOG")
        log_hdr.setStyleSheet(
            "color:#ffbe0b; font-weight:bold; font-size:11px; border:none; margin-top:4px;"
        )
        layout.addWidget(log_hdr)

        self.hs_log = QTextEdit()
        self.hs_log.setReadOnly(True)
        self.hs_log.setMaximumHeight(100)
        self.hs_log.setStyleSheet("""
QTextEdit { background:#0d1117; border:1px solid #30363d; border-radius:4px;
  color:#c9d1d9; padding:5px; font-family:monospace; font-size:11px; }
""")
        layout.addWidget(self.hs_log)
        return panel

    def _hs_on_status(self, message):
        self.log(message)
        if not hasattr(self, "hs_log"):
            return
        import time as _t
        ts = _t.strftime("%H:%M:%S")
        self.hs_log.append(f"[{ts}] {message}")

    def _hs_on_phase(self, text, colour):
        if not hasattr(self, "hs_phase_label"):
            return
        self.hs_phase_label.setText(text)
        self.hs_phase_label.setStyleSheet(
            f"color:{colour}; font-size:22px; font-weight:bold;"
            f"background:#0d1117; border-radius:6px; padding:10px;"
            f"margin:4px 0; border:1px solid {colour};"
        )

    def _hs_on_stats(self, elapsed, cycles, size_kb):
        if hasattr(self, "hs_time_lbl"):
            mins, secs = divmod(elapsed, 60)
            self.hs_time_lbl.setText(f"{mins}m {secs:02d}s" if mins > 0 else f"{elapsed}s")
        if hasattr(self, "hs_cycles_lbl"):
            self.hs_cycles_lbl.setText(str(cycles))
        if hasattr(self, "hs_size_lbl"):
            self.hs_size_lbl.setText(f"{size_kb:.1f}")
            if size_kb > 0:
                self.hs_size_lbl.setStyleSheet(
                    "color:#00ffff; font-size:26px; font-weight:bold; border:none;"
                )
                QTimer.singleShot(400, lambda: hasattr(self, "hs_size_lbl") and
                    self.hs_size_lbl.setStyleSheet(
                        "color:#00b4d8; font-size:26px; font-weight:bold; border:none;"
                    ))
        if hasattr(self, "hs_countdown"):
            remaining = max(0, 300 - elapsed)
            r_m, r_s = divmod(remaining, 60)
            self.hs_countdown.setValue(elapsed)
            self.hs_countdown.setFormat(f"Elapsed: {elapsed}s | Remaining: {r_m}:{r_s:02d}")

    def _hs_on_found(self, filepath):
        if hasattr(self, "hs_phase_label"):
            self.hs_phase_label.setText("✅ HANDSHAKE CAPTURED!")
            self.hs_phase_label.setStyleSheet(
                "color:#00ff88; font-size:24px; font-weight:bold;"
                "background:#0d1117; border-radius:6px; padding:10px;"
                "margin:4px 0; border:2px solid #00ff88;"
            )
        if hasattr(self, "hs_spinner"):
            self.hs_spinner.setRange(0, 100)
            self.hs_spinner.setValue(100)
            self.hs_spinner.setStyleSheet("""
QProgressBar { border:1px solid #00ff88; border-radius:4px; background:#0d1117; height:6px; }
QProgressBar::chunk { background:#00ff88; border-radius:4px; }
""")
        if hasattr(self, "hs_log"):
            import time as _t
            ts = _t.strftime("%H:%M:%S")
            self.hs_log.append(f"[{ts}] ✅ SAVED → {filepath}")

        self.log(f"✅ Handshake saved: {filepath}")
        try:
            subprocess.Popen(
                ["paplay", "/usr/share/sounds/freedesktop/stereo/complete.oga"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass
        QMessageBox.information(
            self, "✅ Handshake Captured!",
            f"WPA Handshake saved to:\n{filepath}\n\nGo to Password Cracking to crack it!",
        )

    def _hs_on_complete(self, success, message):
        if not success:
            self.log(f"Handshake capture ended: {message}")
            if hasattr(self, "hs_phase_label"):
                self.hs_phase_label.setText("❌ NO HANDSHAKE")
                self.hs_phase_label.setStyleSheet(
                    "color:#8b949e; font-size:20px; font-weight:bold;"
                    "background:#0d1117; border-radius:6px; padding:10px;"
                    "margin:4px 0; border:1px solid #8b949e;"
                )
            if hasattr(self, "hs_spinner"):
                self.hs_spinner.setRange(0, 100)
                self.hs_spinner.setValue(0)
        self._hs_cleanup_ui()

    def stop_handshake(self):
        if hasattr(self, "hs_thread") and self.hs_thread.isRunning():
            self.log("Stopping Handshake Capture ...")
            self.hs_thread.stop()
            self.hs_thread.wait()
            self.log("Capture stopped.")
        self._hs_cleanup_ui()

    def _hs_cleanup_ui(self):
        for attr in ("hs_panel", "hs_stop_btn"):
            if hasattr(self, attr):
                getattr(self, attr).deleteLater()
                delattr(self, attr)
        for attr in ("hs_phase_label", "hs_time_lbl", "hs_cycles_lbl",
                     "hs_size_lbl", "hs_countdown", "hs_spinner", "hs_log"):
            if hasattr(self, attr):
                delattr(self, attr)

    # ── WPS (delegates to wps_dialog.py) ─────────────────────────
    def execute_wps(self):
        target = self.selected_target

        dialog = WPSModeDialog(
            target["ssid"], target["bssid"], target["channel"],
            self.current_interface, self,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        self.perform_wps_attack(target, dialog.selected_mode)

    def perform_wps_attack(self, target, mode):
        target_ssid    = target["ssid"]
        target_bssid   = target["bssid"]
        target_channel = target["channel"]

        MODE_LABELS = {
            "pixiedust": "Pixie Dust",
            "pinbrute":  "PIN Brute-Force",
            "both":      "Pixie Dust → PIN",
        }
        self.log(f"Launching WPS {MODE_LABELS.get(mode, mode)} on {target_ssid} ...")
        self.log(f"BSSID: {target_bssid} | Channel: {target_channel}")

        try:
            self.wps_panel    = self._create_wps_panel(target_ssid, target_bssid, target_channel, mode)
            self.wps_stop_btn = QPushButton("■ Stop WPS Attack")
            self.wps_stop_btn.setStyleSheet("""
QPushButton { background:#21262d; border:2px solid #00b4d8; color:#00b4d8; font-weight:bold; padding:10px; border-radius:6px; }
QPushButton:hover { background:#00b4d8; color:#0d1117; }
""")
            self.wps_stop_btn.clicked.connect(self.stop_wps)

            layout = self.centralWidget().layout()
            layout.insertWidget(layout.count() - 2, self.wps_panel)
            layout.insertWidget(layout.count() - 2, self.wps_stop_btn)

            self.wps_thread = WPSAttackThread(
                self.current_interface,
                target_bssid, target_ssid, target_channel,
                mode=mode,
            )
            self.wps_thread.statusupdate.connect(self._wps_on_status)
            self.wps_thread.phasechanged.connect(self._wps_on_phase)
            self.wps_thread.statsupdate.connect(self._wps_on_stats)
            self.wps_thread.wps_result.connect(self._wps_on_result)
            self.wps_thread.attackcomplete.connect(self._wps_on_complete)
            self.wps_thread.start()

            self._wps_start_time = time.time()
            self.wps_timer = QTimer()
            self.wps_timer.timeout.connect(self._wps_tick_timer)
            self.wps_timer.start(1000)

        except Exception as e:
            self.log(f"! WPS Error: {e}")
            QMessageBox.critical(self, "Error", str(e))

    def _create_wps_panel(self, ssid, bssid, channel, mode):
        MODE_LABELS = {
            "pixiedust": "⚡ PIXIE DUST",
            "pinbrute":  "🔢 PIN BRUTE-FORCE",
            "both":      "🔄 PIXIE DUST → PIN",
        }

        panel = QWidget()
        panel.setStyleSheet("""
QWidget { background:#161b22; border:2px solid #00b4d8; border-radius:8px; padding:10px; }
""")
        layout = QVBoxLayout(panel)
        layout.setSpacing(6)

        title = QLabel(f"📡 WPS ATTACK — {MODE_LABELS.get(mode, mode)}")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color:#00b4d8; font-weight:bold; font-size:16px; border:none;")
        layout.addWidget(title)

        info = QLabel(f" {ssid} · {bssid} · Ch {channel}")
        info.setStyleSheet("color:#8b949e; font-size:11px; border:none; margin-bottom:2px;")
        layout.addWidget(info)

        self.wps_phase_label = QLabel("⚙ SETTING UP")
        self.wps_phase_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.wps_phase_label.setStyleSheet(
            "color:#00b4d8; font-size:22px; font-weight:bold;"
            "background:#0d1117; border-radius:6px; padding:10px;"
            "margin:4px 0; border:1px solid #30363d;"
        )
        layout.addWidget(self.wps_phase_label)

        self.wps_cred_box = QLabel("")
        self.wps_cred_box.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.wps_cred_box.setWordWrap(True)
        self.wps_cred_box.setVisible(False)
        self.wps_cred_box.setStyleSheet("""
QLabel { color:#00ff88; font-size:16px; font-weight:bold; font-family:monospace;
  background:#0d1117; border:2px solid #00ff88; border-radius:6px; padding:12px; margin:4px 0; }
""")
        layout.addWidget(self.wps_cred_box)

        stats_row = QHBoxLayout()

        def _stat(attr, label_text, colour, init="—"):
            w = QWidget()
            vl = QVBoxLayout(w)
            vl.setContentsMargins(5, 5, 5, 5)
            val = QLabel(init)
            val.setAlignment(Qt.AlignmentFlag.AlignCenter)
            val.setStyleSheet(f"color:{colour}; font-size:26px; font-weight:bold; border:none;")
            desc = QLabel(label_text)
            desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
            desc.setStyleSheet("color:#8b949e; font-size:10px; border:none;")
            vl.addWidget(val)
            vl.addWidget(desc)
            setattr(self, attr, val)
            return w

        stats_row.addWidget(_stat("wps_time_lbl",     "Time Elapsed",  "#ffbe0b", "0s"))
        stats_row.addWidget(_stat("wps_progress_lbl", "Progress",      "#00b4d8", "—"))
        stats_row.addWidget(_stat("wps_pins_lbl",     "Last PIN Tried","#ff006e", "—"))
        layout.addLayout(stats_row)

        if mode == "pixiedust":
            hint_text = (
                "✔ WPS PIN: XXXXXXXX — success in seconds\n"
                "✔ WPA PSK: password — full key recovered\n"
                "✖ Failed to recover — AP not vulnerable"
            )
            hint_col = "#00b4d8"
        elif mode == "pinbrute":
            hint_text = (
                "🔢 Reaver trying 11,000 PIN combos (4–48 hrs)\n"
                "Progress shown in % above | Results saved to .reaver/\n"
                "Tip: run again later — reaver resumes automatically"
            )
            hint_col = "#ffbe0b"
        else:
            hint_text = (
                "Phase 1: Pixie Dust (fast, few seconds)\n"
                "Phase 2: PIN Brute-Force (auto-starts if Pixie Dust fails)"
            )
            hint_col = "#00ff88"

        hint = QLabel(hint_text)
        hint.setStyleSheet(
            f"color:{hint_col}; font-size:10px; border:1px solid #30363d;"
            "border-radius:4px; padding:8px; background:#0d1117;"
        )
        layout.addWidget(hint)
        return panel

    def stop_wps(self):
        if hasattr(self, "wps_timer"):
            self.wps_timer.stop()
        if hasattr(self, "wps_thread") and self.wps_thread.isRunning():
            self.log("Stopping WPS attack ...")
            self.wps_thread.stop()
            self.wps_thread.wait()
            self.log("WPS attack stopped.")
        self._wps_cleanup_ui()

    def _wps_cleanup_ui(self):
        for attr in ("wps_panel", "wps_stop_btn"):
            if hasattr(self, attr):
                getattr(self, attr).deleteLater()
                delattr(self, attr)
        for attr in ("wps_phase_label", "wps_cred_box",
                     "wps_time_lbl", "wps_progress_lbl", "wps_pins_lbl",
                     "wps_spinner", "wps_log",
                     "wps_timer", "_wps_start_time"):
            if hasattr(self, attr):
                delattr(self, attr)

    # ── WPS signal slots (wired to WPSAttackThread signals) ──────
    def _wps_on_status(self, message):
        self.log(message)
        if hasattr(self, "wps_log"):
            import time as _t
            self.wps_log.append(f"[{_t.strftime('%H:%M:%S')}] {message}")

    def _wps_on_phase(self, text, colour):
        if hasattr(self, "wps_phase_label"):
            self.wps_phase_label.setText(text)
            self.wps_phase_label.setStyleSheet(
                f"color:{colour}; font-size:22px; font-weight:bold;"
                f"background:#0d1117; border-radius:6px; padding:10px;"
                f"margin:4px 0; border:1px solid {colour};"
            )

    def _wps_on_stats(self, elapsed, progress_str, last_pin):
        if hasattr(self, "wps_time_lbl"):
            mins, secs = divmod(elapsed, 60)
            self.wps_time_lbl.setText(f"{mins}m {secs:02d}s" if mins > 0 else f"{elapsed}s")
        if hasattr(self, "wps_progress_lbl"):
            self.wps_progress_lbl.setText(progress_str)
        if hasattr(self, "wps_pins_lbl"):
            self.wps_pins_lbl.setText(last_pin)

    def _wps_on_result(self, pin, psk):
        if hasattr(self, "wps_phase_label"):
            self.wps_phase_label.setText("✅ WPS CRACKED!")
            self.wps_phase_label.setStyleSheet(
                "color:#00ff88; font-size:24px; font-weight:bold;"
                "background:#0d1117; border-radius:6px; padding:10px;"
                "margin:4px 0; border:2px solid #00ff88;"
            )
        if hasattr(self, "wps_cred_box"):
            self.wps_cred_box.setText(f"🔑 PIN: {pin}    🔒 PSK: {psk}")
            self.wps_cred_box.setVisible(True)
        self.log(f"✅ WPS PIN: {pin}  |  PSK: {psk}")
        QMessageBox.information(self, "✅ WPS Cracked!",
                                f"PIN: {pin}\nPassword: {psk}")

    def _wps_on_complete(self, success, message):
        if not success:
            self.log(f"WPS ended: {message}")
            if hasattr(self, "wps_phase_label"):
                self.wps_phase_label.setText("❌ WPS FAILED")
                self.wps_phase_label.setStyleSheet(
                    "color:#8b949e; font-size:20px; font-weight:bold;"
                    "background:#0d1117; border-radius:6px; padding:10px;"
                    "margin:4px 0; border:1px solid #8b949e;"
                )
        self._wps_cleanup_ui()

    def _wps_tick_timer(self):
        if hasattr(self, "_wps_start_time") and hasattr(self, "wps_time_lbl"):
            elapsed = int(time.time() - self._wps_start_time)
            mins, secs = divmod(elapsed, 60)
            self.wps_time_lbl.setText(f"{mins}m {secs:02d}s" if mins > 0 else f"{elapsed}s")

    
    # ── crack password stub ──────────────────────────────────────
    def crack_password(self):
        from PyQt5.QtWidgets import QDialog
        from gui.cracking_tab import CrackingTab
        dialog = QDialog(self)
        dialog.setWindowTitle("🔓 RubyFi — Password Cracking")
        dialog.resize(1100, 700)
        dialog.setStyleSheet("background: #0d1117;")
        lay = QVBoxLayout(dialog)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(CrackingTab(dialog))
        dialog.exec()

    
    def _apply_interface(self, interface: str, mode: str):
        """Central updater for all interface-related UI."""
        self.current_interface = interface
        self.current_mode      = mode
        icon = "✅" if mode == "Monitor" else "🔵"
        self.iface_label.setText(f"🔌 Interface: {interface} ({mode}) {icon}")
        self.update_status()

    def _auto_detect_monitor_interface(self):
        """Read iw dev and auto-populate interface/mode if monitor is already active."""
        try:
            result = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
            iface = None
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("Interface"):
                    iface = line.split()[-1]
                elif "type monitor" in line and iface:
                    self._apply_interface(iface, "Monitor")
                    self.log(f"🔍 Auto-detected monitor interface: {iface}")
                    return True
        except Exception:
            pass

        # Fallback: look for *mon named interfaces via ip link
        try:
            result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True, timeout=5)
            for line in result.stdout.splitlines():
                if ": " in line:
                    candidate = line.split(":")[1].strip().split("@")[0]
                    if "mon" in candidate.lower():
                        self._apply_interface(candidate, "Monitor")
                        self.log(f"🔍 Auto-detected monitor interface: {candidate}")
                        return True
        except Exception:
            pass
        return False


# ═══════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════

def run_gui():
    app = QApplication(sys.argv)
    font = QFont("Ubuntu", 10)
    app.setFont(font)
    window = RubyFiWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    run_gui()
