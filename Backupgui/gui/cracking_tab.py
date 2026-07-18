#!/usr/bin/env python3
"""RubyFi - Password Cracking GUI Tab (cracking_tab.py)"""

import os
import re
import json
import subprocess
import time
from pathlib import Path
from datetime import datetime

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTextEdit, QProgressBar, QLineEdit, QFileDialog, QComboBox,
    QGroupBox, QButtonGroup, QSplitter, QTableWidget, QTableWidgetItem,
    QHeaderView, QStackedWidget, QMessageBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QBrush, QTextCursor


# ══════════════════════════════════════════════════════════════════════════════
#   BACKGROUND ATTACK THREADS
# ══════════════════════════════════════════════════════════════════════════════

class BruteForceThread(QThread):
    """Runs hashcat brute-force in background and emits output signals."""
    output_line    = pyqtSignal(str)
    password_found = pyqtSignal(str)
    attack_done    = pyqtSignal(bool, str)   # (success, message)

    def __init__(self, hash_file: str, mask: str):
        super().__init__()
        self.hash_file = hash_file
        self.mask      = mask
        self.process   = None
        self.running   = True

    # ── run ────────────────────────────────────────────────────────────────
    def run(self):
        try:
            hash_file = self._prepare_hash()
            if not hash_file:
                self.attack_done.emit(False, "Hash conversion failed")
                return

            modes = ["22000", "2500"] if hash_file.endswith((".cap", ".hccapx")) else ["22000"]

            SKIP = ["Device #", "Kernel", "Optimized", "Falling back", "Minimum",
                    "Maximum", "Counting", "Sorted", "Removing", "Removed",
                    "Compared", "potfile", "=====", "Parsed", "INFO: All", "Allocate"]

            for mode in modes:
                if not self.running:
                    break

                cmd = (f"hashcat -m {mode} -a 3 \'{hash_file}\' \'{self.mask}\'"
                       f" -O --status --status-timer=5")
                self.output_line.emit(f"[*] hashcat -m {mode} -a 3 \'{self.mask}\'")

                self.process = subprocess.Popen(
                    cmd, shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, bufsize=1
                )

                mode_failed = False
                cracked     = False

                while self.running:
                    line = self.process.stdout.readline()
                    if not line and self.process.poll() is not None:
                        break
                    line = line.rstrip()
                    if not line:
                        continue

                    if "No hashes loaded" in line or "Token length" in line:
                        mode_failed = True
                        self.output_line.emit(f"[!] Mode {mode} failed — trying next…")
                        self.process.kill()
                        break

                    if not any(p in line for p in SKIP):
                        self.output_line.emit(line)

                    if ("Recovered" in line and "1/1" in line) or "All hashes found" in line:
                        cracked = True

                if cracked:
                    self._kill()
                    pw = self._show_result(hash_file, mode)
                    if pw:
                        self.password_found.emit(pw)
                        self.attack_done.emit(True, f"Password cracked: {pw}")
                    else:
                        self.attack_done.emit(True, "Cracked — but could not retrieve plaintext")
                    return

                if not mode_failed:
                    break

            if self.running:
                self.attack_done.emit(False, "Password not found — mask exhausted")

        except Exception as exc:
            self.attack_done.emit(False, str(exc))

    # ── helpers ────────────────────────────────────────────────────────────
    def _prepare_hash(self):
        if not self.hash_file.endswith((".cap", ".pcap")):
            return self.hash_file

        h22 = f"/tmp/{Path(self.hash_file).stem}.22000"
        if os.path.exists(h22) and os.path.getsize(h22) > 0:
            self.output_line.emit("[✓] Using cached .22000 file")
            return h22

        self.output_line.emit("[*] Converting .cap → .22000 …")
        try:
            subprocess.run(f"hcxpcapngtool -o \'{h22}\' \'{self.hash_file}\' 2>&1",
                           shell=True, capture_output=True, text=True, timeout=30)
            if os.path.exists(h22) and os.path.getsize(h22) > 0:
                self.output_line.emit("[✓] Converted with hcxpcapngtool")
                return h22
        except Exception:
            pass

        hccapx = f"/tmp/{Path(self.hash_file).stem}.hccapx"
        try:
            subprocess.run(
                f"aircrack-ng -J \'{hccapx.replace('.hccapx','')}\' \'{self.hash_file}\' >/dev/null 2>&1",
                shell=True, timeout=30
            )
            if os.path.exists(hccapx) and os.path.getsize(hccapx) > 0:
                self.output_line.emit("[✓] Using .hccapx fallback")
                return hccapx
        except Exception:
            pass

        self.output_line.emit("[!] All conversion methods failed")
        return None

    def _show_result(self, hash_file: str, mode: str):
        try:
            r = subprocess.run(
                f"hashcat -m {mode} \'{hash_file}\' --show 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=10
            )
            for line in r.stdout.strip().split("\n"):
                if ":" in line:
                    return line.split(":")[-1].strip()
        except Exception:
            pass
        return None

    def _kill(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except Exception:
                self.process.kill()

    def stop(self):
        self.running = False
        self._kill()


# ──────────────────────────────────────────────────────────────────────────────

class WordlistThread(QThread):
    """Runs aircrack-ng wordlist attack in background."""
    output_line    = pyqtSignal(str)
    password_found = pyqtSignal(str)
    attack_done    = pyqtSignal(bool, str)

    def __init__(self, hash_file: str, wordlist: str):
        super().__init__()
        self.hash_file = hash_file
        self.wordlist  = wordlist
        self.process   = None
        self.running   = True

    def run(self):
        try:
            wordlist = self.wordlist
            if wordlist.endswith(".gz"):
                self.output_line.emit("[*] Decompressing wordlist …")
                tmp = f"/tmp/{Path(wordlist).stem}"
                subprocess.run(f"gunzip -c \'{wordlist}\' > \'{tmp}\'",
                               shell=True, timeout=120)
                wordlist = tmp
                self.output_line.emit("[✓] Decompressed")

            cmd = f"aircrack-ng -w \'{wordlist}\' \'{self.hash_file}\'"
            self.output_line.emit(f"[*] aircrack-ng -w {Path(wordlist).name}")

            self.process = subprocess.Popen(
                cmd, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )

            found    = False
            found_pw = None

            for line in self.process.stdout:
                if not self.running:
                    break
                line = line.rstrip()
                if line.strip():
                    self.output_line.emit(line)
                if "KEY FOUND!" in line:
                    found = True
                    m = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", line)
                    if m:
                        found_pw = m.group(1).strip()
                    self.process.terminate()
                    break

            try:
                self.process.wait(timeout=5)
            except Exception:
                self.process.kill()

            if found and found_pw:
                self.password_found.emit(found_pw)
                self.attack_done.emit(True, f"Password cracked: {found_pw}")
            else:
                self.attack_done.emit(False, "Wordlist exhausted — password not found")

        except Exception as exc:
            self.attack_done.emit(False, str(exc))

    def stop(self):
        self.running = False
        if self.process and self.process.poll() is None:
            self.process.terminate()


# ──────────────────────────────────────────────────────────────────────────────

class DictionaryRulesThread(QThread):
    """Generates rule-based mutations then runs aircrack-ng."""
    output_line    = pyqtSignal(str)
    password_found = pyqtSignal(str)
    attack_done    = pyqtSignal(bool, str)

    RULE_NAMES = {
        "1": "Append numbers (0-99)",
        "2": "Append symbols (!@#$%)",
        "3": "Capitalize first letter",
        "4": "All rules combined",
        "5": "No rules (basic wordlist)",
    }

    def __init__(self, hash_file: str, wordlist: str, rule: str):
        super().__init__()
        self.hash_file = hash_file
        self.wordlist  = wordlist
        self.rule      = rule
        self.process   = None
        self.running   = True
        self._tmp      = None

    def run(self):
        try:
            self.output_line.emit(f"[*] Rule: {self.RULE_NAMES.get(self.rule, '?')}")
            self.output_line.emit("[*] Generating mutations …")

            mutations = []
            with open(self.wordlist, "r", errors="ignore") as fh:
                for word in fh:
                    word = word.strip()
                    if not word:
                        continue
                    mutations.append(word)
                    if self.rule in ("1", "4"):
                        mutations += [f"{word}{i}" for i in range(100)]
                    if self.rule in ("2", "4"):
                        mutations += [f"{word}{c}" for c in "!@#$%^&*"]
                    if self.rule in ("3", "4"):
                        mutations.append(word.capitalize())

            mutations = list(set(mutations))
            self.output_line.emit(f"[✓] {len(mutations):,} mutations generated")

            self._tmp = f"/tmp/rubify_dr_{int(time.time())}.txt"
            with open(self._tmp, "w") as fh:
                fh.write("\n".join(mutations))

            cmd = f"aircrack-ng -w \'{self._tmp}\' \'{self.hash_file}\'"
            self.output_line.emit(f"[*] aircrack-ng | {len(mutations):,} candidates")

            self.process = subprocess.Popen(
                cmd, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )

            found    = False
            found_pw = None

            for line in self.process.stdout:
                if not self.running:
                    break
                line = line.rstrip()
                if line.strip():
                    self.output_line.emit(line)
                if "KEY FOUND!" in line:
                    found = True
                    m = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", line)
                    if m:
                        found_pw = m.group(1).strip()
                    self.process.terminate()
                    break

            try:
                self.process.wait(timeout=5)
            except Exception:
                self.process.kill()

            self._cleanup()

            if found and found_pw:
                self.password_found.emit(found_pw)
                self.attack_done.emit(True, f"Password cracked: {found_pw}")
            else:
                self.attack_done.emit(False, "Mutations exhausted — password not found")

        except Exception as exc:
            self._cleanup()
            self.attack_done.emit(False, str(exc))

    def _cleanup(self):
        if self._tmp:
            try:
                os.remove(self._tmp)
            except Exception:
                pass

    def stop(self):
        self.running = False
        if self.process and self.process.poll() is None:
            self.process.terminate()
        self._cleanup()


# ══════════════════════════════════════════════════════════════════════════════
#   MAIN CRACKING TAB WIDGET
# ══════════════════════════════════════════════════════════════════════════════

class CrackingTab(QWidget):
    """
    Drop-in QWidget for the RubyFi GUI.

    Usage in main_window.py:
        from gui.cracking_tab import CrackingTab

        def crack_password(self):
            dialog = QDialog(self)
            dialog.setWindowTitle("🔓 Password Cracking")
            dialog.resize(1100, 700)
            dialog.setStyleSheet("background: #0d1117;")
            lay = QVBoxLayout(dialog)
            lay.setContentsMargins(0, 0, 0, 0)
            lay.addWidget(CrackingTab(dialog))
            dialog.exec()
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.hash_file       = None
        self.current_thread  = None
        self._setup_ui()
        self._load_saved_passwords()   # populate table on open

    # ── UI Assembly ─────────────────────────────────────────────────────────

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        # ── Header bar ──
        header = QLabel("🔓  PASSWORD CRACKING")
        header.setAlignment(Qt.AlignCenter)
        header.setFixedHeight(46)
        header.setStyleSheet("""
            QLabel {
                color: #ff006e;
                font-size: 18px;
                font-weight: bold;
                background: #161b22;
                border: 2px solid #ff006e;
                border-radius: 8px;
            }
        """)
        root.addWidget(header)

        # ── Two-column splitter ──
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(2)
        splitter.setStyleSheet("QSplitter::handle { background: #30363d; }")

        splitter.addWidget(self._build_left_panel())
        splitter.addWidget(self._build_right_panel())
        splitter.setSizes([400, 650])
        root.addWidget(splitter, stretch=1)

        # ── Animated progress bar (hidden until attack starts) ──
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setVisible(False)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(6)
        self.progress_bar.setStyleSheet("""
            QProgressBar { background:#0d1117; border:none; border-radius:3px; }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ff006e, stop:0.5 #ffbe0b, stop:1 #00ff88);
                border-radius: 3px;
            }
        """)
        root.addWidget(self.progress_bar)

    # ── Left Panel ───────────────────────────────────────────────────────────

    def _build_left_panel(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 6, 0)
        lay.setSpacing(8)

        lay.addWidget(self._build_file_selector())
        lay.addWidget(self._build_mode_buttons())

        # Stacked config panels (one per mode)
        self.config_stack = QStackedWidget()
        self.config_stack.addWidget(self._build_brute_force_panel())   # 0
        self.config_stack.addWidget(self._build_wordlist_panel())       # 1
        self.config_stack.addWidget(self._build_dict_rules_panel())     # 2
        lay.addWidget(self.config_stack)

        lay.addWidget(self._build_action_buttons())
        lay.addStretch()
        return w

    def _build_file_selector(self):
        grp = self._group("📁  Handshake File", "#3fb950")
        lay = QVBoxLayout(grp)
        lay.setSpacing(6)

        row = QHBoxLayout()
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setPlaceholderText("Select .cap / .pcap / .22000 / .hccapx …")
        self.file_path_edit.setReadOnly(True)
        self.file_path_edit.setStyleSheet(self._input_ss())

        browse = QPushButton("📂 Browse")
        browse.setFixedWidth(88)
        browse.setStyleSheet(self._btn_ss("#3fb950"))
        browse.clicked.connect(self._browse_handshake)

        row.addWidget(self.file_path_edit)
        row.addWidget(browse)
        lay.addLayout(row)

        self.file_info_lbl = QLabel("No file selected")
        self.file_info_lbl.setStyleSheet("color:#8b949e; font-size:11px;")
        lay.addWidget(self.file_info_lbl)
        return grp

    def _build_mode_buttons(self):
        grp = self._group("⚔️  Attack Mode", "#ff006e")
        lay = QHBoxLayout(grp)
        lay.setSpacing(6)

        self.mode_group = QButtonGroup(self)
        modes = [
            ("🔨 Brute Force", 0, "#ff006e"),
            ("📖 Wordlist",    1, "#ffbe0b"),
            ("🎲 Dict+Rules",  2, "#8338ec"),
        ]
        for label, idx, color in modes:
            btn = QPushButton(label)
            btn.setCheckable(True)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background:#21262d; border:2px solid {color};
                    color:{color}; font-weight:bold; padding:8px 4px;
                    border-radius:6px; font-size:12px;
                }}
                QPushButton:checked {{ background:{color}; color:#0d1117; }}
                QPushButton:hover:!checked {{ background:#30363d; }}
            """)
            btn.clicked.connect(lambda _, i=idx: self.config_stack.setCurrentIndex(i))
            self.mode_group.addButton(btn, idx)
            lay.addWidget(btn)

        self.mode_group.button(0).setChecked(True)
        return grp

    def _build_brute_force_panel(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)

        grp = self._group("🔨  Brute Force Config", "#ff006e")
        gl = QVBoxLayout(grp)

        gl.addWidget(self._lbl("Hashcat Mask:"))
        self.mask_edit = QLineEdit()
        self.mask_edit.setPlaceholderText("e.g.  ?d?d?d?d?d?d?d?d")
        self.mask_edit.setStyleSheet(self._input_ss())
        gl.addWidget(self.mask_edit)

        help_lbl = QLabel(
            "?l = lowercase (a-z)     ?u = UPPERCASE (A-Z)\n"
            "?d = digit (0-9)          ?s = special  !@#$%\n"
            "Example:  ?d?d?d?d  →  1234"
        )
        help_lbl.setStyleSheet("color:#8b949e; font-size:11px; padding:4px;")
        gl.addWidget(help_lbl)

        gl.addWidget(self._lbl("Quick Presets:"))
        presets_row = QHBoxLayout()
        for name, mask in [("4-digit","?d?d?d?d"),
                            ("8-digit","?d?d?d?d?d?d?d?d"),
                            ("8-lower","?l?l?l?l?l?l?l?l"),
                            ("6-mix",  "?l?l?l?d?d?d")]:
            b = QPushButton(name)
            b.setFixedHeight(26)
            b.setStyleSheet("""
                QPushButton { background:#21262d; border:1px solid #30363d;
                    color:#cdd9e5; border-radius:4px; font-size:11px; }
                QPushButton:hover { background:#30363d; }
            """)
            b.clicked.connect(lambda _, m=mask: self.mask_edit.setText(m))
            presets_row.addWidget(b)
        gl.addLayout(presets_row)

        lay.addWidget(grp)
        lay.addStretch()
        return w

    def _build_wordlist_panel(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)

        grp = self._group("📖  Wordlist Config", "#ffbe0b")
        gl = QVBoxLayout(grp)

        gl.addWidget(self._lbl("Wordlist File:"))
        wl_row = QHBoxLayout()
        self.wl_edit = QLineEdit()
        self.wl_edit.setPlaceholderText("Select wordlist file …")
        self.wl_edit.setReadOnly(True)
        self.wl_edit.setStyleSheet(self._input_ss())
        wl_btn = QPushButton("📂")
        wl_btn.setFixedWidth(38)
        wl_btn.setStyleSheet(self._btn_ss("#ffbe0b"))
        wl_btn.clicked.connect(self._browse_wordlist)
        wl_row.addWidget(self.wl_edit)
        wl_row.addWidget(wl_btn)
        gl.addLayout(wl_row)

        self.wl_info_lbl = QLabel("No wordlist selected")
        self.wl_info_lbl.setStyleSheet("color:#8b949e; font-size:11px;")
        gl.addWidget(self.wl_info_lbl)

        gl.addWidget(self._lbl("Common Kali Wordlists:"))
        self.common_wl_combo = QComboBox()
        self.common_wl_combo.setStyleSheet(self._combo_ss())
        self.common_wl_combo.addItem("── select ──")
        for path in ["/usr/share/wordlists/rockyou.txt",
                     "/usr/share/wordlists/rockyou.txt.gz",
                     "/usr/share/wordlists/dirb/common.txt",
                     "/usr/share/wordlists/metasploit/unix_users.txt"]:
            if os.path.exists(path):
                self.common_wl_combo.addItem(Path(path).name, path)
        self.common_wl_combo.currentIndexChanged.connect(self._on_common_wl)
        gl.addWidget(self.common_wl_combo)

        lay.addWidget(grp)
        lay.addStretch()
        return w

    def _build_dict_rules_panel(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)

        grp = self._group("🎲  Dictionary + Rules Config", "#8338ec")
        gl = QVBoxLayout(grp)

        gl.addWidget(self._lbl("Wordlist File:"))
        dr_row = QHBoxLayout()
        self.dr_wl_edit = QLineEdit()
        self.dr_wl_edit.setPlaceholderText("Select wordlist …")
        self.dr_wl_edit.setReadOnly(True)
        self.dr_wl_edit.setStyleSheet(self._input_ss())
        dr_btn = QPushButton("📂")
        dr_btn.setFixedWidth(38)
        dr_btn.setStyleSheet(self._btn_ss("#8338ec"))
        dr_btn.clicked.connect(self._browse_dr_wordlist)
        dr_row.addWidget(self.dr_wl_edit)
        dr_row.addWidget(dr_btn)
        gl.addLayout(dr_row)

        gl.addWidget(self._lbl("Mutation Rule:"))
        self.rule_combo = QComboBox()
        self.rule_combo.setStyleSheet(self._combo_ss())
        for val, name in [("1","Append numbers (0-99)"),
                           ("2","Append symbols (!@#$%)"),
                           ("3","Capitalize first letter"),
                           ("4","All rules combined ★"),
                           ("5","No rules  (basic wordlist)")]:
            self.rule_combo.addItem(name, val)
        gl.addWidget(self.rule_combo)

        lay.addWidget(grp)
        lay.addStretch()
        return w

    def _build_action_buttons(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)

        self.start_btn = QPushButton("▶  START ATTACK")
        self.start_btn.setFixedHeight(46)
        self.start_btn.setStyleSheet("""
            QPushButton {
                background:#238636; border:2px solid #2ea043;
                color:#ffffff; font-weight:bold; font-size:14px; border-radius:8px;
            }
            QPushButton:hover { background:#2ea043; }
            QPushButton:disabled { background:#21262d; color:#484f58; border-color:#30363d; }
        """)
        self.start_btn.clicked.connect(self._start_attack)
        lay.addWidget(self.start_btn)

        self.stop_btn = QPushButton("⏹  STOP ATTACK")
        self.stop_btn.setFixedHeight(36)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background:#21262d; border:2px solid #ff006e;
                color:#ff006e; font-weight:bold; font-size:13px; border-radius:8px;
            }
            QPushButton:hover { background:#ff006e; color:#0d1117; }
            QPushButton:disabled { border-color:#30363d; color:#484f58; }
        """)
        self.stop_btn.clicked.connect(self._stop_attack)
        lay.addWidget(self.stop_btn)

        view_btn = QPushButton("📂  View Saved Passwords")
        view_btn.setFixedHeight(30)
        view_btn.setStyleSheet("""
            QPushButton {
                background:#21262d; border:1px solid #30363d;
                color:#8b949e; font-size:12px; border-radius:6px;
            }
            QPushButton:hover { background:#30363d; color:#cdd9e5; }
        """)
        view_btn.clicked.connect(self._load_saved_passwords)
        lay.addWidget(view_btn)
        return w

    # ── Right Panel ──────────────────────────────────────────────────────────

    def _build_right_panel(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(6, 0, 0, 0)
        lay.setSpacing(8)

        lay.addWidget(self._build_output_log(),        stretch=3)
        lay.addWidget(self._build_result_panel())
        lay.addWidget(self._build_saved_table(),       stretch=2)
        return w

    def _build_output_log(self):
        grp = self._group("📟  Live Output", "#00ff88")
        lay = QVBoxLayout(grp)

        self.output_log = QTextEdit()
        self.output_log.setReadOnly(True)
        self.output_log.setPlaceholderText("Attack output will appear here…")
        self.output_log.setStyleSheet("""
            QTextEdit {
                background:#0d1117; color:#00ff88;
                font-family:'Courier New',monospace; font-size:12px;
                border:1px solid #30363d; border-radius:4px; padding:6px;
            }
        """)
        lay.addWidget(self.output_log)

        clr = QPushButton("🗑  Clear")
        clr.setFixedHeight(22)
        clr.setStyleSheet("""
            QPushButton { background:#21262d; border:1px solid #30363d;
                color:#8b949e; border-radius:4px; font-size:11px; }
            QPushButton:hover { background:#30363d; }
        """)
        clr.clicked.connect(self.output_log.clear)
        lay.addWidget(clr)
        return grp

    def _build_result_panel(self):
        self.result_grp = self._group("🎉  Cracked Password", "#ffbe0b")
        self.result_grp.setVisible(False)
        lay = QVBoxLayout(self.result_grp)

        self.result_pw_lbl = QLabel("—")
        self.result_pw_lbl.setAlignment(Qt.AlignCenter)
        self.result_pw_lbl.setStyleSheet("""
            QLabel {
                color:#ffbe0b; font-size:24px; font-weight:bold;
                background:#161b22; border:2px solid #ffbe0b;
                border-radius:6px; padding:10px;
            }
        """)
        lay.addWidget(self.result_pw_lbl)

        self.result_details_lbl = QLabel()
        self.result_details_lbl.setAlignment(Qt.AlignCenter)
        self.result_details_lbl.setStyleSheet("color:#8b949e; font-size:11px;")
        lay.addWidget(self.result_details_lbl)
        return self.result_grp

    def _build_saved_table(self):
        grp = self._group("📂  Saved Passwords", "#8338ec")
        lay = QVBoxLayout(grp)

        self.saved_tbl = QTableWidget()
        self.saved_tbl.setColumnCount(5)
        self.saved_tbl.setHorizontalHeaderLabels(
            ["Password", "AP Name", "BSSID", "Method", "Timestamp"]
        )
        self.saved_tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.saved_tbl.setSelectionBehavior(QTableWidget.SelectRows)
        self.saved_tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.saved_tbl.setAlternatingRowColors(True)
        self.saved_tbl.setStyleSheet("""
            QTableWidget {
                background:#0d1117; color:#cdd9e5;
                gridline-color:#21262d; border:1px solid #30363d;
                border-radius:4px; font-size:12px;
            }
            QTableWidget::item          { padding:4px; }
            QTableWidget::item:selected { background:#1f6feb; color:#fff; }
            QTableWidget::item:alternate{ background:#161b22; }
            QHeaderView::section {
                background:#161b22; color:#8b949e; padding:6px;
                border:1px solid #30363d; font-weight:bold;
            }
        """)
        lay.addWidget(self.saved_tbl)
        return grp

    # ── Slots ────────────────────────────────────────────────────────────────

    def _browse_handshake(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Handshake File", "",
            "Handshake (*.cap *.pcap *.22000 *.hccapx);;All (*)"
        )
        if path:
            self.hash_file = path
            self.file_path_edit.setText(path)
            kb = os.path.getsize(path) / 1024
            self.file_info_lbl.setText(f"✓  {Path(path).name}  ({kb:.1f} KB)")
            self.file_info_lbl.setStyleSheet("color:#3fb950; font-size:11px;")

    def _browse_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Wordlist", "/usr/share/wordlists",
            "Wordlist (*.txt *.gz *.lst);;All (*)"
        )
        if path:
            self.wl_edit.setText(path)
            self._set_wl_info(path, self.wl_info_lbl)

    def _browse_dr_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Wordlist", "/usr/share/wordlists",
            "Wordlist (*.txt *.gz *.lst);;All (*)"
        )
        if path:
            self.dr_wl_edit.setText(path)

    def _on_common_wl(self, idx):
        data = self.common_wl_combo.itemData(idx)
        if data:
            self.wl_edit.setText(data)
            self._set_wl_info(data, self.wl_info_lbl)

    def _set_wl_info(self, path, label):
        try:
            sz = os.path.getsize(path)
            for unit in ("B", "KB", "MB", "GB"):
                if sz < 1024:
                    label.setText(f"✓  {Path(path).name}  ({sz:.1f} {unit})")
                    break
                sz /= 1024
            label.setStyleSheet("color:#3fb950; font-size:11px;")
        except Exception:
            label.setText("File selected")

    def _start_attack(self):
        if not self.hash_file:
            QMessageBox.warning(self, "No File", "Please select a handshake file first.")
            return

        mode = self.mode_group.checkedId()
        self.output_log.clear()
        self.result_grp.setVisible(False)
        self._set_running(True)

        if mode == 0:
            mask = self.mask_edit.text().strip()
            if not mask:
                QMessageBox.warning(self, "No Mask", "Enter a hashcat mask (e.g. ?d?d?d?d).")
                self._set_running(False)
                return
            self._log(f"[*] Brute Force  |  {Path(self.hash_file).name}  |  mask: {mask}")
            thread = BruteForceThread(self.hash_file, mask)

        elif mode == 1:
            wl = self.wl_edit.text().strip()
            if not wl or not os.path.exists(wl):
                QMessageBox.warning(self, "No Wordlist", "Select a valid wordlist file.")
                self._set_running(False)
                return
            self._log(f"[*] Wordlist Attack  |  {Path(self.hash_file).name}  |  {Path(wl).name}")
            thread = WordlistThread(self.hash_file, wl)

        else:
            dr_wl = self.dr_wl_edit.text().strip()
            if not dr_wl or not os.path.exists(dr_wl):
                QMessageBox.warning(self, "No Wordlist", "Select a valid wordlist file.")
                self._set_running(False)
                return
            rule = self.rule_combo.currentData()
            rule_name = self.rule_combo.currentText()
            self._log(f"[*] Dict+Rules  |  {Path(self.hash_file).name}  |  {rule_name}")
            thread = DictionaryRulesThread(self.hash_file, dr_wl, rule)

        self.current_thread = thread
        thread.output_line.connect(self._log)
        thread.password_found.connect(self._on_password_found)
        thread.attack_done.connect(self._on_attack_done)
        thread.start()

    def _stop_attack(self):
        if self.current_thread and self.current_thread.isRunning():
            self._log("[!] Stopping…")
            self.current_thread.stop()
            self.current_thread.wait(3000)
            self._log("[✓] Attack stopped")
        self._set_running(False)

    def _set_running(self, running: bool):
        self.start_btn.setEnabled(not running)
        self.stop_btn.setEnabled(running)
        self.progress_bar.setVisible(running)

    def _log(self, msg: str):
        if   any(x in msg for x in ("[✓]","KEY FOUND","cracked","Cracked")):
            color = "#00ff88"
        elif any(x in msg for x in ("[!]","error","failed","not found","Error")):
            color = "#ff006e"
        elif any(x in msg for x in ("[*]","Starting","Running","Generating")):
            color = "#ffbe0b"
        else:
            color = "#cdd9e5"

        self.output_log.append(f'<span style="color:{color};">{msg}</span>')
        self.output_log.verticalScrollBar().setValue(
            self.output_log.verticalScrollBar().maximum()
        )

    def _on_password_found(self, password: str):
        self.result_grp.setVisible(True)
        self.result_pw_lbl.setText(f"🔑  {password}")

        parts  = Path(self.hash_file).name.split("_")
        ap     = parts[0] if parts else "Unknown"
        bssid  = parts[1] if len(parts) > 1 else "Unknown"
        method = {0:"Brute Force",1:"Wordlist Attack",2:"Dictionary+Rules"}.get(
            self.mode_group.checkedId(), "Unknown"
        )
        self.result_details_lbl.setText(
            f"AP: {ap}   |   BSSID: {bssid}   |   Method: {method}"
        )
        self._save_password(password, method)

    def _on_attack_done(self, success: bool, msg: str):
        self._set_running(False)
        self._log(f"[✓] {msg}" if success else f"[!] {msg}")
        self._load_saved_passwords()

    # ── Persistence ──────────────────────────────────────────────────────────

    def _save_password(self, password: str, method: str):
        try:
            proj_root  = Path(__file__).parent.parent
            pw_dir     = proj_root / "passwords"
            pw_dir.mkdir(parents=True, exist_ok=True)
            results    = pw_dir / "cracked_passwords.json"

            data: dict = {}
            if results.exists():
                try:
                    data = json.loads(results.read_text())
                except Exception:
                    data = {}

            filename = Path(self.hash_file).name
            parts    = filename.split("_")
            entry = {
                "password":  password.strip(),
                "ap_name":   parts[0] if parts else "Unknown",
                "bssid":     parts[1] if len(parts) > 1 else "Unknown",
                "file":      filename,
                "timestamp": datetime.now().isoformat(),
                "method":    method,
            }
            data.setdefault(filename, []).append(entry)
            results.write_text(json.dumps(data, indent=2))
            self._log("[✓] Saved to cracked_passwords.json")
        except Exception as exc:
            self._log(f"[!] Save error: {exc}")

    def _load_saved_passwords(self):
        try:
            proj_root = Path(__file__).parent.parent
            results   = proj_root / "passwords" / "cracked_passwords.json"
            if not results.exists():
                return
            data = json.loads(results.read_text())
            self.saved_tbl.setRowCount(0)
            for entries in data.values():
                for entry in entries:
                    row = self.saved_tbl.rowCount()
                    self.saved_tbl.insertRow(row)

                    pw_item = QTableWidgetItem(entry.get("password",""))
                    pw_item.setForeground(QBrush(QColor("#ffbe0b")))
                    pw_item.setFont(QFont("Courier New", 11, QFont.Bold))
                    self.saved_tbl.setItem(row, 0, pw_item)
                    self.saved_tbl.setItem(row, 1, QTableWidgetItem(entry.get("ap_name","")))
                    self.saved_tbl.setItem(row, 2, QTableWidgetItem(entry.get("bssid","")))

                    m_item = QTableWidgetItem(entry.get("method",""))
                    m_item.setForeground(QBrush(QColor("#8338ec")))
                    self.saved_tbl.setItem(row, 3, m_item)
                    self.saved_tbl.setItem(row, 4,
                        QTableWidgetItem(entry.get("timestamp","")[:16].replace("T"," ")))
        except Exception as exc:
            self._log(f"[!] Load error: {exc}")

    # ── Style Helpers ────────────────────────────────────────────────────────

    def _group(self, title: str, accent: str) -> QGroupBox:
        grp = QGroupBox(title)
        grp.setStyleSheet(f"""
            QGroupBox {{
                color:{accent}; font-weight:bold; font-size:13px;
                border:2px solid {accent}; border-radius:8px;
                margin-top:10px; padding-top:4px;
            }}
            QGroupBox::title {{
                subcontrol-origin:margin; left:10px;
                padding:0 6px; background:#0d1117;
            }}
        """)
        return grp

    def _lbl(self, text: str) -> QLabel:
        l = QLabel(text)
        l.setStyleSheet("color:#cdd9e5; font-size:12px;")
        return l

    def _input_ss(self) -> str:
        return """
            QLineEdit {
                background:#161b22; color:#cdd9e5;
                border:1px solid #30363d; border-radius:4px;
                padding:6px 8px; font-size:12px;
            }
            QLineEdit:focus { border-color:#58a6ff; }
        """

    def _btn_ss(self, color: str) -> str:
        return f"""
            QPushButton {{
                background:#21262d; border:2px solid {color};
                color:{color}; font-weight:bold;
                border-radius:4px; padding:4px 8px;
            }}
            QPushButton:hover {{ background:{color}; color:#0d1117; }}
        """

    def _combo_ss(self) -> str:
        return """
            QComboBox {
                background:#161b22; color:#cdd9e5;
                border:1px solid #30363d; border-radius:4px;
                padding:5px 8px; font-size:12px;
            }
            QComboBox::drop-down { border:none; }
            QComboBox QAbstractItemView {
                background:#161b22; color:#cdd9e5;
                selection-background-color:#1f6feb;
            }
        """
