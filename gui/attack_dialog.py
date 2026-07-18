from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QProgressBar, QTextEdit
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt5.QtGui import QFont, QColor, QBrush
import time

class AttackExecutionDialog(QDialog):
    """Visual attack execution dialog with animations"""
    
    def __init__(self, parent=None, attack_type="", target=""):
        super().__init__(parent)
        self.attack_type = attack_type
        self.target = target
        self.setWindowTitle(f"⚔️ {attack_type.upper()} Attack")
        self.setModal(True)
        self.setMinimumSize(700, 500)
        self.setStyleSheet("""
            QDialog {
                background: #0d1117;
                border: 2px solid #ff006e;
                border-radius: 10px;
            }
        """)
        
        # Attack color map
        self.color_map = {
            "handshake": "#ffbe0b",
            "deauth": "#ff006e",
            "evil_twin": "#fb5607",
            "wps": "#8338ec"
        }
        
        self.attack_color = self.color_map.get(attack_type, "#00ff88")
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title with animation
        title = QLabel(f"⚔️ {self.attack_type.upper()} ATTACK")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(f"""
            font-size: 24px;
            font-weight: bold;
            color: {self.attack_color};
            padding: 15px;
            border-bottom: 2px solid {self.attack_color};
        """)
        layout.addWidget(title)
        
        # Target info
        target_label = QLabel(f"🎯 Target: {self.target}")
        target_label.setStyleSheet("color: #c9d1d9; font-size: 14px; padding: 10px;")
        layout.addWidget(target_label)
        
        # Progress with animation
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setStyleSheet(f"""
            QProgressBar {{
                border: 2px solid {self.attack_color};
                border-radius: 5px;
                background: #161b22;
                color: {self.attack_color};
                text-align: center;
                font-weight: bold;
            }}
            QProgressBar::chunk {{
                background: {self.attack_color};
                border-radius: 3px;
            }}
        """)
        layout.addWidget(self.progress)
        
        # Status display with ASCII art
        self.status_display = QLabel()
        self.status_display.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_display.setFont(QFont("Courier", 11))
        self.status_display.setStyleSheet(f"color: {self.attack_color}; padding: 20px;")
        layout.addWidget(self.status_display)
        
        # Attack log
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setStyleSheet("""
            QTextEdit {
                background: #161b22;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 5px;
                font-family: Courier;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.log_view)
        
        self.setLayout(layout)
        
        # Animation timer
        self.animation_timer = QTimer()
        self.animation_timer.timeout.connect(self.animate_attack)
        self.animation_frames = 0
        
    def start_attack_animation(self):
        """Start attack visualization"""
        self.animation_timer.start(200)
        self.log_message(f"🚀 {self.attack_type.upper()} attack initiated...")
        
    def animate_attack(self):
        """Animate attack execution with visual feedback"""
        self.animation_frames += 1
        progress = min(self.animation_frames * 5, 100)
        self.progress.setValue(progress)
        
        # ASCII animations for different attacks
        if self.attack_type == "handshake":
            self.show_handshake_animation(progress)
        elif self.attack_type == "deauth":
            self.show_deauth_animation(progress)
        elif self.attack_type == "evil_twin":
            self.show_evil_twin_animation(progress)
        elif self.attack_type == "wps":
            self.show_wps_animation(progress)
            
        if progress >= 100:
            self.animation_timer.stop()
            self.log_message("✅ Attack execution complete!")
            
    def show_handshake_animation(self, progress):
        """Show handshake capture animation"""
        stages = [
            ("Listening for beacon frames...", """
     📡
    ═══════
    │ BEACON │
    ═════════
            """),
            ("Waiting for client association...", """
     📱  📡
    ══════════
    │ ASSOC  │
    ══════════
            """),
            ("EAPOL Frame 1 captured!", """
     📱  📡
    ┌──────────┐
    │ EAPOL-1  │
    └──────────┘
            """),
            ("EAPOL Frame 2 captured!", """
     📱  📡
    ┌──────────┐
    │ EAPOL-2  │
    └──────────┘
            """),
            ("Handshake Complete!", """
     ✅ HANDSHAKE CAPTURED ✅
    ╔════════════════════╗
    ║ 4-Way Handshake OK ║
    ╚════════════════════╝
            """)
        ]
        
        stage_idx = min(progress // 20, len(stages) - 1)
        stage_text, ascii_art = stages[stage_idx]
        
        self.log_message(f"[{progress}%] {stage_text}")
        self.status_display.setText(ascii_art)
        
    def show_deauth_animation(self, progress):
        """Show deauthentication animation"""
        stages = [
            ("Crafting deauth packets...", """
     ⚡ DEAUTH ATTACK ⚡
    ╔════════════════╗
    ║ Crafting Frames║
    ╚════════════════╝
            """),
            ("Sending deauth frames...", """
     ⚡⚡⚡ TRANSMITTING ⚡⚡⚡
    ►►►►► DEAUTH PACKETS ◄◄◄◄◄
    [██████░░░░░░░░░░░░] 30%
            """),
            ("Target disconnected!", """
     ✅ DEAUTH SUCCESSFUL ✅
    ╔══════════════════════╗
    ║ Client Disconnected! ║
    ╚══════════════════════╝
            """)
        ]
        
        stage_idx = min(progress // 33, len(stages) - 1)
        stage_text, ascii_art = stages[stage_idx]
        
        self.log_message(f"[{progress}%] {stage_text}")
        self.status_display.setText(ascii_art)
        
    def show_evil_twin_animation(self, progress):
        """Show Evil Twin animation"""
        stages = [
            ("Creating rogue access point...", """
     👿 EVIL TWIN 👿
    ╔═══════════════╗
    ║ Creating AP   ║
    ╚═══════════════╝
            """),
            ("Setting up DHCP server...", """
     👿 EVIL TWIN 👿
    ╔═══════════════════╗
    ║ DHCP: 192.168.1.1 ║
    ╚═══════════════════╝
            """),
            ("Clients connecting...", """
     👿 ROGUE AP ACTIVE 👿
    ╔════════════════════╗
    ║ Clients: 2 connected║
    ║ Traffic: Sniffing  ║
    ╚════════════════════╝
            """)
        ]
        
        stage_idx = min(progress // 33, len(stages) - 1)
        stage_text, ascii_art = stages[stage_idx]
        
        self.log_message(f"[{progress}%] {stage_text}")
        self.status_display.setText(ascii_art)
        
    def show_wps_animation(self, progress):
        """Show WPS PIN cracking animation"""
        stages = [
            ("Initializing WPS attack...", """
     🔐 WPS PIN ATTACK 🔐
    ╔════════════════╗
    ║ Initializing   ║
    ╚════════════════╝
            """),
            ("Testing PIN batches...", """
     🔐 WPS PIN ATTACK 🔐
    ╔════════════════════╗
    ║ Testing: 10000-19999║
    ║ Speed: 1.2 PIN/sec ║
    ╚════════════════════╝
            """),
            ("PIN Found!", """
     ✅ WPS PIN CRACKED ✅
    ╔════════════════════╗
    ║ PIN: 12345670      ║
    ║ PSK: obtained      ║
    ╚════════════════════╝
            """)
        ]
        
        stage_idx = min(progress // 33, len(stages) - 1)
        stage_text, ascii_art = stages[stage_idx]
        
        self.log_message(f"[{progress}%] {stage_text}")
        self.status_display.setText(ascii_art)
        
    def log_message(self, message):
        """Add message to log"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_view.append(f"[{timestamp}] {message}")
