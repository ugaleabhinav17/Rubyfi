"""Interface Management Dialog for RubyFi"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, 
    QLabel, QListWidget, QListWidgetItem, QMessageBox
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont
from utils.interface_manager import InterfaceManager
from utils.monitor import MonitorManager
import subprocess
import re

class InterfaceDialog(QDialog):
    """Dialog for managing wireless interfaces"""
    
    interface_changed = pyqtSignal(str, str)  # interface, mode
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("🔧 Interface Management")
        self.setModal(True)
        self.setMinimumSize(600, 400)
        self.selected_interface = None
        self.selected_mode = None 
        self.manager = InterfaceManager()
        self.monitor_manager=MonitorManager()
        self.current_interface_from_parent = None 
        self.init_ui()
        # Get current interface from parent window
        if hasattr(parent, 'current_interface'):
            self.current_interface_from_parent = parent.current_interface
        self.load_interfaces()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("🔧 INTERFACE MANAGEMENT")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("""
            font-size: 18px; 
            font-weight: bold; 
            color: #00ff88; 
            margin: 10px;
        """)
        layout.addWidget(header)
        
        # Interface list label
        list_label = QLabel("Available Wireless Interfaces:")
        list_label.setStyleSheet("color: #c9d1d9; font-weight: bold;")
        layout.addWidget(list_label)
        
        # Interface list widget
        self.interface_list = QListWidget()
        self.interface_list.setStyleSheet("""
            QListWidget {
                background: #0d1117;
                border: 2px solid #30363d;
                border-radius: 8px;
                color: #c9d1d9;
                font-size: 13px;
                padding: 5px;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #21262d;
            }
            QListWidget::item:selected {
                background: #238636;
                color: white;
            }
            QListWidget::item:hover {
                background: #21262d;
            }
        """)
        self.interface_list.itemClicked.connect(self.on_interface_selected)
        layout.addWidget(self.interface_list)
        
        # Action buttons with FIXED styling
        btn_layout = QHBoxLayout()
        
        self.monitor_btn = QPushButton("📡 Enable Monitor Mode")
        self.monitor_btn.clicked.connect(self.enable_monitor)
        self.monitor_btn.setEnabled(False)
        
        self.managed_btn = QPushButton("🔌 Disable Monitor Mode")
        self.managed_btn.clicked.connect(self.disable_monitor)
        self.managed_btn.setEnabled(False)
        
        self.mac_btn = QPushButton("🔀 Change MAC Address")
        self.mac_btn.clicked.connect(self.change_mac)
        self.mac_btn.setEnabled(False)
        
        # Apply SAME styling to ALL buttons (including disabled state)
        button_style = """
            QPushButton {
                background: #21262d;
                border: 2px solid #00ff88;
                color: #00ff88;
                padding: 10px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover:enabled {
                background: #00ff88;
                color: #0d1117;
            }
            QPushButton:disabled {
                background: #161b22;
                border: 2px solid #30363d;
                color: #30363d;
            }
        """
        
        for btn in [self.monitor_btn, self.managed_btn, self.mac_btn]:
            btn.setStyleSheet(button_style)
            btn.setMinimumHeight(40)
        
        btn_layout.addWidget(self.monitor_btn)
        btn_layout.addWidget(self.managed_btn)
        btn_layout.addWidget(self.mac_btn)
        layout.addLayout(btn_layout)
        
        # Close button
        close_btn = QPushButton("✅ Done")
        close_btn.clicked.connect(self.accept)
        close_btn.setStyleSheet("""
            QPushButton {
                background: #238636;
                border: 2px solid #238636;
                color: white;
                padding: 10px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background: #2ea043;
            }
        """)
        layout.addWidget(close_btn)
        
        self.setLayout(layout)

    
    # in interface_dialog.py - replace load_interfaces() with:

    # --- replace load_interfaces, on_interface_selected, enable_monitor, disable_monitor ---

    def load_interfaces(self):
        """Load wireless interfaces. Prefer InterfaceManager.list_interfaces() for consistency."""
        self.interface_list.clear()
        interfaces = []

        # Preferred: use InterfaceManager.list_interfaces() (uses `iw dev`)
        try:
            ifaces = self.manager.list_interfaces()
            for iface in ifaces:
                mode = self.manager.get_interface_mode(iface) or "Unknown"
                interfaces.append((iface, mode))
        except Exception:
            # fallback to old iwconfig parsing when 'iw' isn't available
            try:
                result = subprocess.run(['iwconfig'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if line and not line.startswith(' '):
                        parts = line.split()
                        iface = parts[0]
                        if "no wireless extensions" not in line:
                            mode = "Managed"
                            if "Mode:Monitor" in line or "Mode: monitor" in line:
                                mode = "Monitor"
                            interfaces.append((iface, mode))
            except FileNotFoundError:
                pass

        print("DEBUG interfaces from load_interfaces:", interfaces)

        if not interfaces:
            QMessageBox.warning(
                self,
                "No Interfaces",
                "No wireless interfaces found.\n\nOn Linux, check: iw dev / iwconfig\nOn Windows, you must run this on Kali/WSL for WiFi features."
            )
            return

        # add items to list
        for iface, mode in interfaces:
            mode_icon = "📡" if str(mode).lower() == "monitor" else "🔌"
            item = QListWidgetItem(f"{mode_icon} {iface} ({mode})")
            # store canonical iface and mode in user role
            item.setData(Qt.ItemDataRole.UserRole, (iface, str(mode)))
            self.interface_list.addItem(item)

        # Decide which item to select:
        # prefer: active_interface (monitor interface we created), then parent.current_interface, else first
        selection_target = getattr(self, "active_interface", None) or self.current_interface_from_parent

        selected_item = None
        if selection_target:
            # find item whose iface matches selection_target
            for idx in range(self.interface_list.count()):
                it = self.interface_list.item(idx)
                data = it.data(Qt.ItemDataRole.UserRole)
                if data and data[0] == selection_target:
                    selected_item = it
                    break

        if selected_item is None:
            selected_item = self.interface_list.item(0)

        if selected_item:
            self.interface_list.setCurrentItem(selected_item)
            # call selection handler to set buttons correctly
            self.on_interface_selected(selected_item)


    def on_interface_selected(self, item):
        """Handle interface selection"""
        data = item.data(Qt.ItemDataRole.UserRole)
        if not data:
            return

        self.selected_interface, self.selected_mode = data
        # normalize the mode string for comparison
        mode_norm = str(self.selected_mode).lower()

        # Enable/disable buttons based on normalized mode
        if mode_norm == "managed" or mode_norm == "up" or mode_norm == "station":
            # managed-like states
            self.monitor_btn.setEnabled(True)
            self.managed_btn.setEnabled(False)
        elif mode_norm == "monitor":
            # monitor-like state
            self.monitor_btn.setEnabled(False)
            self.managed_btn.setEnabled(True)
        else:
            # unknown; be conservative - enable change mac, enable monitor
            self.monitor_btn.setEnabled(True)
            self.managed_btn.setEnabled(False)

        self.mac_btn.setEnabled(True)
        # keep base_interface in sync (useful later)
        # if user selected a monitor iface, base_interface remains unchanged unless we stored it earlier
        if not hasattr(self, "base_interface"):
            self.base_interface = None


    def enable_monitor(self):
        if not self.selected_interface:
            return

        try:
            # DO NOT guess interface name — let monitor_manager return the real name
            monitor_iface = self.monitor_manager.enable_monitor(self.selected_interface)

            if not monitor_iface:
                QMessageBox.warning(self, "Failed", "Monitor mode could not be enabled.")
                return

            # store the real monitor interface and also keep the base interface
            self.base_interface = self.selected_interface
            self.active_interface = monitor_iface

            QMessageBox.information(
                self,
                "Monitor Enabled",
                f"Monitor mode enabled:\n{self.base_interface} → {monitor_iface}"
            )

            # Notify parent (top-left label + logs) — send the actual interface name to show
            self.interface_changed.emit(monitor_iface, "Monitor")

            # reload to reflect newly created interface; load_interfaces will try to select active_interface
            self.load_interfaces()

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))


    def disable_monitor(self):
        try:
            # Prefer the interface that is actually active (monitor iface), fallback to selected_interface
            iface_to_disable = getattr(self, "active_interface", None) or self.selected_interface

            restored_iface = self.monitor_manager.disable_monitor(iface_to_disable)

            # If restore failed the manager may return False/None
            if not restored_iface:
                QMessageBox.warning(
                    self,
                    "Warning",
                    "Could not reliably disable monitor mode. Check terminal."
                )
                return

            # Clear active_interface (monitor no longer exists) and update base_interface
            self.active_interface = None
            self.base_interface = restored_iface

            QMessageBox.information(
                self,
                "Monitor Disabled",
                f"Monitor mode disabled:\n{iface_to_disable} → {restored_iface}"
            )

            # Update UI & logs: tell parent the interface that should be shown now (managed)
            self.interface_changed.emit(restored_iface, "Managed")

            # reload to reflect new modes; load_interfaces will select restored_iface if present
            self.load_interfaces()

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    
    def showEvent(self, event):
        """Called when dialog is shown - refresh interface list"""
        super().showEvent(event)
        
        # Update current interface from parent
        if hasattr(self.parent(), 'current_interface'):
            self.current_interface_from_parent = self.parent().current_interface
        
        # Reload interfaces to show current state
        self.load_interfaces()

    def change_mac(self):
        """Change MAC address with visual feedback"""
        if not self.selected_interface:
            return
        
        try:
            # Check if macchanger exists
            result = subprocess.run(['which', 'macchanger'], capture_output=True)
            if result.returncode != 0:
                QMessageBox.warning(self, "Missing Tool", 
                    "macchanger not installed.\n\nInstall: sudo apt install macchanger")
                return
            
            # Get old MAC first
            old_mac_result = subprocess.run(
                ['cat', f'/sys/class/net/{self.selected_interface}/address'],
                capture_output=True, text=True
            )
            old_mac = old_mac_result.stdout.strip() if old_mac_result.returncode == 0 else "Unknown"
            
            # Change MAC
            subprocess.run(['ip', 'link', 'set', self.selected_interface, 'down'], check=True)
            
            mac_result = subprocess.run(
                ['macchanger', '-r', self.selected_interface],
                capture_output=True, text=True
            )
            
            subprocess.run(['ip', 'link', 'set', self.selected_interface, 'up'], check=True)
            
            # Parse new MAC from macchanger output
            new_mac = "Unknown"
            if "New MAC" in mac_result.stdout:
                import re
                match = re.search(r'New\s+MAC:\s+([0-9a-fA-F:]{17})', mac_result.stdout)
                if match:
                    new_mac = match.group(1)
            
            # Show detailed result
            QMessageBox.information(self, "✅ MAC Changed Successfully", 
                f"Interface: {self.selected_interface}\n\n"
                f"Old MAC: {old_mac}\n"
                f"New MAC: {new_mac}\n\n"
                f"Vendor: (unknown)")
            
            # Log to parent window if available
            if hasattr(self.parent(), 'log'):
                self.parent().log(f"🔀 MAC changed: {self.selected_interface}")
                self.parent().log(f"   Old: {old_mac}")
                self.parent().log(f"   New: {new_mac}")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", 
                f"Failed to change MAC: {e}\n\n"
                f"Make sure macchanger is installed:\n"
                f"sudo apt install macchanger")
