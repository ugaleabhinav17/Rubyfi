# main.py

import os
import subprocess
import sys
import time
import json
import shutil
from typing import Optional, Dict, Any
from termcolor import colored
# from attacks.csa_injection import CSAInjection
import config
from utils.scan_networks import WiFiScanner
from utils.monitor import MonitorManager
from utils.interface_manager import InterfaceManager
from attacks.handshake import HandshakeCapture
from attacks.deauth import DeauthAttack
from attacks.beacon_flood import BeaconFlood
from attacks.ssl_strip import SSLStripAttack
from attacks.dns_spoof import DNSSpoofAttack
from attacks.wifi_phishing import WiFiPhishing
from attacks.evil_twin_deauth import EvilTwinDeauth

# from attacks.nodogsplash_attack import NodogsplashAttack

class WiFiToolkit:
    """Enhanced WiFi Toolkit with all improvements."""
    
    def __init__(self):
        """Initialize toolkit state."""
        self.iface: Optional[str] = None
        self.base_iface: Optional[str] = None
        self.monitor_iface: Optional[str] = None
        self.target: Optional[Dict[str, Any]] = None
        self.monitor_mgr = MonitorManager()
        self.interface_mgr = InterfaceManager()
        self.scanner = WiFiScanner()

    def wifiphisher_cleanup(self):
        """Kill all previous attacks before starting new one."""
        print(colored("\n🧹 Clearing previous attacks...", "cyan"))

        for proc in ["wifiphisher", "airbase-ng", "hostapd", "lighttpd",
                     "dnsmasq", "mdk4", "aireplay-ng", "airodump-ng",
                     "bettercap", "hostapd"]:
            subprocess.run(f"pkill -f {proc}", shell=True, capture_output=True)

        for i in range(5):
            subprocess.run(f"ip link set at{i} down 2>/dev/null",
                           shell=True, capture_output=True)

        subprocess.run("systemctl stop NetworkManager",  shell=True, capture_output=True)
        time.sleep(1)
        subprocess.run("systemctl start NetworkManager", shell=True, capture_output=True)

        subprocess.run("iptables -t nat -F 2>/dev/null", shell=True, capture_output=True)
        subprocess.run("iptables -F 2>/dev/null",        shell=True, capture_output=True)
        subprocess.run("ip neigh flush all 2>/dev/null", shell=True, capture_output=True)

        for f in ["/var/lib/misc/dnsmasq.leases", "/tmp/dnsmasq.leases",
                  "/tmp/*wifiphisher*", "/tmp/*evil*", "/tmp/*csa*"]:
            subprocess.run(f"rm -f {f}", shell=True, capture_output=True)

        time.sleep(2)
        print(colored("[✓] All previous attacks cleared!\n", "green"))


    def run(self):
        """Main application loop."""
        try:
            self.monitor_mgr.check_root()
            self.monitor_mgr.check_dependencies()
        except SystemExit as e:
            print(e)
            return
        
        auto_iface = self.interface_mgr.auto_select_interface()
        if auto_iface:
            self.base_iface = auto_iface
            self.iface = auto_iface
        
        self._load_last_target()
        
        while True:
            self._display_menu()
            choice = input(colored(" ➤ Choose option: ", "cyan", attrs=['bold'])).strip()
            
            if choice == "1":
                self.manage_interfaces()
            elif choice == "2":
                self.scan_and_select_ap_procedure()
            elif choice == "3":
                self.launch_attacks()
            elif choice == "4":
                self.password_cracking()
            elif choice == "0":
                self._handle_exit()
                break
            else:
                print(colored("\n [!] Invalid option!", "red"))
                time.sleep(1)
    def password_cracking(self):
        """Password cracking menu."""
        from attacks.cracking.menu import CrackingMenu
        menu = CrackingMenu()
        while menu.display():
            pass

    def scan_and_select_ap_procedure(self):
        """Network scanning procedure."""
        os.system('cls' if os.name == 'nt' else 'clear')
        self._display_banner()
        
        print("\n" + colored("╔" + "═" * 58 + "╗", "cyan", attrs=['bold']))
        print(colored("║" + " " * 16 + "📡 NETWORK SCAN MODULE" + " " * 20 + "║", "cyan", attrs=['bold']))
        print(colored("╚" + "═" * 58 + "╝", "cyan", attrs=['bold']))
        
        
        self._prompt_for_scan_cleanup()
        
        if not self._ensure_interface_selected():
            input("\nPress Enter to return...")
            return
        
        monitor_iface = None
        try:
            monitor_iface = self.monitor_mgr.enable_monitor(self.iface)
            if not monitor_iface:
                raise RuntimeError("Failed to enable monitor mode")
            
            self.monitor_iface = monitor_iface
            networks = self.scanner.run_scan(monitor_iface)
            
            if not networks:
                print(colored("\n[!] No networks found.", "yellow"))
                return
            
            self.target = None
            self._select_ap_from_scan(networks)
            self._save_target()
            
        except Exception as e:
            print(colored(f"[!] Error during scan: {e}", "red"))
        finally:
            if monitor_iface:
                restored = self.monitor_mgr.disable_monitor(monitor_iface)
                if restored:
                    self.iface = restored
                    self.base_iface = restored
                    self.monitor_iface = None
            
            print(colored("\n[*] Scan complete. Interface restored.", "cyan"))
            input("\nPress Enter to return...")
    
    def launch_attacks(self):
        """Attack menu."""
        os.system('cls' if os.name == 'nt' else 'clear')
        self._display_banner()
        
        print("\n" + colored("╔" + "═" * 58 + "╗", "red", attrs=['bold']))
        print(colored("║" + " " * 19 + "⚔️  ATTACK MODULE" + " " * 23 + "║", "red", attrs=['bold']))
        print(colored("╚" + "═" * 58 + "╝", "red", attrs=['bold']))
        
        if not self.target and not self._load_last_target():
            print(colored("\n[-] No target selected. Run scan first.", "red"))
            input("\nPress Enter...")
            return
        
        if not self._ensure_interface_selected():
            input("\nPress Enter...")
            return
        
        monitor_iface = None
        try:
            # monitor_iface = self.monitor_mgr.enable_monitor(self.iface)
            # if not monitor_iface:
            #     print(colored("\n[!] Failed to enable monitor mode.", "red"))
            #     input("\nPress Enter...")
            #     return
            
            self.monitor_iface = monitor_iface
            
            print(f"\n📍 Target: {colored(self.target['ssid'], 'yellow', attrs=['bold'])}")
            print(f"   BSSID: {self.target['bssid']} | Channel: {self.target['channel']}")
            
            # Display security info
            if self.target.get('is_wpa3', False):
                print(colored(f"   Security: 🔒 WPA3 (SAE)", "red", attrs=['bold']))
            else:
                sec_type = self.target.get('enc', 'Unknown')
                print(f"   Security: {sec_type}")
            
            # print(f"   Using: {colored(monitor_iface, 'cyan')}\n")
            
            print(colored(" [1]", "red", attrs=['bold']) + " 🎯 Handshake Capture")
            print(colored(" [2]", "red", attrs=['bold']) + " 💥 Deauthentication Attacks")
            print(colored(" [3]", "red", attrs=['bold']) + " 🔐 WPS PIN Attack")
            print(colored(" [4]", "red", attrs=['bold']) + " 🕵️ Evil Twin + DEAUTH (MiTM))")
            print(colored(" [5]", "red", attrs=['bold']) + " 📡 Beacon Flood (SSID Chaos)")
            # print(colored(" [6]", "red", attrs=['bold']) + " 🍋 SSL Stripping (HTTPS Downgrade)")
            # print(colored(" [7]", "red", attrs=['bold']) + " 🎯 DNS Spoofing (Redirection)")
            print(colored(" [6]", "red", attrs=['bold']) + " 🎣 Wi-Fi Phishing (Firmware Upgrade)")
            print(colored(" [D]", "green", attrs=['bold']) + " 🔓 View Decrypted Credentials")
            print(colored(" [0]", "white") + " ⬅️  Back")
            
            choice = input(colored("\n ➤ Select attack: ", "cyan", attrs=['bold'])).strip()
            

            if choice in ['1', '2', '3', '4', '5', '6', '7']:
                monitor_iface = self.monitor_mgr.enable_monitor(self.iface)
                if not monitor_iface:
                    print(colored("\n[!] Failed to enable monitor mode.", "red"))
                    input("\nPress Enter...")
                    return
            
            else:  # choice == '8'
                monitor_iface = self.base_iface  # keep wlan0 managed
                print(colored(f"[*] Using managed interface for phishing: {monitor_iface}", "cyan"))
            if choice == '1':
                attack = HandshakeCapture(
                    bssid=self.target['bssid'],
                    ssid=self.target['ssid'],
                    channel=self.target['channel'],
                    monitor_interface=monitor_iface,
                    target_info=self.target
                )
                attack.run_capture()
                input("\nPress Enter...")
            
            elif choice == '2':
                self._deauth_submenu(monitor_iface)
            
            elif choice == '3':
                from attacks.wps_attack import WPSAttack
                wps = WPSAttack(
                    monitor_interface=monitor_iface,
                    bssid=self.target['bssid'],
                    ssid=self.target['ssid'],
                    channel=self.target['channel']
                )
                wps.run()
                input("\nPress Enter...")
            
            # In main.py - inside launch_attacks()

            elif choice == '4':
                self._evil_twin_deauth_submenu(monitor_iface)

            # elif choice == '4':
            #     self.wifiphisher_cleanup()
            #     from attacks.downgrade_attack import WPA3DowngradeAttack
            #     attack = WPA3DowngradeAttack(
            #         monitor_interface=monitor_iface,
            #         target_bssid=self.target['bssid'],
            #         target_ssid=self.target['ssid'],
            #         target_channel=self.target['channel']
            #     )
            #     attack.run()

            
            elif choice == '5': # Added
                attack = BeaconFlood(
                    monitor_interface=monitor_iface,
                    target_ssid=self.target['ssid'],
                    target_channel=self.target['channel']
                )
                attack.run()
                input("\nPress Enter...")
            
            elif choice == '6':
                attack = SSLStripAttack(
                    monitor_interface=monitor_iface,
                    target_bssid=self.target['bssid'],
                    target_ssid=self.target['ssid'],
                    target_channel=self.target['channel']
                )
                attack.run()
                input("\nPress Enter...")
            
            elif choice == '7': # Added logic
                attack = DNSSpoofAttack(
                    monitor_interface=monitor_iface,
                    target_bssid=self.target['bssid'],
                    target_ssid=self.target['ssid'],
                    target_channel=self.target['channel']
                )
                attack.run()
                input("\nPress Enter...")
            
            # elif choice == '8':
            #     attack = WiFiPhishing(
            #         monitor_interface=monitor_iface,
            #         target_bssid=self.target['bssid'],
            #         target_ssid=self.target['ssid'],
            #         target_channel=self.target['channel']
            #     )
            #     attack.run()

            elif choice == '8':
            #     MonitorManager.disable_monitor(self.base_iface)
                attack = WiFiPhishing(
                    ap_interface=self.base_iface,          # ← use existing attribute
                    target_bssid=self.target['bssid'],
                    target_ssid=self.target['ssid'],
                    target_channel=self.target['channel']
                )
                attack.run()



        
            elif choice.lower() == 'd':
                from utils.harvester import CredentialHarvester
                h = CredentialHarvester()
                h.extract()
                input("\nPress Enter to return...")
        
        finally:
            if monitor_iface:
                restored = self.monitor_mgr.disable_monitor(monitor_iface)
                if restored:
                    self.iface = restored
                    self.base_iface = restored
                    self.monitor_iface = None
                print(colored("\n[*] Attack complete. Interface restored.", "cyan"))
    
    def _deauth_submenu(self, monitor_iface: str):
        """Deauthentication attack submenu."""
        os.system('cls' if os.name == 'nt' else 'clear')
        self._display_banner()
        
        print("\n" + colored("╔" + "═" * 58 + "╗", "yellow", attrs=['bold']))
        print(colored("║" + " " * 13 + "💥 DEAUTHENTICATION ATTACKS" + " " * 18 + "║", "yellow", attrs=['bold']))
        print(colored("╚" + "═" * 58 + "╝", "yellow", attrs=['bold']))
        
        print(f"\n📍 Target: {colored(self.target['ssid'], 'yellow', attrs=['bold'])}")
        print(f"   BSSID: {self.target['bssid']}")
        print(f"   Using: {colored(monitor_iface, 'cyan')}\n")
        
        print(colored(" [1]", "red", attrs=['bold']) + " Broadcast Deauth (all clients)")
        print(colored(" [2]", "yellow", attrs=['bold']) + " Directed Deauth (specific client)")
        print(colored(" [0]", "white") + " Back")
        
        choice = input(colored("\n ➤ Select: ", "cyan", attrs=['bold'])).strip()
        
        if choice == '1':
            attack = DeauthAttack(
                monitor_interface=monitor_iface,
                bssid=self.target['bssid'],
                ssid=self.target['ssid'],
                channel=self.target['channel'],
                client_mac=None
            )
            attack.run()
        
        elif choice == '2':
            client_mac = self._find_and_select_client(monitor_iface)
            if client_mac == "CANCEL":
                input("\nPress Enter to return...")
                return
            
            attack = DeauthAttack(
                monitor_interface=monitor_iface,
                bssid=self.target['bssid'],
                ssid=self.target['ssid'],
                channel=self.target['channel'],
                client_mac=client_mac
            )
            attack.run()
        else:
            return
        
        input("\nPress Enter to return...")
    
    def _evil_twin_deauth_submenu(self, monitor_iface: str):
        """Displays and handles the Evil Twin + Deauth attack menu."""
        os.system('cls' if os.name == 'nt' else 'clear')
        self._display_banner()
        
        print("\n" + "=" * 18 + " Evil Twin + Deauthentication Attack " + "=" * 18)
        print(colored("\n⚠️  WARNING: This creates a rogue AP for Man-in-the-Middle attacks!", "red", attrs=['bold']))
        print(colored("⚠️  Use only for authorized security testing!\n", "red"))
        
        print(f"[*] Target AP: {self.target['ssid']} ({self.target['bssid']})")
        print(f"[*] Channel: {self.target['channel']}")
        print(f"[*] Using: {monitor_iface}\n")
        
        print(colored("How this attack works:", "cyan", attrs=['bold']))
        print("  1. Creates a fake AP (Evil Twin) with the same SSID")
        print("  2. Sends Deauth frames to disconnect clients from real AP")
        print("  3. Clients automatically reconnect to your fake AP")
        print("  4. All traffic flows through your AP (Man-in-the-Middle)")
        print("  5. You can capture credentials, session tokens, etc.\n")
        
        confirm = input(colored("Start Evil Twin + Deauth attack? [y/N]: ", "yellow")).strip().lower()
        
        if confirm != 'y':
            print(colored("[*] Attack cancelled.", "cyan"))
            input("\nPress Enter to return to menu...")
            return
        
        # Create and run the attack
        try:
            attack = EvilTwinDeauth(
                monitor_interface=monitor_iface,
                target_bssid=self.target['bssid'],
                target_ssid=self.target['ssid'],
                target_channel=self.target['channel']
            )
            
            attack.run()
            
        except Exception as e:
            print(colored(f"\n[!] Attack failed: {e}", "red"))
        
        input("\nPress Enter to return to menu...")
    
    
    def _find_and_select_client(self, monitor_iface: str) -> Optional[str]:
        """Scan and select a client."""
        clients = self.scanner.scan_for_clients(monitor_iface, self.target['bssid'], self.target['channel'])
        
        if not clients:
            print(colored("\n[!] No clients were detected during scan.", "yellow"))
            choice = input(colored("    Proceed with broadcast deauth anyway? (Y/n): ", "cyan")).strip().lower()
            
            if choice != 'n':
                print(colored("[*] Proceeding with broadcast deauth to all clients.", "green"))
                return None
            else:
                print(colored("[*] Attack cancelled.", "yellow"))
                return "CANCEL"
        
        return self._select_client_from_scan(clients)
    
    def _select_client_from_scan(self, clients: list) -> Optional[str]:
        """Show selection prompt directly - NO list printed."""
        print(colored("━" * 70, "cyan"))
        print(colored(f"[*] Select client for directed deauth:\n", "cyan"))
        
        try:
            choice = input(colored(" ➤ Client NUM (or Enter to cancel): ", "cyan", attrs=['bold'])).strip()
            
            if choice and 1 <= int(choice) <= len(clients):
                client_mac = clients[int(choice) - 1]['Station MAC']
                print(colored(f"\n[✓] Selected: {client_mac}", "green", attrs=['bold']))
                return client_mac
            else:
                print(colored("\n[*] Cancelled.", "yellow"))
                return None
        except (ValueError, IndexError):
            print(colored("\n[!] Invalid input.", "red"))
            return None
    
    def manage_interfaces(self):
        """Interface management menu."""
        os.system('cls' if os.name == 'nt' else 'clear')
        self._display_banner()
        
        print("\n" + colored("╔" + "═" * 58 + "╗", "magenta", attrs=['bold']))
        print(colored("║" + " " * 16 + "🔧 INTERFACE MANAGEMENT" + " " * 19 + "║", "magenta", attrs=['bold']))
        print(colored("╚" + "═" * 58 + "╝", "magenta", attrs=['bold']))
        
        if not self.iface:
            self.iface = self.interface_mgr.select_interface()
            if self.iface:
                self.base_iface = self.iface
        
        if not self.iface:
            input("\nPress Enter to return...")
            return
        
        mode = self.interface_mgr.get_interface_mode(self.iface)
        print(f"\n[✓] Selected: {colored(self.iface, 'cyan', attrs=['bold'])} ({mode})")
        
        print("\n [1] Enable Monitor Mode")
        print(" [2] Disable Monitor Mode")
        print(" [3] Change MAC Address")
        print(" [0] Back")
        
        choice = input(colored("\n ➤ Select: ", "cyan", attrs=['bold'])).strip()
        
        if choice == "1":
            new_iface = self.monitor_mgr.enable_monitor(self.iface)
            if new_iface:
                self.monitor_iface = new_iface
                self.iface = new_iface
        
        elif choice == "2":
            restored_iface = self.monitor_mgr.disable_monitor(self.iface)
            if restored_iface:
                self.iface = restored_iface
                self.base_iface = restored_iface
                self.monitor_iface = None
        
        elif choice == "3":
            self.interface_mgr.change_mac(self.iface)
        
        input("\nPress Enter to return...")
    
    # ============ DISPLAY METHODS ============
    
    def _display_banner(self):
        """Display toolkit banner."""
        banner = r"""
    ██████╗ ██╗   ██╗██████╗ ██╗   ██╗███████╗██╗
    ██╔══██╗██║   ██║██╔══██╗╚██╗ ██╔╝██╔════╝██║
    ██████╔╝██║   ██║██████╔╝ ╚████╔╝ █████╗  ██║
    ██╔══██╗██║   ██║██╔══██╗  ╚██╔╝  ██╔══╝  ██║
    ██║  ██║╚██████╔╝██████╔╝   ██║   ██║     ██║
    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝    ╚═╝   ╚═╝     ╚═╝
    """
        subtitle = "  🔥 Advanced Red Team WiFi Toolkit - Group C-29 🔥"
        print(colored(banner, 'red', attrs=['bold']))
        print(colored(subtitle, 'cyan', attrs=['bold']) + "\n")
    
    def _display_menu(self):
        """Display main menu."""
        os.system('cls' if os.name == 'nt' else 'clear')
        self._display_banner()
        
        # Interface status
        if self.monitor_iface:
            iface_text = f"{self.monitor_iface} (Monitor)"
        elif self.iface:
            mode = self.interface_mgr.get_interface_mode(self.iface)
            iface_text = f"{self.iface} ({mode})"
        else:
            iface_text = "Not Selected"
        
        # Target status
        if self.target:
            target_text = self.target['ssid'][:35]
        else:
            target_text = "None"
        
        # Calculate padding - reduced by 1
        iface_padding = 60 - 1 - 2 - 13 - len(iface_text) - 1
        target_padding = 60 - 1 - 2 - 13 - len(target_text) - 1
        
        print(colored("  ╔" + "═" * 60 + "╗", "yellow"))
        
        # Interface line
        print(colored("  ║ ", "yellow") + 
            colored("📡", "yellow") + 
            colored(" Interface : ", "yellow") + 
            (colored(iface_text, "green", attrs=['bold']) if self.monitor_iface or self.iface else colored(iface_text, "red")) +
            " " * iface_padding + colored(" ║", "yellow"))
        
        # Target line
        print(colored("  ║ ", "yellow") + 
            colored("🎯", "yellow") + 
            colored(" Target    : ", "yellow") + 
            (colored(target_text, "yellow", attrs=['bold']) if self.target else colored(target_text, "red")) +
            " " * target_padding + colored(" ║", "yellow"))
        
        print(colored("  ╚" + "═" * 60 + "╝", "yellow"))
        
        print(colored("\n [1]", "red", attrs=['bold']) + " 🔧 Manage Interfaces")
        print(colored(" [2]", "red", attrs=['bold']) + " 📡 Scan & Select Target AP")
        print(colored(" [3]", "red", attrs=['bold']) + " ⚔️  Launch Attack")
        print(colored(" [4]", "red", attrs=['bold']) + " 🔓 Password Cracking")
        print(colored(" [0]", "white") + " 🚪 Exit Toolkit\n")


    # ============ HELPER METHODS ============
    
    def _select_ap_from_scan(self, networks: list):
        """Let user select an AP from scan results."""
        try:
            choice = input("\nSelect target AP NUM (or Enter to skip) ➤ ").strip()
            
            if choice and 1 <= int(choice) <= len(networks):
                self.target = networks[int(choice) - 1]
                print(colored(f"[✓] Selected AP: {self.target['ssid']}", "green"))
            else:
                print(colored("[!] No AP selected.", "yellow"))
        except (ValueError, IndexError):
            print(colored("[!] Invalid input.", "red"))
    
    def _save_target(self):
        """Save target AP information to JSON file."""
        if not self.target:
            return
        
        # Remove client_mac if present
        if 'client_mac' in self.target:
            del self.target['client_mac']
        
        # Clear old target files
        for f in config.TARGETS_DIR.glob("*.json"):
            f.unlink()
        
        # Create filename
        safe_ssid = "".join(c for c in self.target['ssid'] if c.isalnum() or c in ('_','-')).rstrip() or "HiddenSSID"
        safe_bssid = self.target['bssid'].replace(":", "-")
        filename = f"{safe_ssid}_{safe_bssid}.json"
        filepath = config.TARGETS_DIR / filename
        
        # Save target
        with open(filepath, "w") as f:
            json.dump(self.target, f, indent=4)
        
        print(colored(f"[✓] Target saved to {filepath}", "green"))
    
    def _load_last_target(self):
        """Load the most recent target from JSON files."""
        json_files = list(config.TARGETS_DIR.glob("*.json"))
        if not json_files:
            return False
        
        try:
            latest_file = max(json_files, key=os.path.getmtime)
            with open(latest_file, "r") as f:
                self.target = json.load(f)
            print(colored(f"[*] Loaded last target: {self.target.get('ssid', 'N/A')}", "cyan"))
            return True
        except (IOError, json.JSONDecodeError):
            self.target = None
            return False
    
    def _prompt_for_scan_cleanup(self):
        """Ask user if they want to clean up old scan files."""
        scan_files = list(config.SCAN_RESULTS_DIR.glob("*"))
        if not scan_files:
            return
        
        print(colored("\n[?] Previous scan files found.", "yellow"))
        choice = input("    Delete them? (Y/n): ").lower().strip()
        
        if choice == 'n':
            print(colored("[*] Skipping cleanup.", "cyan"))
            return
        
        print(colored("[*] Cleaning up old scan files...", "cyan"))
        for f in scan_files:
            try:
                f.unlink()
            except OSError as e:
                print(colored(f"    Could not delete {f.name}: {e}", "red"))
        
        print(colored("[✓] Cleanup complete.", "green"))
    
    def _ensure_interface_selected(self) -> bool:
        """Ensure an interface is selected."""
        if not self.iface:
            self.iface = self.interface_mgr.select_interface()
            if self.iface:
                self.base_iface = self.iface
        
        return self.iface is not None
    
    def _handle_exit(self):
        """Handle cleanup on exit."""
        iface_to_restore = self.monitor_iface if self.monitor_iface else self.iface
        
        if iface_to_restore:
            mode = self.interface_mgr.get_interface_mode(iface_to_restore)
            if mode == "Monitor":
                choice = input(f"\n[?] {iface_to_restore} is in monitor mode. Disable? (Y/n): ").lower().strip()
                if choice != 'n':
                    self.monitor_mgr.disable_monitor(iface_to_restore)
        from utils.interface_manager import InterfaceManager       
        InterfaceManager.restart_network_services()
        print(colored("\n🎯 Thank you for using RUBYFI Toolkit!", "green", attrs=['bold']))
        print(colored("   Stay ethical. Stay safe. 🛡️\n", "cyan"))


if __name__ == "__main__":
    try:
        toolkit = WiFiToolkit()
        toolkit.run()
    except KeyboardInterrupt:
        print(colored("\n\n[!] User interrupted program. Exiting...", "yellow"))
    except Exception as e:
        print(colored(f"\n[!] Critical error: {e}", "red"))
        import traceback
        traceback.print_exc()
