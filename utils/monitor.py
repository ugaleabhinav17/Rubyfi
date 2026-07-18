# utils/monitor.py

import os
import subprocess
import time
import shutil
from typing import Optional, Set
from termcolor import colored
from .interface_manager import InterfaceManager

class MonitorManager:
    """Handles enabling/disabling monitor mode and checking dependencies."""
    def __init__(self):
        self.dependencies = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng", 
                             "mdk4", "wash", "macchanger", "iw", "iwconfig", "ip", "systemctl"]
        self.interface_mgr = InterfaceManager()

    def check_root(self):
        """Exits if the script is not run as root."""
        if os.geteuid() != 0:
            raise SystemExit(colored("[!] This script requires root privileges. Exiting.", "red"))

    def check_dependencies(self):
        """Checks for required command-line tools and exits if any are missing."""
        print("[*] Checking for required tools...")
        missing = [dep for dep in self.dependencies if not shutil.which(dep)]
        if missing:
            msg = f"[!] Missing dependencies: {', '.join(missing)}. Please install them."
            raise SystemExit(colored(msg, "red"))
        print(colored("[✓] All dependencies are present.", "green"))
        time.sleep(1)

    def enable_monitor(self, iface: str) -> Optional[str]:
        """Enables monitor mode on a given interface."""
        if self.interface_mgr.get_interface_mode(iface) == "Monitor":
            print(colored(f"[✓] Interface {iface} is already in monitor mode.", "green"))
            return iface

        print(f"[*] Enabling monitor mode on {iface}...")
        try:
            subprocess.run(["airmon-ng", "check", "kill"], capture_output=True, text=True)
            before: Set[str] = set(self.interface_mgr.list_interfaces())
            subprocess.run(["airmon-ng", "start", iface], check=True, capture_output=True, text=True)
            time.sleep(1)
            after: Set[str] = set(self.interface_mgr.list_interfaces())
            
            new_ifaces = after - before
            if new_ifaces:
                monitor_iface = new_ifaces.pop()
                print(colored(f"[✓] Monitor mode enabled on new interface: {monitor_iface}", "green"))
                return monitor_iface
            elif self.interface_mgr.get_interface_mode(iface) == "Monitor":
                print(colored(f"[✓] Monitor mode enabled on {iface}", "green"))
                return iface
            
            print(colored(f"[!] Failed to confirm monitor mode.", "red"))
            return None
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(colored(f"[!] Failed to enable monitor mode: {e}", "red")); return None

    # def disable_monitor(self, iface: str) -> Optional[str]:
    #     """
    #     Disables monitor mode and returns the name of the new managed-mode interface.
    #     """
    #     if self.interface_mgr.get_interface_mode(iface) != "Monitor":
    #         print(colored(f"[*] {iface} is not in monitor mode.", "cyan")); return iface
        
    #     # Predict the base interface name (e.g., wlan0mon -> wlan0)
    #     base_iface = iface[:-3] if iface.endswith('mon') else iface
        
    #     print(f"[*] Disabling monitor mode on {iface}...")
    #     try:
    #         subprocess.run(["airmon-ng", "stop", iface], check=True, capture_output=True)
    #         print(colored(f"[✓] Monitor mode stopped.", "green"))
    #         self.interface_mgr.restart_network_services()

    #         # Verify the base interface now exists and is in managed mode
    #         time.sleep(2) # Give services time to restart
    #         all_ifaces = self.interface_mgr.list_interfaces()
    #         if base_iface in all_ifaces:
    #             print(colored(f"[✓] Auto-selected restored interface '{base_iface}'.", "green"))
    #             return base_iface
    #         else:
    #             print(colored("[!] Could not determine the original interface name after disabling.", "yellow"))
    #             return None # Force re-selection if prediction was wrong
    #     except (subprocess.CalledProcessError, FileNotFoundError) as e:
    #         print(colored(f"[!] Failed to stop monitor mode: {e}", "red")); return None
        


    def disable_monitor(self, iface: str) -> Optional[str]:
        """
        Disables monitor/master mode and returns the name of the new managed-mode interface.
        """
        mode = self.interface_mgr.get_interface_mode(iface)

        # ── Early exit: already managed ──────────────────────────────────────────
        if mode not in ("Monitor", "Master"):
            print(colored(f"[*] {iface} is not in monitor/master mode.", "cyan"))
            return iface

        base_iface = iface[:-3] if iface.endswith("mon") else iface

        # ── Master mode: teardown AP, force managed via iw ───────────────────────
        if mode == "Master":
            print(f"[*] Interface {iface} is in Master mode. Switching to managed...")
            try:
                subprocess.run(["ip", "link", "set", iface, "down"],
                            check=True, capture_output=True)
                subprocess.run(["iw", "dev", iface, "set", "type", "managed"],
                            check=True, capture_output=True)
                subprocess.run(["ip", "link", "set", iface, "up"],
                            check=True, capture_output=True)
                print(colored("[✓] Switched from Master → Managed.", "green"))

            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                print(colored(f"[!] Failed to switch from Master mode: {e}", "red"))
                return None

        # ── Monitor mode: use airmon-ng stop ─────────────────────────────────────
        elif mode == "Monitor":
            print(f"[*] Disabling monitor mode on {iface}...")
            try:
                subprocess.run(["airmon-ng", "stop", iface],
                            check=True, capture_output=True)
                print(colored("[✓] Monitor mode stopped.", "green"))

            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                print(colored(f"[!] Failed to stop monitor mode: {e}", "red"))
                return None

        # ── Shared post-teardown: restart services & verify ──────────────────────
        self.interface_mgr.restart_network_services()
        time.sleep(2)  # Give services time to come back

        all_ifaces = self.interface_mgr.list_interfaces()
        if base_iface in all_ifaces:
            print(colored(f"[✓] Auto-selected restored interface '{base_iface}'.", "green"))
            return base_iface
        else:
            print(colored("[!] Could not determine the original interface after disabling.", "yellow"))
            return None
        