# utils/interface_manager.py

import subprocess
from typing import List, Optional
from termcolor import colored

class InterfaceManager:
    """Manages network interfaces: listing, selecting, MAC changes, etc."""

    @staticmethod
    def list_interfaces() -> List[str]:
        """Lists available wireless interfaces using `iw dev`."""
        interfaces = []
        try:
            result = subprocess.run(["iw", "dev"], capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                if line.strip().startswith("Interface"):
                    interfaces.append(line.split()[-1])
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(colored("[!] Failed to list interfaces. Is 'iw' installed?", "red"))
        return interfaces

    def auto_select_interface(self) -> Optional[str]:
        """
        Automatically selects the interface if only one is available.
        Returns the interface name or None if multiple/zero interfaces exist.
        """
        interfaces = self.list_interfaces()
        if len(interfaces) == 1:
            iface = interfaces[0]
            print(colored(f"[*] Found single wireless interface. Auto-selecting '{iface}'.", "green"))
            return iface
        return None

    def select_interface(self) -> Optional[str]:
        """
        Prompts the user to select an interface if more than one is available.
        """
        interfaces = self.list_interfaces()
        if not interfaces:
            print(colored("\n[!] No wireless interfaces found.", "red"))
            return None
        
        # If auto-selection didn't run (or found multiple), we prompt the user.
        print("\nAvailable interfaces:")
        for i, iface in enumerate(interfaces, 1):
            mode = self.get_interface_mode(iface)
            print(f"  [{i}] {iface} (Mode: {mode})")
        
        try:
            choice = input("Select interface [number]: ").strip()
            idx = int(choice) - 1
            if 0 <= idx < len(interfaces):
                return interfaces[idx]
        except (ValueError, IndexError):
            pass
        
        print(colored("[!] Invalid choice.", "red"))
        return None

    @staticmethod
    def get_interface_mode(iface: str) -> str:
        """Returns the operational mode of an interface ('Monitor', 'Managed', etc.)."""
        if not iface: return "N/A"
        try:
            result = subprocess.run(["iwconfig", iface], capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                if "Mode:" in line:
                    return line.split("Mode:")[1].split()[0]
            return "Unknown"
        except (subprocess.CalledProcessError, FileNotFoundError):
            return "N/A"

    def change_mac(self, iface: str) -> bool:
        """Randomizes the MAC address of the specified interface."""
        if self.get_interface_mode(iface) == "Monitor":
            print(colored(f"[!] Cannot change MAC while '{iface}' is in monitor mode.", "red"))
            return False

        print(f"[*] Changing MAC address for {iface}...")
        try:
            subprocess.run(["ip", "link", "set", iface, "down"], check=True, capture_output=True)
            result = subprocess.run(["macchanger", "-r", iface], check=True, capture_output=True, text=True)
            subprocess.run(["ip", "link", "set", iface, "up"], check=True, capture_output=True)
            
            print(colored(f"[✓] MAC address randomized for {iface}.", "green"))
            for line in result.stdout.splitlines():
                if "New MAC" in line: print(f"    {line.strip()}")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(colored(f"[!] MAC change failed. Ensure 'macchanger' is installed.", "red"))
            subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)
            return False

    @staticmethod
    def restart_network_services():
        """Restarts the NetworkManager service to restore connectivity."""
        print("[*] Restarting NetworkManager service...")
        try:
            subprocess.run(["systemctl", "restart", "NetworkManager"], check=True)
            print(colored("[✓] NetworkManager restarted successfully.", "green"))
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(colored("[!] Failed to restart NetworkManager.", "yellow"))