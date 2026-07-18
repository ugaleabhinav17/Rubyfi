# utils/scan_networks.py
"""
This module is the core scanning engine for the toolkit.
This version uses a purely passive scanning method and includes a fix
to ensure correct target selection.
"""

import os
import csv
import json
import time
import subprocess
import threading
import queue
from typing import List, Dict, Any, Set
from termcolor import colored
from collections import defaultdict

import config

class WiFiScanner:
    """A class to handle all WiFi scanning operations."""

    def run_scan(self, monitor_iface: str) -> List[Dict[str, Any]]:
        """
        Performs a continuous, passive, live scan for all nearby APs.
        """
        self._clean_glob("live_scan*")
        output_path = config.SCAN_RESULTS_DIR / "live_scan"
        
        airodump_cmd = ["airodump-ng", "--band", "abg", "--write", str(output_path), "--output-format", "csv", "--write-interval", "1", monitor_iface]
        wash_cmd = ["wash", "-i", monitor_iface, "-F"]

        airodump_proc = subprocess.Popen(airodump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wash_proc = self._start_wash_process(wash_cmd)
        
        wash_q, _ = self._setup_reader_thread(wash_proc)
        all_networks, wps_bssids = {}, set()
        
        print(colored("\n[*] Starting passive live scan... Press Ctrl+C to stop.", "cyan"))
        
        final_list = [] # This will hold the list in its last displayed order
        try:
            while True:
                time.sleep(1.2)
                csv_file = next(config.SCAN_RESULTS_DIR.glob("live_scan*.csv"), None)
                if csv_file and os.path.exists(csv_file):
                    all_networks = self._parse_airodump_csv(csv_file)
                
                self._read_wash_queue(wash_q, wps_bssids)
                
                # --- FIX: Sort the list here, and use this sorted list for both display and for the final return ---
                sorted_list = sorted(list(all_networks.values()), key=lambda x: x.get('pwr', -100), reverse=True)
                for net in sorted_list:
                    net['wps'] = "Yes" if net['bssid'] in wps_bssids else "No"
                
                self._display_live_scan(monitor_iface, sorted_list)
                final_list = sorted_list # Continuously update the final list
        
        except KeyboardInterrupt:
            print(colored("\n\n[✓] Live scan stopped by user.", "green"))
        finally:
            print(colored("[*] Terminating scanning processes...", "cyan"))
            for proc in [airodump_proc, wash_proc]:
                if proc: proc.terminate(); proc.wait(timeout=5)
        
        with open(config.SCAN_RESULTS_DIR / "all_networks.json", "w") as f:
            json.dump(final_list, f, indent=4)
        return final_list

    def check_wps_status(self, monitor_interface: str, bssid: str, channel: int) -> dict:
        """Check WPS status for a specific AP using wash."""
        try:
            # Set interface to correct channel
            subprocess.run(
                ["iwconfig", monitor_interface, "channel", str(channel)],
                capture_output=True,
                timeout=5
            )
            
            # Run wash to check WPS
            result = subprocess.run(
                ["timeout", "10", "wash", "-i", monitor_interface, "-s", bssid.upper()],
                capture_output=True,
                text=True
            )
            
            wps_info = {
                'wps_enabled': False,
                'wps_locked': False,
                'wps_version': None
            }
            
            # Parse wash output
            for line in result.stdout.split('\n'):
                if bssid.upper() in line.upper():
                    wps_info['wps_enabled'] = True
                    
                    # Check if WPS is locked
                    if 'Yes' in line or 'Locked' in line.lower():
                        wps_info['wps_locked'] = True
                    
                    # Extract WPS version if available
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part.startswith('1.') or part.startswith('2.'):
                            wps_info['wps_version'] = part
                            break
                    
                    break
            
            return wps_info
        
        except Exception as e:
            return {'wps_enabled': False, 'wps_locked': False, 'wps_version': None}
    

    def _parse_airodump_csv(self, csv_file: str) -> Dict[str, Any]:
        """A robust parser for the two-part airodump-ng CSV file."""
        networks = {}
        client_counts = defaultdict(int)
        
        try:
            with open(csv_file, 'r', encoding="utf-8", errors="ignore") as f: lines = f.readlines()
        except (FileNotFoundError, IOError): return {}

        parsing_clients = False
        ap_header, client_header = [], []
        ap_reader = csv.reader([line for line in lines if line.strip()])

        for row in ap_reader:
            # Clean the row of extra whitespace
            row = [item.strip() for item in row]
            
            if not row: continue

            if 'Station MAC' in row[0]:
                parsing_clients = True
                client_header = row
                continue
            
            if 'BSSID' in row[0] and not parsing_clients:
                ap_header = row
                continue

            if parsing_clients and client_header:
                if len(row) >= 6:
                    ap_bssid = row[5]
                    # Check against BSSIDs we've already found.
                    if ap_bssid in networks:
                        client_counts[ap_bssid] += 1
            elif not parsing_clients and ap_header:
                if len(row) >= len(ap_header):
                    try:
                        data = dict(zip(ap_header, row))
                        bssid = data.get('BSSID')
                        if not bssid or len(bssid) != 17: continue

                        networks[bssid] = {
                            "bssid": bssid,
                            "ssid": data.get('ESSID') or "<Hidden SSID>",
                            "channel": int(data.get('channel', '0')),
                            "pwr": int(data.get('Power', '-100')),
                            "enc": data.get('Privacy', ''),
                            "clients": 0 # Start with 0 clients
                        }
                    except (ValueError, KeyError, TypeError): continue

        for bssid, count in client_counts.items():
            if bssid in networks:
                networks[bssid]['clients'] = count
        
        return networks

    def _display_live_scan(self, monitor_iface, sorted_networks: List[Dict]):
        """Clears the screen and prints the formatted live scan results."""
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print(colored(f"      📡 Live Scan on {monitor_iface} 📡", "yellow", attrs=['bold']))
        print(f"\n{'NUM':<4} {'SSID':<32} {'BSSID':<19} {'CH':>3} {'PWR':>4}   {'WPS':>5} {'CLIENTS':>7}   {'ENCR'}")
        print(f"{'---':<4} {'-'*32} {'-'*19} {'-'*3} {'-'*4}   {'-'*5} {'-'*7}   {'-'*12}")

        for i, net in enumerate(sorted_networks, 1):
            band_color = "magenta" if net.get('channel', 0) > 14 else "cyan"
            ssid_formatted = colored(f"{net.get('ssid', ''):<32}", band_color)
            wps_formatted = colored(f"{net.get('wps', 'No'):>5}", "green" if net.get('wps') == "Yes" else "red")
            client_formatted = colored(f"{net.get('clients', 0):>7}", "green" if net.get('clients', 0) > 0 else "yellow")
            print(f"[{i:2d}] {ssid_formatted} {net.get('bssid', ''):<19} {net.get('channel', ''):>3} {net.get('pwr', ''):>4}   {wps_formatted} {client_formatted}   {net.get('enc', '')}")
        
        print(f"\n{colored(f'[*] Scanning... Found {len(sorted_networks)} networks. (Press Ctrl+C to stop)', 'cyan')}")

    # --- The other helper methods are unchanged ---
    # def scan_for_clients(self, monitor_iface: str, bssid: str, channel: int) -> List[Dict[str, Any]]:
    #     print(colored(f"\n[*] Starting focused scan for clients on BSSID {bssid} (Channel {channel})...", "cyan"))
    #     output_path = config.SCAN_RESULTS_DIR / f"clients_of_{bssid.replace(':', '-')}"
    #     self._clean_glob(f"clients_of_{bssid.replace(':', '-')}*")
    #     cmd = ["airodump-ng", "--bssid", bssid, "--channel", str(channel), "--write", str(output_path), "--output-format", "csv", monitor_iface]
    #     proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    #     try:
    #         for i in range(15, 0, -1): print(f"    Listening for clients... Time remaining: {i:2d}s", end="\r"); time.sleep(1)
    #     except KeyboardInterrupt: print("\n[!] Scan stopped by user.")
    #     finally: proc.terminate(); proc.wait(timeout=5)
    #     print("\n[✓] Focused scan finished. Parsing client list...")
    #     csv_file = next(config.SCAN_RESULTS_DIR.glob(f"clients_of_{bssid.replace(':', '-')}*.csv"), None)
    #     if not csv_file: return []
    #     return self._parse_clients_from_csv(csv_file, bssid)
    
    def scan_for_clients(self, monitor_iface: str, bssid: str, channel: int) -> List[Dict[str, Any]]:
        """
        Live client scanning - updates every 1 second.
        Press Ctrl+C to stop and select.
        """
        self._clean_glob(f"clients_of_{bssid.replace(':', '-')}*")
        output_path = config.SCAN_RESULTS_DIR / f"clients_of_{bssid.replace(':', '-')}"
        
        cmd = ["airodump-ng", "--bssid", bssid, "--channel", str(channel), 
            "--write", str(output_path), "--output-format", "csv", monitor_iface]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        final_clients = []
        
        try:
            elapsed = 0
            while True:
                time.sleep(1)  # Update every 1 second
                elapsed += 1
                
                # Parse clients
                csv_file = next(config.SCAN_RESULTS_DIR.glob(f"clients_of_{bssid.replace(':', '-')}*.csv"), None)
                clients = []
                if csv_file:
                    clients = self._parse_clients_from_csv(csv_file, bssid)
                    try:
                        clients = sorted(clients, key=lambda x: int(x.get('Power', '-999')), reverse=True)
                    except:
                        pass
                
                # Display
                self._display_client_scan_simple(bssid, channel, clients, elapsed)
                final_clients = clients
        
        except KeyboardInterrupt:
            # Don't clear screen - leave last scan visible
            print(colored("\n\n[✓] Client scan stopped by user.\n", "green"))
        
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            
            # Return silently - NO output here
            return final_clients


    def _display_client_scan_simple(self, bssid: str, channel: int, clients: List[Dict], elapsed: int):
        """Display with 1 second refresh rate."""
        print("\033[2J\033[H", end="")  # Clear screen
        
        print(colored(f"\n📱 Live Client Scan on {bssid}", "cyan", attrs=['bold']))
        print()
        
        print(f"{'NUM':<4} {'STATION MAC':<19} {'CH':>3} {'PWR':>5} {'PACKETS':>9} {'PROBES':<20}")
        print(f"{'---':<4} {'-------------------':<19} {'---':>3} {'-----':>5} {'---------':>9} {'--------------------':<20}")
        
        if clients:
            for i, client in enumerate(clients, 1):
                mac = client.get('Station MAC', '')
                pwr = client.get('Power', '-1')
                packets = client.get('# packets', '0')
                probes = client.get('Probes', '')[:20]
                
                try:
                    pwr_val = int(pwr)
                    if pwr_val >= -50:
                        pwr_str = colored(f"{pwr:>5}", "green")
                    elif pwr_val >= -70:
                        pwr_str = colored(f"{pwr:>5}", "yellow")
                    else:
                        pwr_str = colored(f"{pwr:>5}", "red")
                except:
                    pwr_str = f"{pwr:>5}"
                
                print(f"[{i:2d}] {mac:<19} {channel:>3} {pwr_str} {packets:>9} {probes:<20}")
        else:
            print(colored("     No clients detected yet...", "yellow"))
        
        # Show elapsed time
        print(f"\n[*] Scanning... Found {len(clients)} client(s). | Time: {elapsed}s (Press Ctrl+C to stop)")


    def _parse_clients_from_csv(self, csv_file: str, target_bssid: str) -> List[Dict[str, Any]]:
        """
        Parse clients from airodump CSV.
        FIX: Filter out unassociated clients (Power = -1 or BSSID = "(not associated)")
        """
        clients = []
        
        try:
            with open(csv_file, 'r', encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except (FileNotFoundError, IOError):
            return []
        
        client_header = 'Station MAC,'
        if client_header not in content:
            return []
        
        _, client_content = content.split(client_header, 1)
        client_lines = (client_header + client_content).strip().splitlines()
        client_reader = csv.DictReader(client_lines)
        
        for row in client_reader:
            cleaned_row = {k.strip(): v.strip() for k, v in row.items()}
            
            # FIX: Only include clients that are:
            # 1. Associated with target BSSID
            # 2. Have valid power (not -1)
            # 3. Not marked as "(not associated)"
            
            bssid = cleaned_row.get('BSSID', '').strip()
            power = cleaned_row.get('Power', '-1').strip()
            
            # Skip if not associated with target AP
            if bssid != target_bssid:
                continue
            
            # Skip if BSSID is "(not associated)"
            if "(not associated)" in bssid.lower():
                continue
            
            # FIX: Skip clients with Power = -1 (not really connected)
            try:
                if int(power) == -1:
                    continue
            except ValueError:
                continue
            
            clients.append(cleaned_row)
        
        return clients

    def _start_wash_process(self, wash_cmd):
        try: return subprocess.Popen(wash_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1, universal_newlines=True)
        except FileNotFoundError: print(colored("\n[!] 'wash' not found. Cannot perform live WPS scan. Install 'reaver'.", "red")); time.sleep(2); return None
    def _setup_reader_thread(self, proc):
        if not proc: return None, None
        q = queue.Queue(); t = threading.Thread(target=self._enqueue_output, args=(proc.stdout, q)); t.daemon = True; t.start()
        return q, t
    def _enqueue_output(self, out, q):
        try:
            for line in iter(out.readline, ''): q.put(line)
            out.close()
        except ValueError: pass
    def _read_wash_queue(self, q: queue.Queue, wps_bssids: Set):
        if not q: return
        while not q.empty():
            try:
                line = q.get_nowait()
                if "BSSID" in line or "---" in line or not line.strip(): continue
                parts = [p for p in line.split(' ') if p]
                if len(parts) >= 5: wps_bssids.add(parts[0])
            except queue.Empty: break
    def _clean_glob(self, pattern: str):
        for f in config.SCAN_RESULTS_DIR.glob(pattern):
            try: os.remove(f)
            except OSError: pass