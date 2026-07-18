import subprocess
import json
import os
import time
import re
from pathlib import Path
from termcolor import colored
from datetime import datetime

class BruteForceAttack:
    """Brute force password cracking using hashcat."""
    
    def __init__(self, hash_file, selector):
        self.hash_file = hash_file
        self.selector = selector
        self.process = None

    def run(self):
        """Main brute force attack flow."""
        print(colored("\n" + "="*60, "cyan"))
        print(colored("🔨 BRUTE FORCE ATTACK", "cyan", attrs=['bold']))
        print(colored("="*60, "cyan"))
        
        hash_file = self._prepare_hash()
        if not hash_file:
            print(colored("\n[!] Cannot proceed without hash file", "red"))
            input(colored("Press Enter...", "cyan"))
            return
        
        print(colored("\n[?] Hashcat Mask Pattern:", "yellow"))
        print("[?] ?l = lowercase (a-z)")
        print("[?] ?u = UPPERCASE (A-Z)")
        print("[?] ?d = digit (0-9)")
        print("[?] ?s = special (!@#$%)")
        print(colored("\n[*] Examples:", "cyan"))
        print("    ?d?d?d?d = 1234")
        print("    manmeet?d?d = manmeet01-99")
        
        mask = input(colored("\n[?] Enter mask: ", "cyan", attrs=['bold'])).strip()
        if not mask:
            print(colored("[!] Mask cannot be empty", "red"))
            input("Press Enter...")
            return
        
        print(colored(f"\n[*] Starting attack...", "cyan"))
        print(colored(f"    File: {Path(self.hash_file).name}", "cyan"))
        print(colored(f"    Mask: {mask}", "cyan"))
        print(colored(f"\n[*] Initializing hashcat (5-10 seconds)...\n", "yellow"))
        
        self._run_hashcat(hash_file, mask)

    def _prepare_hash(self):
        """Convert .cap file to hashcat format."""
        if not self.hash_file.endswith(('.cap', '.pcap')):
            return self.hash_file
        
        print(colored("\n[*] Converting .cap file...", "cyan"))
        
        hash_file = f"/tmp/{Path(self.hash_file).stem}.22000"
        hccapx_file = f"/tmp/{Path(self.hash_file).stem}.hccapx"
        
        if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
            print(colored(f"[✓] Using cached hash file", "green"))
            return hash_file
        
        try:
            print(colored("[*] Step 1: hcxpcapngtool", "cyan"))
            result = subprocess.run(
                f"hcxpcapngtool -o '{hash_file}' '{self.hash_file}' 2>&1",
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
                print(colored("[✓] Converted successfully", "green"))
                return hash_file
            else:
                print(colored("[!] Method 1 failed, trying alternative...", "yellow"))
            
            print(colored("[*] Step 2: cap2hashcat", "cyan"))
            result = subprocess.run(
                f"cap2hashcat '{self.hash_file}' '{hash_file}' 2>&1",
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
                print(colored("[✓] Converted successfully", "green"))
                return hash_file
            
            print(colored("[*] Step 3: aircrack-ng", "cyan"))
            subprocess.run(
                f"aircrack-ng -J '{hccapx_file.replace('.hccapx', '')}' '{self.hash_file}' > /dev/null 2>&1",
                shell=True,
                timeout=30
            )
            
            if os.path.exists(hccapx_file) and os.path.getsize(hccapx_file) > 0:
                print(colored("[*] Step 4: Converting .hccapx", "cyan"))
                subprocess.run(
                    f"hcxpcapngtool '{hccapx_file}' -o '{hash_file}' 2>&1",
                    shell=True,
                    timeout=30
                )
                
                if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
                    print(colored("[✓] Converted successfully", "green"))
                    return hash_file
                else:
                    print(colored("[✓] Using .hccapx format", "green"))
                    return hccapx_file
            
            print(colored("[!] All conversion methods failed", "red"))
            return None
            
        except subprocess.TimeoutExpired:
            print(colored("[!] Conversion timeout", "red"))
            return None
        except Exception as e:
            print(colored(f"[!] Error: {e}", "red"))
            return None

    def _run_hashcat(self, hash_file, mask):
        """Run hashcat attack."""
        modes = ["22000", "2500"] if hash_file.endswith(('.cap', '.hccapx')) else ["22000"]
        
        for mode in modes:
            cmd = f"hashcat -m {mode} -a 3 '{hash_file}' '{mask}' -O --status --status-timer=5"
            print(colored(f"[*] Running: hashcat -m {mode} -a 3 ... '{mask}'", "yellow"))
            
            self.process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            mode_failed = False
            initialized = False
            line_count = 0
            password_found = False
            last_progress_time = time.time()
            
            try:
                # STEP 1: Show hashcat output
                print(colored("── HASHCAT OUTPUT ──", "cyan", attrs=['bold']))
                while True:
                    try:
                        line = self.process.stdout.readline()
                    except:
                        break
                    
                    if not line:
                        break
                    
                    line = line.rstrip('\n').strip()
                    if not line:
                        continue
                    
                    line_count += 1
                    
                    if not initialized and line_count > 5:
                        initialized = True
                        print(colored("[✓] Hashcat initialized\n", "green"))
                    
                    if 'No hashes loaded' in line or 'Token length' in line:
                        print(colored(f"[!] Mode {mode} failed\n", "yellow"))
                        self.process.kill()
                        mode_failed = True
                        break
                    
                    skip_patterns = [
                        'Device #', 'Kernel', 'Optimized', 'Falling back',
                        'Minimum', 'Maximum', 'Counting', 'Sorted',
                        'Removing', 'Removed', 'Compared', 'potfile',
                        '=====', 'Parsed', 'INFO: All', 'Allocate'
                    ]
                    skip = any(pattern in line for pattern in skip_patterns)
                    
                    current_time = time.time()
                    if initialized and not skip:
                        if 'Status' in line and (current_time - last_progress_time) > 2:
                            print(colored(line, "cyan"))
                            last_progress_time = current_time
                        elif 'Cracked' in line:
                            print(colored(line, "cyan"))
                            password_found = True
                        elif 'Speed' in line and (current_time - last_progress_time) > 2:
                            print(colored(line, "cyan"))
                            last_progress_time = current_time
                        elif 'Progress' in line and (current_time - last_progress_time) > 2:
                            print(colored(line, "cyan"))
                            last_progress_time = current_time
                        elif 'Recovered' in line:
                            print(colored(line, "cyan"))
                            if '1/1' in line and '(100.00%)' in line:
                                password_found = True
                    
                    if 'All hashes found as potfile' in line:
                        password_found = True
                        print(colored("[✓] Password found in cache!", "green"))
                    
                    if password_found:
                        print(colored("\n[✓] Password CRACKED! Stopping attack...", "green"))
                        self.process.terminate()
                        try:
                            self.process.wait(timeout=2)
                        except:
                            self.process.kill()
                        break
                
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                
                # STEP 2: Show professional interface
                print()
                print(colored("="*60, "cyan"))
                print()
                
                if password_found:
                    print(colored("\n" + "="*60, "cyan"))
                    print()
                    time.sleep(1)
                    self._save(hash_file)
                    return
                
                if not mode_failed:
                    return
            
            except KeyboardInterrupt:
                print(colored("\n[!] Attack stopped", "yellow"))
                self.process.kill()
                try:
                    self.process.wait(timeout=2)
                except:
                    pass
                return
            except Exception as e:
                print(colored(f"\n[!] Error: {e}", "red"))
                try:
                    self.process.kill()
                    self.process.wait(timeout=2)
                except:
                    pass

    def _display_professional_result(self, password):
        """Display password result - PROFESSIONAL INTERFACE."""
        # Professional header
        print(colored("╔" + "═"*58 + "╗", "green", attrs=['bold']))
        print(colored("║" + "🎉 PASSWORD CRACKED SUCCESSFULLY".center(58) + "║", "green", attrs=['bold']))
        print(colored("╚" + "═"*58 + "╝", "green", attrs=['bold']))
        
        # Clean password display
        print()
        print(colored("┌─ PASSWORD " + "─"*47 + "┐", "green"))
        print(colored("│ " + colored(password, "yellow", attrs=['bold']).ljust(56) + "│", "green"))
        print(colored("└" + "─"*58 + "┘", "green"))
        
        # Extract AP info
        filename = Path(self.hash_file).name
        parts = filename.split('_')
        ap_name = parts[0] if len(parts) > 0 else "Unknown"
        bssid = parts[1] if len(parts) > 1 else "Unknown"
        
        # Additional details
        print()
        print(colored("┌─ NETWORK DETAILS " + "─"*40 + "┐", "cyan"))
        print(colored(f"│ AP Name: {ap_name:<49}│", "cyan"))
        print(colored(f"│ BSSID:   {bssid:<49}│", "cyan"))
        print(colored(f"│ Method:  {'Brute Force':<49}│", "cyan"))
        print(colored(f"│ File:    {Path(self.hash_file).name:<49}│", "cyan"))
        print(colored("└" + "─"*58 + "┘", "cyan"))
        
        print()

    def _save(self, hash_file):
        """Save cracked password to JSON."""
        time.sleep(1)
        
        try:
            result = subprocess.run(
                f"hashcat -m 22000 '{hash_file}' --show 2>/dev/null",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if ':' in line:
                        parts = line.split(':')
                        password = parts[-1].strip()
                        
                        if password and len(password) > 0:
                            # Display professional result
                            self._display_professional_result(password)
                            
                            # Save to JSON
                            self.selector.save_password(password, "Brute Force")
                            print(colored("✓ SAVED", "green", attrs=['bold']))
                            
                            filename = Path(self.hash_file).name
                            print(colored(f"  Location: passwords/cracked_passwords.json", "green"))
                            
                            input(colored("\nPress Enter to continue...", "cyan"))
                            return
            
            print(colored("[!] Could not retrieve password", "red"))
            input(colored("Press Enter...", "cyan"))
        
        except Exception as e:
            print(colored(f"[!] Error: {e}", "red"))
            input(colored("Press Enter...", "cyan"))