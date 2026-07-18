import subprocess
import json
import os
import time
import re
from pathlib import Path
from termcolor import colored
from datetime import datetime

class DictionaryAttackWithRules:
    """Dictionary attack with john the ripper rules."""
    
    def __init__(self, hash_file, selector):
        self.hash_file = hash_file
        self.selector = selector

    def run(self):
        """Main dictionary attack with rules flow."""
        print(colored("\n" + "="*60, "cyan"))
        print(colored("📚 DICTIONARY ATTACK (WITH RULES)", "cyan", attrs=['bold']))
        print(colored("="*60, "cyan"))
        
        # Get available wordlists
        print(colored("\n[*] Available Kali Linux Wordlists:", "yellow"))
        wordlists = self._get_kali_wordlists()
        
        if not wordlists:
            print(colored("[!] No wordlists found", "red"))
            input("Press Enter...")
            return
        
        print(colored(f"\n[✓] Found {len(wordlists)} wordlist(s)\n", "green"))
        for i, wl in enumerate(wordlists, 1):
            size = self._get_file_size(wl)
            print(colored(f"[{i}]", "yellow") + f" {Path(wl).name:<40} ({size})")
        
        print(colored(f"[0]", "white") + "  Enter custom path")
        
        try:
            choice = int(input(colored("\n[?] Select wordlist: ", "cyan", attrs=['bold'])).strip())
            
            if choice == 0:
                wordlist = input(colored("[?] Enter wordlist path: ", "yellow")).strip()
                if not os.path.exists(wordlist):
                    print(colored("[!] File not found", "red"))
                    input("Press Enter...")
                    return
            elif 1 <= choice <= len(wordlists):
                wordlist = wordlists[choice - 1]
            else:
                print(colored("[!] Invalid selection", "red"))
                input("Press Enter...")
                return
        except:
            print(colored("[!] Invalid input", "red"))
            input("Press Enter...")
            return
        
        # Select rule engine
        print(colored("\n[?] Select rule engine:", "yellow"))
        print("[1] Append numbers (0-99)")
        print("[2] Append symbols (!@#$%)")
        print("[3] Capitalize first letter")
        print("[4] All rules combined")
        print("[5] No rules (basic wordlist)")
        
        rule_choice = input(colored("[?] Select: ", "cyan", attrs=['bold'])).strip()
        
        if rule_choice not in ['1', '2', '3', '4', '5']:
            print(colored("[!] Invalid selection", "red"))
            input("Press Enter...")
            return
        
        print(colored(f"\n[*] Starting attack...", "cyan"))
        print(colored(f"    File: {Path(self.hash_file).name}", "cyan"))
        print(colored(f"    Wordlist: {Path(wordlist).name}", "cyan"))
        print(colored(f"    Rules: {self._get_rule_name(rule_choice)}", "cyan"))
        print(colored(f"\n[*] Initializing aircrack-ng...\n", "yellow"))
        
        self._run_attack(wordlist, rule_choice)

    def _get_kali_wordlists(self):
        """Get all Kali Linux wordlists."""
        kali_paths = [
            "/usr/share/wordlists/",
            "/usr/share/dict/",
            "/opt/wordlists/",
        ]
        
        wordlists = []
        for path in kali_paths:
            if os.path.exists(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        if not file.startswith('.'):
                            full_path = os.path.join(root, file)
                            wordlists.append(full_path)
        
        common_wordlists = [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/rockyou.txt.gz",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/metasploit/unix_users.txt",
        ]
        
        for wl in common_wordlists:
            if os.path.exists(wl) and wl not in wordlists:
                wordlists.append(wl)
        
        return sorted(list(set(wordlists)))

    def _get_file_size(self, filepath):
        """Get human readable file size."""
        try:
            size = os.path.getsize(filepath)
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size < 1024.0:
                    return f"{size:.2f} {unit}"
                size /= 1024.0
            return f"{size:.2f} TB"
        except:
            return "0 B"

    def _get_rule_name(self, choice):
        """Get human readable rule name."""
        rules = {
            '1': 'Append numbers (0-99)',
            '2': 'Append symbols (!@#$%)',
            '3': 'Capitalize first letter',
            '4': 'All rules combined',
            '5': 'No rules (basic wordlist)'
        }
        return rules.get(choice, 'Unknown')

    def _run_attack(self, wordlist, rule_choice):
        """Run aircrack-ng with rule-based mutations."""
        hash_file = self.hash_file
        
        # Create temp wordlist with rules
        temp_wordlist = f"/tmp/{Path(wordlist).stem}_rules.txt"
        
        print(colored("[*] Generating mutations with rules...", "cyan"))
        
        try:
            # Apply rules and generate mutations
            mutations = []
            with open(wordlist, 'r', errors='ignore') as f:
                for word in f:
                    word = word.strip()
                    if not word:
                        continue
                    
                    # Rule 1: Append numbers
                    if rule_choice in ['1', '4']:
                        for i in range(100):
                            mutations.append(f"{word}{i}")
                    
                    # Rule 2: Append symbols
                    if rule_choice in ['2', '4']:
                        for char in '!@#$%^&*':
                            mutations.append(f"{word}{char}")
                    
                    # Rule 3: Capitalize first letter
                    if rule_choice in ['3', '4']:
                        mutations.append(word.capitalize())
                        mutations.append(word[0].upper() + word[1:])
                    
                    # Rule 5: No rules (basic)
                    if rule_choice == '5':
                        mutations.append(word)
                    else:
                        mutations.append(word)  # Always include original
            
            # Remove duplicates
            mutations = list(set(mutations))
            print(colored(f"[✓] Generated {len(mutations):,} mutations", "green"))
            
            # Write to temp file
            with open(temp_wordlist, 'w') as f:
                f.write('\n'.join(mutations))
            
            print(colored(f"[✓] Saved to: {temp_wordlist}\n", "green"))
            
            # Run aircrack with mutations
            cmd = f"aircrack-ng -w '{temp_wordlist}' '{hash_file}'"
            
            print(colored("╔" + "═" * 60 + "╗", "magenta", attrs=['bold']))
            print(colored("║" + " 📚 DICTIONARY ATTACK (WITH RULES) ".center(59) + "║", "magenta", attrs=['bold']))
            print(colored("╚" + "═" * 60 + "╝", "magenta", attrs=['bold']))
            print()
            print(colored("[*] File: " + Path(hash_file).name, "cyan"))
            print(colored("[*] Mutations: " + f"{len(mutations):,}", "cyan"))
            print(colored("[*] Rules: " + self._get_rule_name(rule_choice), "cyan"))
            print()
            print(colored("[*] Running attack...", "yellow"))
            print(colored("="*60, "cyan"))
            print()
            
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            password_found = False
            found_password = None
            
            # Read output - show all lines (including keys) until password found
            for line in process.stdout:
                line = line.rstrip('\n')
                if line.strip():
                    print(colored(line, "cyan"))
                
                if 'KEY FOUND!' in line:
                    password_found = True
                    try:
                        match = re.search(r'KEY FOUND!\s*\[\s*(.+?)\s*\]', line)
                        if match:
                            found_password = match.group(1).strip()
                    except:
                        pass
                    
                    # CRITICAL: STOP READING IMMEDIATELY
                    break  # ← EXIT LOOP IMMEDIATELY
            
            # Kill the process to stop it
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=1)
                except:
                    pass
            
            
            # Show separator
            print(10*"\n")
            print()
            print(colored("="*60, "cyan"))
            print()
            
            
            # Clear screen and show professional interface
            # time.sleep(0.5)
            # os.system('clear')
            

            if password_found and found_password:
                self._display_professional_result(found_password)
                self._save_password_direct(found_password)
                input(colored("Press Enter to continue...", "cyan"))
            else:
                print(colored("[✓] Mutations exhausted - password not found", "yellow"))
                input(colored("Press Enter to continue...", "cyan"))
            
            # Cleanup
            try:
                os.remove(temp_wordlist)
            except:
                pass
        
        except KeyboardInterrupt:
            print(colored("\n[!] Attack stopped", "yellow"))
            try:
                os.remove(temp_wordlist)
            except:
                pass
            input("Press Enter...")
        
        except Exception as e:
            print(colored(f"[!] Error: {e}", "red"))
            try:
                os.remove(temp_wordlist)
            except:
                pass
            input("Press Enter...")

    def _display_professional_result(self, password):
        """Display password result - PROFESSIONAL INTERFACE."""
        print(colored("╔" + "═"*58 + "╗", "green", attrs=['bold']))
        print(colored("║" + "🎉 PASSWORD CRACKED SUCCESSFULLY".center(57) + "║", "green", attrs=['bold']))
        print(colored("╚" + "═"*58 + "╝", "green", attrs=['bold']))
        
        print()
        print(colored("┌─ PASSWORD " + "─"*47 + "┐", "green"))
        print(colored("   " + colored(password, "yellow", attrs=['bold']).ljust(56) + " ", "green"))
        print(colored("└" + "─"*58 + "┘", "green"))
        
        filename = Path(self.hash_file).name
        parts = filename.split('_')
        ap_name = parts[0] if len(parts) > 0 else "Unknown"
        bssid = parts[1] if len(parts) > 1 else "Unknown"
        
        print()
        print(colored("┌─ NETWORK DETAILS " + "─"*41 + "┐", "cyan"))
        print(colored(f"│ AP Name: {ap_name:<49}│", "cyan"))
        print(colored(f"│ BSSID:   {bssid:<49}│", "cyan"))
        print(colored(f"│ Method:  {'Dictionary Attack (Rules)':<49}│", "cyan"))
        print(colored(f"│ File:    {Path(self.hash_file).name:<49}│", "cyan"))
        print(colored("└" + "─"*59 + "┘", "cyan"))
        
        print()

    def _save_password_direct(self, password):
        """FIXED: Save password directly to JSON."""
        try:
            project_root = Path(__file__).parent.parent.parent
            password_dir = project_root / "passwords"
            password_dir.mkdir(parents=True, exist_ok=True)
            results_file = password_dir / "cracked_passwords.json"
            
            # Load existing data
            data = {}
            if results_file.exists():
                try:
                    with open(results_file, 'r') as f:
                        data = json.load(f)
                except:
                    data = {}
            
            # Extract AP info
            filename = Path(self.hash_file).name
            parts = filename.split('_')
            ap_name = parts[0] if len(parts) > 0 else "Unknown"
            bssid = parts[1] if len(parts) > 1 else "Unknown"
            
            # Create entry - EXACTLY what was extracted
            entry = {
                "password": str(password).strip(),
                "ap_name": str(ap_name).strip(),
                "bssid": str(bssid).strip(),
                "file": str(filename).strip(),
                "timestamp": datetime.now().isoformat(),
                "method": "Dictionary Attack (Rules)"
            }
            
            # Add to data
            if filename not in data:
                data[filename] = []
            data[filename].append(entry)
            
            # Save to JSON
            with open(results_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            print(colored("✓ SAVED", "green", attrs=['bold']))
            print(colored(f"  Location: passwords/cracked_passwords.json", "green"))
        
        except Exception as e:
            print(colored(f"[!] Error saving: {e}", "red"))