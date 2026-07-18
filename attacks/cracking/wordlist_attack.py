import subprocess
import json
import os
import time
import gzip
import sys
import re
from pathlib import Path
from termcolor import colored
from datetime import datetime

class WordlistAttack:
    """Wordlist dictionary attack using aircrack-ng."""
    
    def __init__(self, hash_file, selector):
        self.hash_file = hash_file
        self.selector = selector
        self.process = None

    def run(self):
        """Main wordlist attack flow."""
        print(colored("\n" + "="*60, "cyan"))
        print(colored("📖 WORDLIST ATTACK", "cyan", attrs=['bold']))
        print(colored("="*60, "cyan"))
        
        # Show available Kali wordlists
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
        
        # Count words
        try:
            if wordlist.endswith('.gz'):
                with gzip.open(wordlist, 'rt') as f:
                    word_count = sum(1 for _ in f)
            else:
                word_count = sum(1 for _ in open(wordlist))
            print(colored(f"\n[✓] Wordlist: {word_count:,} passwords", "green"))
        except:
            word_count = 0
        
        print(colored(f"\n[*] Starting attack...", "cyan"))
        print(colored(f"    File: {Path(self.hash_file).name}", "cyan"))
        print(colored(f"    Wordlist: {Path(wordlist).name}", "cyan"))
        print(colored(f"\n[*] Initializing aircrack-ng...\n", "yellow"))
        
        self._run_aircrack(wordlist, word_count)

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

    def _run_aircrack(self, wordlist, word_count):
        """Run aircrack-ng dictionary attack."""
        # Handle compressed wordlists
        if wordlist.endswith('.gz'):
            print(colored("[*] Extracting wordlist...", "cyan"))
            temp_wordlist = f"/tmp/{Path(wordlist).stem}"
            try:
                subprocess.run(f"gunzip -c '{wordlist}' > '{temp_wordlist}'",
                             shell=True, timeout=60)
                wordlist = temp_wordlist
                print(colored("[✓] Extracted\n", "green"))
            except:
                print(colored("[!] Extraction failed", "red"))
                input("Press Enter...")
                return
        
        hash_file = self.hash_file
        
        # Run aircrack-ng directly in main terminal
        cmd = f"aircrack-ng -w '{wordlist}' '{hash_file}'"
        
        print(colored("╔" + "═" * 60 + "╗", "magenta", attrs=['bold']))
        print(colored("║" + " 🔓 WORDLIST PASSWORD ATTACK ".center(59) + "║", "magenta", attrs=['bold']))
        print(colored("╚" + "═" * 60 + "╝", "magenta", attrs=['bold']))
        print()
        print(colored("[*] File: " + Path(hash_file).name, "cyan"))
        print(colored("[*] Wordlist: " + Path(wordlist).name, "cyan"))
        print(colored("[*] Total passwords: " + f"{word_count:,}", "cyan"))
        print()
        print(colored("[*] Running attack...", "yellow"))
        print(colored("="*60, "cyan"))
        print()
        
        self.process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        password_found = False
        found_password = None
        
        try:
            # STEP 1: Read and display ALL aircrack output
            print(colored("── AIRCRACK OUTPUT ──", "cyan", attrs=['bold']))
            for line in self.process.stdout:
                line = line.rstrip('\n')
                
                # Print all aircrack output
                if line.strip():
                    print(colored(line, "cyan"))
                
                sys.stdout.flush()
                
                # Check for password found
                if 'KEY FOUND!' in line:
                    password_found = True
                    try:
                        match = re.search(r'KEY FOUND!\s*\[\s*(.+?)\s*\]', line)
                        if match:
                            found_password = match.group(1).strip()
                    except:
                        pass
            
            # Wait for process to complete
            try:
                returncode = self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
            
            # STEP 2: Now show the professional interface
            print()
            print(colored("="*60, "cyan"))
            print()
            
            if password_found and found_password:
                # Display professional result
                self._display_professional_result(found_password)
                # Save to JSON
                self._save(found_password)
                input(colored("Press Enter to continue...", "cyan"))
            else:
                print(colored("[✓] Wordlist exhausted - password not found", "yellow"))
                input(colored("Press Enter to continue...", "cyan"))
        
        except KeyboardInterrupt:
            print(colored("\n\n[!] Attack stopped by user", "yellow"))
            self.process.kill()
            try:
                self.process.wait(timeout=2)
            except:
                pass
            input("Press Enter...")
        
        except Exception as e:
            print(colored(f"\n[!] Error: {e}", "red"))
            try:
                self.process.kill()
                self.process.wait(timeout=2)
            except:
                pass
            input("Press Enter...")

    def _display_professional_result(self, password):
        """Display password result with professional interface."""
        # Professional header
        print(colored("╔" + "═"*58 + "╗", "green", attrs=['bold']))
        print(colored("║" + "🎉 PASSWORD CRACKED SUCCESSFULLY".center(57) + "║", "green", attrs=['bold']))
        print(colored("╚" + "═"*58 + "╝", "green", attrs=['bold']))
        
        # Clean password display
        print()
        print(colored("┌─ PASSWORD " + "─"*47 + "┐", "green"))
        print(colored(" " + colored(password, "yellow", attrs=['bold']).ljust(56) + " ", "green"))
        print(colored("└" + "─"*58 + "┘", "green"))
        
        # Extract AP info
        filename = Path(self.hash_file).name
        parts = filename.split('_')
        ap_name = parts[0] if len(parts) > 0 else "Unknown"
        bssid = parts[1] if len(parts) > 1 else "Unknown"
        
        # Additional details section
        print()
        print(colored("┌─ NETWORK DETAILS " + "─"*41 + "┐", "cyan"))
        print(colored(f"│ AP Name: {ap_name:<49}│", "cyan"))
        print(colored(f"│ BSSID:   {bssid:<49}│", "cyan"))
        print(colored(f"│ Method:  {'Wordlist Attack':<49}│", "cyan"))
        print(colored(f"│ File:    {Path(self.hash_file).name:<49}│", "cyan"))
        print(colored("└" + "─"*59 + "┘", "cyan"))
        
        print()

    def _save(self, password):
        """Save cracked password to JSON."""
        # Get project root
        project_root = Path(__file__).parent.parent.parent
        password_dir = project_root / "passwords"
        password_dir.mkdir(parents=True, exist_ok=True)
        results_file = password_dir / "cracked_passwords.json"
        
        try:
            # Load existing data
            data = {}
            if results_file.exists():
                try:
                    with open(results_file, 'r') as f:
                        data = json.load(f)
                except:
                    data = {}
            
            # Extract AP info from filename
            filename = Path(self.hash_file).name
            parts = filename.split('_')
            ap_name = parts[0] if len(parts) > 0 else "Unknown"
            bssid = parts[1] if len(parts) > 1 else "Unknown"
            
            # Create entry
            entry = {
                "password": str(password).strip(),
                "ap_name": str(ap_name).strip(),
                "bssid": str(bssid).strip(),
                "file": str(filename).strip(),
                "timestamp": datetime.now().isoformat(),
                "method": "Wordlist Attack"
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