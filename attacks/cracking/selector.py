import os
import json
from pathlib import Path
from termcolor import colored
from datetime import datetime

class HandshakeSelector:
    """Select handshake file and manage password results."""
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent.parent
        self.possible_dirs = [
            self.project_root / "temp" / "handshakes",
            self.project_root / "handshakes",
            Path("/tmp/handshakes"),
        ]
        
        self.password_dir = self.project_root / "passwords"
        self.handshake_dir = None
        self.results_file = self.password_dir / "cracked_passwords.json"
        self.selected_file = None
        self._create_password_dir()

    def _create_password_dir(self):
        """Create password directory."""
        if not self.password_dir.exists():
            self.password_dir.mkdir(parents=True, exist_ok=True)

    def _find_handshake_dir(self):
        """Find handshake directory."""
        for dir_path in self.possible_dirs:
            if dir_path.exists():
                cap_files = list(dir_path.glob('*.cap'))
                if cap_files:
                    return dir_path
        return None

    def select_handshake(self):
        """Browse and select handshake file."""
        self.handshake_dir = self._find_handshake_dir()
        
        if not self.handshake_dir:
            print(colored("\n[!] Handshake directories checked:", "red"))
            for dir_path in self.possible_dirs:
                exists = "✓" if dir_path.exists() else "✗"
                print(colored(f" [{exists}] {dir_path}", "yellow"))
            
            choice = input(colored("\n[?] Enter custom path? (y/N): ", "yellow")).strip().lower()
            if choice == 'y':
                path = input(colored("[?] Enter file path: ", "yellow")).strip()
                if os.path.exists(path):
                    self.selected_file = path
                    return True
            return False
        
        print(colored(f"\n[✓] Using: {self.handshake_dir}", "green"))
        
        valid_files = []
        for ext in ['*.cap', '*.pcap', '*.22000', '*.hccapx']:
            valid_files.extend(self.handshake_dir.glob(ext))
        
        if not valid_files:
            print(colored(f"\n[!] No handshake files found", "red"))
            return False
        
        print(colored(f"\n[✓] Found {len(valid_files)} file(s):\n", "green"))
        for i, file in enumerate(valid_files, 1):
            size = file.stat().st_size / (1024 * 1024)
            print(colored(f"[{i}]", "yellow") + f" {file.name:<40} ({size:.2f} MB)")
        
        print(colored(f"[0]", "white") + " Enter custom path")
        
        try:
            choice = int(input(colored("\n[?] Select file: ", "cyan", attrs=['bold'])).strip())
            
            if choice == 0:
                path = input(colored("[?] Enter file path: ", "yellow")).strip()
                if os.path.exists(path):
                    self.selected_file = path
                    return True
            elif 1 <= choice <= len(valid_files):
                self.selected_file = str(valid_files[choice - 1])
                print(colored(f"\n[✓] Selected: {Path(self.selected_file).name}", "green"))
                return True
        except:
            pass
        
        return False

    def save_password(self, password, method):
        """Save cracked password - FIXED VERSION."""
        try:
            # Load existing data
            data = {}
            if self.results_file.exists():
                try:
                    with open(self.results_file, 'r') as f:
                        data = json.load(f)
                except Exception as e:
                    print(colored(f"[!] Error reading JSON: {e}", "red"))
                    data = {}
            
            # Extract filename
            filename = Path(self.selected_file).name
            
            # Extract AP info from filename (format: AP_BSSID_timestamp.cap)
            parts = filename.split('_')
            ap_name = parts[0] if len(parts) > 0 else "Unknown"
            bssid = parts[1] if len(parts) > 1 else "Unknown"
            
            # FIXED: Create complete entry dictionary
            entry = {
                "password": password.strip() if isinstance(password, str) else str(password),
                "ap_name": ap_name,
                "bssid": bssid,
                "file": filename,
                "timestamp": datetime.now().isoformat(),
                "method": method
            }
            
            # Add to data
            if filename not in data:
                data[filename] = []
            
            data[filename].append(entry)
            
            # Save to JSON with proper formatting
            try:
                with open(self.results_file, 'w') as f:
                    json.dump(data, f, indent=2)
                print(colored("[✓] Password saved successfully", "green"))
            except Exception as e:
                print(colored(f"[!] Error saving JSON: {e}", "red"))
        
        except Exception as e:
            print(colored(f"[!] Error in save_password: {e}", "red"))

    def show_saved_passwords(self):
        """Display saved passwords with proper formatting."""
        if not self.results_file.exists():
            print(colored("\n[!] No saved passwords", "yellow"))
            input("Press Enter...")
            return
        
        try:
            with open(self.results_file, 'r') as f:
                data = json.load(f)
            
            print(colored("\n" + "="*60, "cyan"))
            print(colored("📂 SAVED PASSWORDS", "cyan", attrs=['bold']))
            print(colored("="*60, "cyan"))
            
            entry_count = 0
            for filename, entries in data.items():
                print(colored(f"\n📄 {filename}", "yellow", attrs=['bold']))
                print(colored("─" * 60, "yellow"))
                
                for i, entry in enumerate(entries, 1):
                    entry_count += 1
                    password = entry.get('password', 'N/A')
                    ap_name = entry.get('ap_name', 'N/A')
                    bssid = entry.get('bssid', 'N/A')
                    method = entry.get('method', 'N/A')
                    timestamp = entry.get('timestamp', 'N/A')
                    
                    # Display with better formatting
                    print(f" [{entry_count}] Password: {colored(password, 'green', attrs=['bold'])}")
                    print(f"     AP Name : {ap_name}")
                    print(f"     BSSID   : {bssid}")
                    print(f"     Method  : {method}")
                    print(f"     Time    : {timestamp}")
                    print()
            
            print(colored("="*60, "cyan"))
            print(colored(f"Total passwords cracked: {entry_count}", "cyan"))
        
        except Exception as e:
            print(colored(f"[!] Error reading passwords: {e}", "red"))
        
        input(colored("\nPress Enter...", "cyan"))