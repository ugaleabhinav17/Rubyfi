import os
import time
from termcolor import colored
from .selector import HandshakeSelector
from .brute_force import BruteForceAttack
from .wordlist_attack import WordlistAttack
from .dictionary_attack_rules import DictionaryAttackWithRules

class CrackingMenu:
    """Password cracking menu."""
    
    def __init__(self):
        self.selector = HandshakeSelector()
        self.selected_file = None
    
    def display(self):
        """Display menu."""
        if not self.selected_file:
            if not self.selector.select_handshake():
                return False
            self.selected_file = self.selector.selected_file
        
        # Clear terminal before showing menu
        os.system('clear')
        
        print(colored("\n╔" + "═" * 60 + "╗", "magenta", attrs=['bold']))
        print(colored("║" + " " * 13 + "🔓 PASSWORD CRACKING" + " " * 27 + "║", "magenta", attrs=['bold']))
        print(colored("╚" + "═" * 60 + "╝", "magenta", attrs=['bold']))
        
        print(colored(f"\n[✓] Using: {os.path.basename(self.selected_file)}", "green"))
        
        print(colored("\n[1]", "red", attrs=['bold']) + " 🔨 Brute Force")
        print(colored("[2]", "red", attrs=['bold']) + " 📖 Wordlist")
        print(colored("[3]", "red", attrs=['bold']) + " 🎲 Dictionary Attack With Rules")
        print(colored("[4]", "red", attrs=['bold']) + " 📂 View Saved")
        print(colored("[0]", "white") + " ⬅️  Back")
        
        choice = input(colored("\n ➤ Select: ", "cyan", attrs=['bold'])).strip()
        
        if choice == '1':
            BruteForceAttack(self.selected_file, self.selector).run()
            return True
        elif choice == '2':
            WordlistAttack(self.selected_file, self.selector).run()
            return True
        elif choice == '3':
            DictionaryAttackWithRules(self.selected_file, self.selector).run()
            return True
        elif choice == '4':
            self.selector.show_saved_passwords()
            return True
        elif choice == '0':
            return False
        else:
            print(colored("[!] Invalid", "red"))
            time.sleep(1)
            return True
