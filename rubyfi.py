"""RubyFi - Universal Launcher (CLI/GUI)"""

import sys
import os
import subprocess
from termcolor import colored

def clear():
    os.system('clear')

def banner():
        """Display toolkit banner."""
        banner = r"""
    ██████╗ ██╗   ██╗██████╗ ██╗   ██╗███████╗██╗
    ██╔══██╗██║   ██║██╔══██╗╚██╗ ██╔╝██╔════╝██║
    ██████╔╝██║   ██║██████╔╝ ╚████╔╝ █████╗  ██║
    ██╔══██╗██║   ██║██╔══██╗  ╚██╔╝  ██╔══╝  ██║
    ██║  ██║╚██████╔╝██████╔╝   ██║   ██║     ██║
    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝    ╚═╝   ╚═╝     ╚═╝
    """
        subtitle = "  🔥 Advanced Red Team WiFi Toolkit - Group C-29 🔥"
        print(colored(banner, 'red', attrs=['bold']))
        print(colored(subtitle, 'cyan', attrs=['bold']) + "\n")

def main():
    clear()
    banner()
    print(colored("    Welcome to RubyFi! Please select your preferred interface mode:\n", 'yellow'))
    print(colored("    [1] 💻 Command Line Interface (CLI)", 'green', attrs=['bold']))
    print(colored("    [2] 🖥️  Graphical Interface (GUI)", 'green', attrs=['bold']))
    print(colored("    [3] 🚪 Exit", 'red',attrs=['bold']))
    print()
    
    choice = input("    ➤ Select mode: ").strip()
    
    if choice == "1":
        clear()
        try:
            os.system('python3 main.py')
        except Exception as e:
            print(f"[!] Error launching CLI: {e}")
            input("Press Enter to return...")
            main()
        
    elif choice == "2":
        # Import GUI
        from gui.main_window import run_gui
        run_gui()
        
    elif choice == "3":
        print(colored("\n   Thank you for using RUBYFI Toolkit!\n", 'blue', attrs=['bold']))
        print(colored("   Stay ethical. Stay safe. 🛡️", 'green'))
        sys.exit(0)
    else:
        print(colored("\n    [!] Invalid choice", 'red'))
        input("\n    Press Enter to continue...")
        main()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Run as root: sudo python3 rubyfi.py")
        sys.exit(1)
    main()
