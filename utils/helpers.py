# utils/helpers.py

import subprocess
from termcolor import colored

def run_in_new_terminal(command: str):
    """
    Runs a command in a new terminal window (for Linux).
    Includes a pause to allow the user to see the output before the window closes.
    """
    full_command = f'{command}; echo; read -p "Process finished. Press Enter to close this window..."'
    try:
        subprocess.Popen(['x-terminal-emulator', '-e', 'bash', '-c', full_command])
    except FileNotFoundError:
        print(colored("[!] Could not open a new terminal. 'x-terminal-emulator' might not be installed.", "red"))