# attacks/base.py

from abc import ABC, abstractmethod
from termcolor import colored


class BaseAttack(ABC):
    """
    For attacks that require a monitor mode interface
    (deauth, handshake capture, beacon flood, etc.).
    """

    def __init__(self, monitor_interface: str):
        if not monitor_interface:
            raise ValueError("A monitor mode interface must be provided.")
        self.monitor_interface = monitor_interface

    @abstractmethod
    def _execute(self):
        """Core logic of the attack. Must be implemented by subclasses."""
        pass

    def run(self):
        """Public method to run the attack with error handling."""
        try:
            self._execute()
        except KeyboardInterrupt:
            print(colored(f"\n[!] {self.__class__.__name__} stopped by user.", "yellow"))
        except Exception as e:
            print(colored(f"[!] An unexpected error occurred during the attack: {e}", "red"))
        finally:
            print(colored(f"\n[*] {self.__class__.__name__} finished.", "cyan"))


class BaseNonMonitorAttack(ABC):
    """
    For attacks that use a normal managed/AP interface (no monitor mode),
    e.g. the WiFi phishing attack powered by wifiphisher.
    """

    def __init__(self, interface: str):
        if not interface:
            raise ValueError("An interface must be provided.")
        self.interface = interface

    @abstractmethod
    def _execute(self):
        """Core logic of the attack. Must be implemented by subclasses."""
        pass

    def run(self):
        """Public method to run the attack with error handling."""
        try:
            self._execute()
        except KeyboardInterrupt:
            print(colored(f"\n[!] {self.__class__.__name__} stopped by user.", "yellow"))
        except Exception as e:
            print(colored(f"[!] An unexpected error occurred during the attack: {e}", "red"))
        finally:
            print(colored(f"\n[*] {self.__class__.__name__} finished.", "cyan"))
