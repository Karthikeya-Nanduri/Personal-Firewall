import argparse
import os
import sys
import tkinter as tk # Tkinter import for GUI mode

# Add src directory to Python path to allow direct imports
# This makes imports like 'from src.firewall_core import FirewallCore' possible
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# Now import modules from src
from src.firewall_core import FirewallCore
from src.cli_interface import CLIInterface
from src.gui_interface import GUIInterface
from src.rule_engine import RuleEngine

def main():
    parser = argparse.ArgumentParser(description="Lightweight Personal Firewall")
    parser.add_argument('--cli', action='store_true', help='Run the firewall with a Command Line Interface.')
    parser.add_argument('--gui', action='store_true', help='Run the firewall with a Graphical User Interface (default if no flag).')
    parser.add_argument('--interface', type=str, default=None, help='Network interface to sniff on (e.g., eth0, wlan0). Defaults to all if not specified.')

    args = parser.parse_args()

    # IMPORTANT: Check for root privileges
    if os.geteuid() != 0:
        print("Error: This script must be run with root privileges (e.g., using sudo).")
        sys.exit(1)

    # Initialize RuleEngine first (it loads rules from config)
    rule_engine = RuleEngine()

    # Initialize FirewallCore (it needs the rule_engine)
    firewall = FirewallCore(interface=args.interface, rule_engine=rule_engine)

    # Determine which interface to run
    if args.cli:
        print("Starting firewall in CLI mode...")
        cli = CLIInterface(firewall)
        cli.start()
    elif args.gui or (not args.cli and not args.gui): # Default to GUI if neither --cli nor --gui is provided
        print("Starting firewall in GUI mode...")
        root = tk.Tk()
        gui = GUIInterface(root, firewall)
        root.mainloop() # Start the Tkinter event loop
    else:
        print("Invalid usage. Please specify either --cli or --gui (default is GUI). Use --help for options.")
        sys.exit(1)

if __name__ == "__main__":
    main()
