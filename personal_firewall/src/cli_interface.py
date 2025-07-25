import time
import threading
import sys
import queue # We'll use this to handle log messages between threads
from .firewall_core import FirewallCore

class CLIInterface:
    def __init__(self, firewall_core):
        self.firewall_core = firewall_core
        self.running = False
        self.log_display_thread = None

    def _display_logs(self):
        """Continuously reads from the log queue and prints to console."""
        while self.running:
            try:
                # Try to get a log entry from the queue, but don't wait forever
                log_entry = self.firewall_core.get_log_queue().get(timeout=0.05)
                print(log_entry)
            except queue.Empty:
                # No new log messages right now, so let's just keep looping
                pass
            except Exception as e:
                print(f"Error displaying log: {e}")
            time.sleep(0.01) # Let's pause briefly so we don't use too much CPU

    def start(self):
        self.running = True
        print("Starting CLI Firewall Interface...")

        # We'll show log messages in a separate thread so the CLI stays responsive
        self.log_display_thread = threading.Thread(target=self._display_logs, daemon=True)
        self.log_display_thread.start()

        # Start the firewall core (this also starts the sniffer in its own thread)
        if not self.firewall_core.start_firewall():
            print("Firewall failed to start. Exiting CLI.")
            self.running = False
            return

        print("\nFirewall is running. Type 'stop' to halt.")
        # This is the main loop where we wait for user commands
        while self.running:
            try:
                command = input("Firewall > ").strip().lower()
                if command == "stop":
                    self.stop()
                elif command == "status":
                    print("Firewall Status: Running (monitoring and enforcing rules)")
                elif command == "help":
                    print("Commands: stop, status, help")
                else:
                    print("Unknown command. Type 'help' for options.")
            except EOFError: # This happens if the user presses Ctrl+D to exit
                print("\nExiting CLI due to EOF.")
                self.stop()
                sys.exit(0) # Exit cleanly
            except KeyboardInterrupt: # This happens if the user presses Ctrl+C
                print("\nExiting CLI due to KeyboardInterrupt.")
                self.stop()
                sys.exit(0) # Exit cleanly

    def stop(self):
        if self.running:
            self.running = False # Tell the log display thread to stop
            self.firewall_core.stop_firewall()
            print("CLI Firewall Interface stopped.")
