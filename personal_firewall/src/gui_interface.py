import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import queue
import time # We might need this for adding small delays if necessary
from .firewall_core import FirewallCore

class GUIInterface:
    def __init__(self, master, firewall_core):
        self.master = master
        master.title("Personal Firewall Monitor")
        master.geometry("1000x600") # Let's set a nice big window size for our app

        self.firewall_core = firewall_core
        self.running = False # This keeps track of whether the firewall is running from the GUI's perspective

        self.create_widgets()
        self.process_log_queue() # Start looking for new log messages to show in the GUI

        # Make sure we clean up properly if the user closes the window
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_widgets(self):
        # Let's make a frame to hold our buttons
        button_frame = tk.Frame(self.master)
        button_frame.pack(pady=10)

        self.start_button = tk.Button(button_frame, text="Start Firewall", command=self.start_firewall, bg="green", fg="white", font=("Arial", 12))
        self.start_button.pack(side=tk.LEFT, padx=10)

        self.stop_button = tk.Button(button_frame, text="Stop Firewall", command=self.stop_firewall, state=tk.DISABLED, bg="red", fg="white", font=("Arial", 12))
        self.stop_button.pack(side=tk.LEFT, padx=10)

        # This is where we'll show the firewall logs to the user
        self.log_text = scrolledtext.ScrolledText(self.master, wrap=tk.WORD, bg="black", fg="lime green", font=("Consolas", 10))
        self.log_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.log_text.insert(tk.END, "Firewall log will appear here...\n")
        self.log_text.config(state=tk.DISABLED) # Make sure users can't edit the log area

        # Show the current status of the firewall at the bottom
        self.status_label = tk.Label(self.master, text="Status: Stopped", bd=1, relief=tk.SUNKEN, anchor=tk.W, font=("Arial", 10))
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

    def start_firewall(self):
        if not self.running:
            self.running = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.status_label.config(text="Status: Starting...")
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, "Attempting to start firewall...\n")
            self.log_text.config(state=tk.DISABLED)

            # We'll start the firewall in a separate thread so the GUI doesn't freeze
            threading.Thread(target=self._start_firewall_threaded, daemon=True).start()

    def _start_firewall_threaded(self):
        try:
            success = self.firewall_core.start_firewall()
            if success:
                self.master.after(0, lambda: self.status_label.config(text="Status: Running"))
                self.master.after(0, lambda: self.log_text.config(state=tk.NORMAL))
                self.master.after(0, lambda: self.log_text.insert(tk.END, "Firewall started successfully. Monitoring traffic.\n"))
                self.master.after(0, lambda: self.log_text.config(state=tk.DISABLED))
            else:
                self.master.after(0, lambda: messagebox.showerror("Firewall Error", "Failed to start firewall. Check console for details. Ensure you run with sudo."))
                self.master.after(0, self._revert_buttons_after_failure) # If starting fails, put the buttons back how they were
        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("Firewall Error", f"An error occurred during firewall start: {e}\nEnsure you run with sudo."))
            self.master.after(0, self._revert_buttons_after_failure)

    def _revert_buttons_after_failure(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Stopped (Error)")


    def stop_firewall(self):
        if self.running:
            self.running = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.status_label.config(text="Status: Stopping...")
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, "Attempting to stop firewall...\n")
            self.log_text.config(state=tk.DISABLED)

            # Again, stop the firewall in a separate thread so the GUI stays responsive
            threading.Thread(target=self._stop_firewall_threaded, daemon=True).start()

    def _stop_firewall_threaded(self):
        try:
            self.firewall_core.stop_firewall()
            self.master.after(0, lambda: self.status_label.config(text="Status: Stopped"))
            self.master.after(0, lambda: self.log_text.config(state=tk.NORMAL))
            self.master.after(0, lambda: self.log_text.insert(tk.END, "Firewall stopped successfully. UFW rules cleaned.\n"))
            self.master.after(0, lambda: self.log_text.config(state=tk.DISABLED))
        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("Firewall Error", f"Failed to stop firewall cleanly: {e}"))
            self.master.after(0, lambda: self.status_label.config(text="Status: Stopped with errors"))


    def process_log_queue(self):
        """Keep checking for new log messages and update the GUI with them."""
        while not self.firewall_core.get_log_queue().empty():
            try:
                message = self.firewall_core.get_log_queue().get_nowait()
                self.log_text.config(state=tk.NORMAL)
                self.log_text.insert(tk.END, message + "\n")
                self.log_text.see(tk.END) # Always scroll to the latest log entry
                self.log_text.config(state=tk.DISABLED)
            except queue.Empty:
                pass # This shouldn't happen because of the while condition, but just in case
        self.master.after(100, self.process_log_queue) # Check again in 100ms

    def on_closing(self):
        """This runs when the user tries to close the window."""
        if self.running:
            if messagebox.askyesno("Exit Firewall", "Firewall is running. Do you want to stop it before exiting? This will clean up UFW rules."):
                self.stop_firewall()
                # Give the firewall a moment to stop before closing the window
                self.master.after(500, self.master.destroy)
            else:
                # If the user doesn't want to stop the firewall, just close the window.
                # Note: This means the firewall rules will still be active until manually cleaned up.
                self.master.destroy()
        else:
            self.master.destroy()
