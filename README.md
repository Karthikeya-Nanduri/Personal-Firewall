# Personal-Firewall
# 🛡️ Personal Firewall (Python & UFW)

A lightweight, customizable personal firewall developed in Python, designed to filter network traffic, enforce rules using UFW, and provide real-time logging through both Command Line and Graphical User Interfaces.

## ✨ Features

* **Rule-Based Filtering:** Define custom rules to allow or block traffic based on IP, port, and protocol.
* **Packet Sniffing:** Utilizes Scapy to passively monitor network packets.
* **System-Level Enforcement:** Integrates with UFW (Uncomplicated Firewall) to actively enforce defined rules on the Linux system.
* **Real-time Logging:** Records all firewall decisions and packet details to a log file.
* **Dual Interface:** Offers both a Command Line Interface (CLI) and a Graphical User Interface (GUI) for control and monitoring.
* **Graceful Shutdown:** Ensures UFW rules are cleaned up upon stopping the firewall.

## 🚀 How It Works (Simplified)

Imagine your computer's internet connection is a gate. This Python firewall acts as a smart security guard:

1.  **You set the rules:** You define what traffic should be allowed or blocked in a simple configuration file.
2.  **It watches:** Using **Scapy**, the firewall constantly observes every piece of data trying to enter or leave your computer.
3.  **It decides:** For each piece of data, it quickly checks your rules to see if it should be allowed or blocked.
4.  **It enforces:** For any traffic that needs blocking or allowing, it tells your computer's built-in firewall, **UFW**, to apply the necessary action immediately.
5.  **It records:** Every decision is logged, creating a detailed history of your network activity.
6.  **You monitor:** You can see all this happening live through a simple text window (CLI) or a visual application (GUI).

## 📁 File Structure

The project is organized into a clear, modular structure:
├── src/
│   ├── packet_sniffer.py
│   ├── rule_engine.py
│   ├── firewall_core.py
│   ├── gui_interface.py
│   └── cli_interface.py
├── config/
│   └── firewall_rules.conf
├── logs/
│   └── .gitkeep  (Placeholder to keep the directory in Git)
└── main.py
* `main.py`:
    * **Description:** The main entry point of the application. It parses arguments, checks for root privileges, and launches either the CLI or GUI.
* `config/`:
    * **Description:** Directory for configuration files.
    * `firewall_rules.conf`: Defines the customizable firewall rules (allow/block, IP, port, protocol) in JSON format.
* `logs/`:
    * **Description:** Directory for storing firewall activity logs.
* `src/`:
    * **Description:** Contains the core Python source code for the firewall's functionalities.
    * `packet_sniffer.py`: Handles raw packet capturing and observation using the Scapy library.
    * `rule_engine.py`: Loads rules from `firewall_rules.conf` and provides the logic to match network packets against these rules.
    * `firewall_core.py`: The central component. It manages UFW rules, processes sniffed packets, logs events, and controls the firewall's overall lifecycle (start/stop).
    * `gui_interface.py`: Implements the graphical user interface using Tkinter for interactive control and live log monitoring.
    * `cli_interface.py`: Provides a text-based command-line interface for controlling the firewall and displaying live logs.

