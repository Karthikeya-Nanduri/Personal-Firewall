import subprocess
import logging
from datetime import datetime
import os
import queue
import threading
import time # We'll use this if we need to add small delays

from scapy.all import IP, TCP, UDP, ICMP # Let's import just the layers we need from Scapy

# Local imports
from .rule_engine import RuleEngine
from .packet_sniffer import PacketSniffer

# Set up logging
LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
FIREWALL_LOG_FILE = os.path.join(LOGS_DIR, 'firewall_log.log')

# Make sure the logs directory exists so we don't run into errors
os.makedirs(LOGS_DIR, exist_ok=True)

logging.basicConfig(filename=FIREWALL_LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class FirewallCore:
    def __init__(self, interface=None, rule_engine=None):
        self.interface = interface
        self.rule_engine = rule_engine if rule_engine else RuleEngine()
        self.sniffer = PacketSniffer(self._packet_handler, self.interface)
        self.log_queue = queue.Queue() # We'll use this to send logs to the GUI or CLI
        self.sniff_stop_event = threading.Event()
        self.ufw_rules_added = [] # We'll keep track of the rules we add so we can remove them later

    def _run_ufw_command(self, command_parts):
        """Helper to execute ufw commands."""
        try:
            # We need sudo because ufw needs root privileges
            full_command = ['sudo', 'ufw'] + command_parts
            # logging.debug(f"Executing UFW command: {' '.join(full_command)}") # Uncomment for debugging UFW commands
            result = subprocess.run(full_command, check=True, capture_output=True, text=True)
            # logging.debug(f"UFW stdout: {result.stdout.strip()}")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Error executing UFW command: {' '.join(full_command)}")
            logging.error(f"UFW Stderr: {e.stderr.strip()}")
            logging.error(f"UFW Stdout: {e.stdout.strip()}")
            return False
        except FileNotFoundError:
            logging.error("Error: ufw command not found. Is it installed and in PATH?")
            return False
        except Exception as e:
            logging.error(f"An unexpected error occurred running UFW command: {e}")
            return False

    def _add_ufw_rule(self, rule):
        """Adds a UFW rule based on a firewall rule dictionary. Returns the UFW command string used."""
        cmd_parts = []
        rule_action_ufw = rule["action"] # This will be either 'allow' or 'deny' for UFW

        # Let's figure out the protocol part
        protocol_str = ""
        if rule["protocol"] != "any":
            protocol_str = f"proto {rule['protocol']}"

        # Start building the command
        cmd_parts.append(rule_action_ufw)

        # Now let's build the source and destination parts
        src_part = ""
        if rule["src_ip"] != "any":
            src_part = f"from {rule['src_ip']}"

        dst_part = ""
        if rule["dst_ip"] != "any":
            dst_part = f"to {rule['dst_ip']}"

        port_part = ""
        if rule["dst_port"] != "any":
            port_part = f"port {rule['dst_port']}"

        # UFW Rule Construction Logic (Simplified, adapt as needed for complex scenarios)
        # This logic tries to cover common patterns:

        if src_part and not dst_part and not port_part:
            # For example: 'deny from 192.168.1.100' (applies to incoming to any port/proto)
            # Or 'allow from 192.168.1.100' (applies to outgoing from specific source, not ideal for this setup)
            # UFW by default treats 'from' as incoming unless 'out' is specified.
            cmd_parts.extend([src_part, protocol_str, port_part])
        elif dst_part and not src_part and not port_part:
            # For example: 'deny to 8.8.8.8' (applies to outgoing from any source to specific dest)
            cmd_parts.extend([dst_part, protocol_str, port_part])
        elif port_part:
            # For example: 'allow 80/tcp' (applies to incoming and outgoing)
            # If IP parts are missing but ports are present, specify 'to any' or 'from any'
            if not src_part and not dst_part:
                cmd_parts.extend([port_part, protocol_str])
            else: # With IP parts and port
                cmd_parts.extend([src_part, dst_part, port_part, protocol_str])
        elif protocol_str and not src_part and not dst_part and not port_part:
            # For example: 'deny icmp'
            cmd_parts.append(protocol_str)
        else: # This catches "any" cases, or more complex combined cases
            cmd_parts.extend([src_part, dst_part, port_part, protocol_str])

        # Remove any empty strings and trim spaces
        final_cmd_parts = [p.strip() for p in cmd_parts if p.strip()]
        ufw_command_str = " ".join(final_cmd_parts)

        if not ufw_command_str.strip(): # This shouldn't happen if the rule is well-formed
            logging.warning(f"Skipping empty UFW command construction for rule ID {rule.get('id', 'N/A')}")
            return False

        if self._run_ufw_command(ufw_command_str.split()):
            self.ufw_rules_added.append(ufw_command_str) # Save the command string so we can delete it later
            logging.info(f"Added UFW rule: '{ufw_command_str}' (Rule ID: {rule.get('id', 'N/A')}, Desc: {rule['description']})")
            return True
        return False

    def _delete_ufw_rule(self, rule_str):
        """Deletes a UFW rule using its exact command string."""
        delete_cmd = ['delete'] + rule_str.split()
        if self._run_ufw_command(delete_cmd):
            # logging.info(f"Deleted UFW rule: '{rule_str}'")
            return True
        return False

    def _initialize_ufw(self):
        """Sets up UFW with default policies and initial rules."""
        print("Initializing UFW firewall...")

        # 1. Let's disable UFW first to make sure we start clean
        print("Disabling UFW...")
        self._run_ufw_command(['disable'])
        time.sleep(0.5) # Give UFW a moment to process

        # 2. Now reset UFW to clear all existing rules (from previous runs or other services)
        print("Resetting UFW to clear existing rules...")
        self._run_ufw_command(['reset'])
        time.sleep(0.5) # Give UFW a moment to process

        # 3. Set the default policies
        print("Setting UFW default policies: deny incoming, allow outgoing.")
        self._run_ufw_command(['default', 'deny', 'incoming'])
        self._run_ufw_command(['default', 'allow', 'outgoing'])

        # 4. Enable UFW
        print("Enabling UFW...")
        if not self._run_ufw_command(['enable']):
            logging.error("Failed to enable UFW. Firewall may not be active.")
            print("ERROR: Failed to enable UFW. Check UFW logs/status.")
            return False
        time.sleep(1) # Give UFW a moment to fully enable

        # 5. Add essential rules (like SSH and loopback)
        print("Adding essential UFW rules (e.g., SSH, loopback)...")
        # Allow SSH (port 22) - This is super important if you're connecting remotely!
        if not self._run_ufw_command(['allow', 'ssh']): # Allows incoming SSH
            logging.warning("Failed to add UFW rule for SSH. You might get locked out if connecting remotely.")
        else:
            self.ufw_rules_added.append('allow ssh') # Track for cleanup

        # Loopback interface traffic is usually handled by UFW or iptables,
        # but you can add explicit rules if you want. UFW's default behavior usually covers it.
        # For example, if you want to allow a specific port on loopback:
        # self._add_ufw_rule({"action": "allow", "protocol": "tcp", "src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "src_port": "any", "dst_port": 8080, "description": "Allow local web server"})

        # 6. Now let's apply the custom rules from the config file
        print("Applying custom rules from firewall_rules.conf to UFW...")
        for rule in self.rule_engine.rules:
            # The "Default deny all" rule from the config file is basically handled by
            # `ufw default deny incoming`, so we mostly just need to add explicit
            # "block" (deny) and "allow" rules from the config that override the defaults.
            # The rule_engine.apply_rules() (for sniffing) still uses all rules.
            # For UFW, we just try to add each rule. UFW will handle precedence.
            self._add_ufw_rule(rule)

        print("\nInitial UFW setup complete. Current UFW status:")
        self._run_ufw_command(['status', 'verbose'])
        return True

    def _packet_handler(self, packet):
        """Callback function for the packet sniffer."""
        action, rule_description = self.rule_engine.apply_rules(packet)

        log_entry = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
        log_entry += f"Action: {action.upper()} (Rule: {rule_description}) "

        # Let's get packet details if there's an IP layer
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            log_entry += f"SrcIP: {ip_layer.src} DstIP: {ip_layer.dst} "

            # Check for TCP/UDP layers
            if packet.haslayer(TCP):
                tcp_layer = packet.getlayer(TCP)
                log_entry += f"Proto: TCP SrcPort: {tcp_layer.sport} DstPort: {tcp_layer.dport} "
            elif packet.haslayer(UDP):
                udp_layer = packet.getlayer(UDP)
                log_entry += f"Proto: UDP SrcPort: {udp_layer.sport} DstPort: {udp_layer.dport} "
            elif packet.haslayer(ICMP):
                log_entry += f"Proto: ICMP "
            else:
                log_entry += f"Proto: Other ({ip_layer.proto}) "
        else:
            log_entry += f"Non-IP Packet: {packet.summary()} " # If it's not an IP packet, just show a summary

        # Log to file
        if action == "block":
            logging.warning(log_entry)
        elif action == "allow":
            logging.info(log_entry)
        else: # "pass" (should ideally be covered by "Default deny all" or an explicit allow/deny)
            logging.info(log_entry)

        # Send the log to the queue so the CLI/GUI can show it
        self.log_queue.put(log_entry)

    def start_firewall(self):
        """Starts the firewall core logic, including UFW setup and sniffing."""
        print("Starting firewall services...")
        if not self._initialize_ufw():
            print("Failed to initialize UFW. Aborting firewall start.")
            return False # Let the caller know we failed

        self.sniff_stop_event.clear() # Make sure the stop event is clear before starting
        sniff_thread = threading.Thread(target=self.sniffer.start_sniffing, args=(self.sniff_stop_event,), daemon=True)
        sniff_thread.start()
        print("Firewall operational. Monitoring traffic...")
        return True # Let the caller know we succeeded

    def stop_firewall(self):
        """Stops the firewall and cleans up UFW rules."""
        print("Stopping firewall services...")
        self.sniff_stop_event.set() # Tell the sniffer to stop
        time.sleep(0.1) # Give the sniffer a moment to stop

        # Let's delete all the rules we added
        print("Deleting custom UFW rules added by this firewall...")
        # Go in reverse order to avoid any issues with rule numbering
        for rule_str in reversed(self.ufw_rules_added):
            self._delete_ufw_rule(rule_str)
        self.ufw_rules_added = [] # Clear the list now that we're done

        # Reset UFW to a clean, inactive state
        print("Resetting UFW to default inactive state...")
        self._run_ufw_command(['reset'])
        time.sleep(0.5)

        print("Firewall stopped. UFW rules cleaned up and UFW is inactive.")

    def get_log_queue(self):
        return self.log_queue
