import json
import os
from datetime import datetime # We'll use this to add timestamps to our logs
from scapy.all import IP, TCP, UDP, ICMP # Let's import just the layers we need

# Let's figure out the base directory of the project so our file paths always work
# os.path.abspath(__file__) -> /path/to/personal_firewall/src/rule_engine.py
# os.path.dirname(...) -> /path/to/personal_firewall/src
# os.path.dirname(os.path.dirname(...)) -> /path/to/personal_firewall
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_FILE = os.path.join(BASE_DIR, 'config', 'firewall_rules.conf')

class RuleEngine:
    def __init__(self, rules_file=RULES_FILE):
        self.rules_file = rules_file
        self.rules = []
        self.load_rules()

    def load_rules(self):
        """Loads firewall rules from the configuration file."""
        try:
            with open(self.rules_file, 'r') as f:
                self.rules = json.load(f)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Rules loaded successfully from {self.rules_file}")
        except FileNotFoundError:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Error: Rules file not found at {self.rules_file}")
            self.rules = []
        except json.JSONDecodeError:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Error: Invalid JSON in rules file: {self.rules_file}")
            self.rules = []
        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] An unexpected error occurred loading rules: {e}")
            self.rules = []

    def check_rule(self, packet, rule):
        """Checks if a given packet matches a specific rule."""
        # Most rules only make sense for IP packets, so let's check for that first
        if not packet.haslayer(IP):
            # If it's not an IP packet, we usually skip it (unless you want to log these)
            return False

        ip_layer = packet.getlayer(IP)

        # 1. Check Source IP
        if rule["src_ip"] != "any" and rule["src_ip"] != ip_layer.src:
            return False

        # 2. Check Destination IP
        if rule["dst_ip"] != "any" and rule["dst_ip"] != ip_layer.dst:
            return False

        # 3. Check Protocol
        protocol_match = False
        if rule["protocol"] == "any":
            protocol_match = True
        elif rule["protocol"] == "tcp" and packet.haslayer(TCP):
            protocol_match = True
        elif rule["protocol"] == "udp" and packet.haslayer(UDP):
            protocol_match = True
        elif rule["protocol"] == "icmp" and packet.haslayer(ICMP):
            protocol_match = True

        if not protocol_match:
            return False

        # 4. Check Ports (only for TCP/UDP if specified in rule and present in packet)
        # Let's only check ports if the protocol is TCP or UDP, to avoid errors on ICMP or other types
        if (rule["protocol"] == "tcp" or (rule["protocol"] == "any" and packet.haslayer(TCP))) and packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            if rule["src_port"] != "any" and rule["src_port"] != tcp_layer.sport:
                return False
            if rule["dst_port"] != "any" and rule["dst_port"] != tcp_layer.dport:
                return False
        elif (rule["protocol"] == "udp" or (rule["protocol"] == "any" and packet.haslayer(UDP))) and packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            if rule["src_port"] != "any" and rule["src_port"] != udp_layer.sport:
                return False
            if rule["dst_port"] != "any" and rule["dst_port"] != udp_layer.dport:
                return False
        # If the protocol is ICMP or "any" but not TCP/UDP, we don't need to check ports

        return True # If we made it this far, the packet matches the rule!

    def apply_rules(self, packet):
        """Applies the loaded rules to a packet and returns the action and matching rule's description.
        Returns "pass", "No matching rule" if no rule explicitly matches."""
        for rule in self.rules:
            if self.check_rule(packet, rule):
                return rule["action"], rule["description"] # Tell the caller what to do and why
        return "pass", "No explicit rule match (packet passed by default)"
        # Note: If you have a "Default deny all" rule in your config, this line shouldn't be reached
