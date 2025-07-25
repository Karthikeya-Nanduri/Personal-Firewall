from scapy.all import sniff

class PacketSniffer:
    def __init__(self, packet_callback, interface=None):
        self.packet_callback = packet_callback
        self.interface = interface # For example, 'eth0' or 'wlan0'. If not set, we'll sniff on all interfaces.

    def start_sniffing(self, stop_event=None):
        """
        Starts sniffing packets using Scapy.
        stop_event: A threading.Event to signal when to stop sniffing.
        """
        print(f"Starting packet sniffing on interface: {self.interface if self.interface else 'all available interfaces'}")
        try:
            # The sniff function captures packets from the network
            # prn: This is the function we'll call for every packet we see
            # store: We don't want to keep packets in memory (saves RAM for long sniffs)
            # iface: This lets us pick which network interface to listen on (optional)
            # stop_filter: This is a function that returns True if we want to stop sniffing after the current packet
            sniff(prn=self.packet_callback, store=0, iface=self.interface,
                  stop_filter=lambda x: stop_event and stop_event.is_set())
        except Exception as e:
            print(f"Error during sniffing: {e}")
        finally:
            print("Packet sniffing stopped.")
