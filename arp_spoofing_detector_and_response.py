from scapy.all import *
from datetime import datetime
import logging
import os
import uuid
import argparse

class ColoredFormatter(logging.Formatter):
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    def format(self, record):
        message = super().format(record)
        return self.colorize(record.levelno, message)

    def colorize(self, level, message):
        if level == logging.DEBUG:
            return f"{self.CYAN}{message}{self.RESET}"
        elif level == logging.INFO:
            return f"{self.GREEN}{message}{self.RESET}"
        elif level == logging.WARNING:
            return f"{self.YELLOW}{message}{self.RESET}"
        elif level == logging.ERROR:
            return f"{self.RED}{message}{self.RESET}"
        elif level == logging.CRITICAL:
            return f"{self.MAGENTA}{message}{self.RESET}"
        return message

class ARPSpoofingDetectorAndResponse:

    DETAILS_MSG = " Dest. IP: {0} | Impersonated IP: {1} | False MAC: {2} | Actual MAC: {3}"
    POSSIBLE_ARP_SPOOFING_MSG = "Posible ARP Spoofing detected." + DETAILS_MSG
    ARP_SPOOFING_DETECTION_MSG = "ARP Spoofing detected." + DETAILS_MSG 

    def __init__(self, packet_count):
        self.logging_configuration()
        self.known_devices_file_path = "known_devices.json"
        self.known_devices = self.load_known_devices(self.known_devices_file_path)
        self.local_ip = self.get_local_ip()
        self.local_mac = self.get_local_mac()
        self.packet_count = self.get_packets_count(packet_count)

    def logging_configuration(self):
        """Initializes the logging tool
        """
        current_time = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        log_file_name = f"{current_time}_arp_spoofing_dr_log.log"

        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(ColoredFormatter(log_format))
        
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s',  
            handlers=[
                logging.FileHandler(log_file_name),
                console_handler
            ])

    def load_known_devices(self, file_path):
        """Loads the IP and MAC of known devices from a json file

        Args:
            file_path (str): path of the json file to be load

        Returns:
            {(str):(str)}: dictionary with key "ip_address" and value "mac_address"
        """
        known_devices = {}
        try:
            with open(file_path, 'r') as f:
                content = f.read().strip()
                data = json.loads(content)
        
                for device in data:
                    ip = device['ip_address'].strip()
                    mac = device['mac_address'].strip()
                    known_devices[ip] = self.convert_mac_into_valid_format(mac)
                    
        except FileNotFoundError:
            self.log_info(f"File {self.known_devices_file_path} doesn't exists")
            self.log_info("No known devices have been recognized")
        except Exception:
            self.log_info("No known devices have been recognized")
        
        return known_devices

    def convert_mac_into_valid_format(self, mac_address):
        """Converts a MAC address into a valid format (e.g., XX:XX:XX:XX:XX:XX)

        Args:
            mac_address (str): The MAC address to convert

        Returns:
            (str): The MAC address in a valid format
        """
        invalid_mac_separator = '-'
        valid_mac_separator = ':'

        if invalid_mac_separator in mac_address:
            mac_address = mac_address.replace(invalid_mac_separator, valid_mac_separator)
        
        return mac_address
    
    def get_local_ip(self):
        """Obtains the local IP address

        Returns:
            (str): Local IP address
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        finally:
            s.close() 
        return local_ip

    def get_local_mac(self):
        """Reliably retrieves the local MAC address
        
        Returns
            (str): Local MAC address
        """
        return ':'.join(("%012x" % uuid.getnode())[i:i+2] for i in range(0,12,2))

    def get_packets_count(self, packet_count):
        """Validates and adjust the number of packets specified by the user.

        This method checks the provided packet_count against predefined limits.
        If packet_count is None or below the minimum allowed, it sets it to a default value.
        If packet_count exceeds the maximum allowed, it logs a message and adjusts it to the maximum.

        Args:
            packets_count (int or None): The desired number of packets to send.

        Returns:
            (int): The validated number of packets, adjusted if necessary.
        """
        if packet_count is None or packet_count < MIN_PACKETS_COUNT:
            packet_count = DEFAULT_PACKETS_COUNT
    
        elif packet_count > MAX_PACKETS_COUNT:
            self.log_info(f"The maximum number of packets allowed is {MAX_PACKETS_COUNT}. Adjusting packet count to {MAX_PACKETS_COUNT}.")
            packet_count = MAX_PACKETS_COUNT
        
        return packet_count
       
    def log_info(self, message):
        """Displays a info log message

        Args:
            (str): Message to be displayed
        """
        logging.info(message)  

    def start_detection(self):
        """Captures ARP packets for process them for ARP Spoofing
        """
        try:
            self.log_info("Starting detection. Searching for ARP Spoofing...")
            sniff(prn=self.process_packet, filter="arp", store=0)
        except KeyboardInterrupt:
            self.log_info("Stopping ARP Spoofing detection...")

    def process_packet(self, packet):
        """Processes ARP packets for ARP spoofing detection

        Compares the actual MAC address of an IP with the MAC address from the ARP packet for that IP
        Displays alerts through logging

        Args:
            packet (scapy.packet): Packet to be processed
        """
        is_arp_reply_packet =  packet.haslayer(ARP) and packet[ARP].op == 2
        if is_arp_reply_packet:

            destination_ip = packet[ARP].pdst
            source_ip = packet[ARP].psrc
            destination_mac = packet[ARP].hwdst
            source_mac = packet[ARP].hwsrc
            actual_mac, is_reliable_mac = self.get_mac(source_ip)

            if (actual_mac is not None) and (actual_mac.lower() != source_mac.lower()):
                if is_reliable_mac:
                    self.log_warning(self.ARP_SPOOFING_DETECTION_MSG.format(destination_ip, source_ip, source_mac, actual_mac))

                    if self.local_ip == destination_ip:
                        self.restore_local_arp_cache(host_ip=source_ip, host_mac=actual_mac)

                    else:    
                        self.send_arp_packets(destination_ip=destination_ip, destination_mac=destination_mac, host_ip=source_ip, host_mac=actual_mac) 
                else:
                    self.log_warning(self.POSSIBLE_ARP_SPOOFING_MSG.format(destination_ip, source_ip, source_mac, actual_mac))
        
    def get_mac(self, ip):
        """Retrieves the MAC address for a given IP address and determines its reliability
        
        Args:
            ip (str): IP address for which the MAC address is to be determined

        Returns:
            tuple:
                - (str) MAC address of the provided IP
                - (bool) Flag to indicate the reliability of the MAC
        """
        if ip == self.local_ip:
            return self.local_mac, True
        
        elif ip in self.known_devices:
            return self.known_devices[ip], True
        
        else: 
            return self.get_mac_from_arp_response(ip), False
    
    def get_mac_from_arp_response(self, ip):
        """Retrieves the MAC address from an ARP response for a given IP address.

        Args:
            ip (str): The IP address to query.

        Returns:
            (str): MAC address in system format.
        """    
        answer, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout = 3, verbose = 0)
        if answer:
            return answer[0][1].src
        
        return None

    def log_warning(self, message):
        """Displays a warning log message

        Args:
            (str): Message to be displayed
        """
        logging.warning(message)

    def restore_local_arp_cache(self, host_ip, host_mac):
        """Restores local ARP cache deleting the host_ip entry and writting it again

        Args:
            host_ip (str): IP address for the host to be written to the local cache
            host_mac (str): Actual MAC address of the device with the host_ip
        """
        os.system(f"sudo arp -d {host_ip}")
        os.system(f"sudo arp -s {host_ip} {host_mac} temp")
        self.log_info(f"Restored local ARP cache: {host_ip} is at {host_mac}")  
    
    def send_arp_packets(self, destination_ip, destination_mac, host_ip, host_mac):
        """Sends ARP packets to destination_ip

        Args:
            destination_ip (str): IP address of the device where the host_mac address reference will be restored
            destination_mac (str): MAC address of the device with the destination_ip
            host_ip (str): IP address of the device being impersonated
            host_mac (str): Actual MAC address of the host device
        """
        arp_response = ARP(
                pdst=destination_ip,
                hwdst=destination_mac,
                psrc=host_ip,
                hwsrc=host_mac,
                op='is-at'
            )
        sendp(Ether(dst=destination_mac)/arp_response, verbose=0, count=self.packet_count)
        self.log_info(f"{self.packet_count} ARP packets sent to {destination_ip}: {host_ip} is at {host_mac}")

DEFAULT_PACKETS_COUNT = 10
MIN_PACKETS_COUNT = 1
MAX_PACKETS_COUNT = 1000

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-p', '--packets',
        type=int, 
        help=
            "Number of ARP packets to send to mitigate the attack during each detection. "
            f"Default value: {DEFAULT_PACKETS_COUNT}, "
            f"Min. value: {MIN_PACKETS_COUNT}, "
            f"Max. value: {MAX_PACKETS_COUNT}")
    
    args = parser.parse_args()
    packets_count = args.packets

    arp_spoofing_detector = ARPSpoofingDetectorAndResponse(packets_count)
    arp_spoofing_detector.start_detection()