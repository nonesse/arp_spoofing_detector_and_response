from scapy.all import *
import logging
import os
from datetime import datetime
import uuid

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
            return f"{self.RED}{message}{self.RESET}"
        elif level == logging.ERROR:
            return f"{self.YELLOW}{message}{self.RESET}"
        elif level == logging.CRITICAL:
            return f"{self.MAGENTA}{message}{self.RESET}"
        return message

class ARPSpoofingDetectorAndResponse:

    DETAILS_MSG = " Dest. IP: {0} | Impersonated IP: {1} | False MAC: {2} | Actual MAC: {3}"
    POSSIBLE_ARP_SPOOFING_MSG = "Posible ARP Spoofing detected." + DETAILS_MSG
    ARP_SPOOFING_DETECTION_MSG = "ARP Spoofing detected." + DETAILS_MSG 

    def __init__(self):
        self.logging_configuration()
        self.known_devices_file_path = "known_devices.json"
        self.known_devices = self.load_known_devices(self.known_devices_file_path)
        self.local_ip = self.get_local_ip()
        self.local_mac = self.get_local_mac()

    def logging_configuration(self):
        """Initialize the logging tool
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
        """Load the IP and MAC of known devices from a json file

        Args:
            file_path (str): path of the json file to be load

        Returns:
            known_devices {(str):(str)}: dictionary with key "ip_address" and value "mac_address"
                """
        known_devices = {}
        try:
            with open(file_path, 'r') as f:
                content = f.read().strip()
                data = json.loads(content)
        
                for device in data:
                    ip = device['ip_address'].strip()
                    mac = device['mac_address'].strip()
                    known_devices[ip] = mac
                    
        except FileNotFoundError:
            print(f"File {self.known_devices_file_path} doesn't exists")
            print("No known devices have been recognized")
        except Exception:
            print("No known devices have been recognized")
        
        return known_devices

    def get_local_ip(self):
        """Obtains the local IP address

        Returns:
            local_ip (str): Local IP address
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        finally:
            s.close() 
        return local_ip

    def get_local_mac(self):
        """Obtains the local MAC address reliably
        
        Returns
            (str): Local MAC address
        """
        return ':'.join(("%012x" % uuid.getnode())[i:i+2] for i in range(0,12,2))

    def start_detection(self):
        """Capture ARP packets for process them for ARP Spoofing
        """
        try:
            print("Searching for ARP Spoofing...")
            sniff(prn=self.process_packet, filter="arp", store=0)
        except KeyboardInterrupt:
            print("Stopping ARP Spoofing detection...")

    def process_packet(self, packet):
        """Process ARP packets for ARP Spoofing detection

        Compare the actual MAC address of an IP with the MAC address from the ARP packet for that IP.
        Display alerts through logging

        Args:
            packet (scapy.packet): Packet to be processed
        """
        is_arp_reply_packet =  packet.haslayer(ARP) and packet[ARP].op == 2
        if is_arp_reply_packet:

            source_ip = packet[ARP].psrc
            destination_ip = packet[ARP].pdst
            source_mac = packet[ARP].hwsrc
            actual_mac = self.get_mac(source_ip)

            if (actual_mac is not None) and (actual_mac.lower() != source_mac.lower()):

                if self.local_ip == destination_ip:
                    self.i_am_the_target(impersonated_ip=source_ip, false_mac=source_mac, actual_mac=actual_mac)

                elif self.local_ip == source_ip:
                    self.someone_is_trying_to_impersonate_me(destination_ip=destination_ip, destination_mac=packet[ARP].hwdst, false_mac=source_mac)

                else:
                    self.log_warning(self.POSSIBLE_ARP_SPOOFING_MSG.format(destination_ip, source_ip, source_mac, actual_mac))
     
    def get_mac(self, ip):
        """Get the MAC address for a given IP address
        
        Args:
            ip (str): IP address for which the MAC address is to be determined

        Returns:
            (str) MAC address of the provided IP
        """
        if ip == self.local_ip:
            return self.local_mac
        
        elif ip in self.known_devices:
            return self.known_devices[ip]
        
        else: 
            answer, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout = 3, verbose = 0)
            if answer:
                return answer[0][1].src
        
    def i_am_the_target(self, impersonated_ip, false_mac, actual_mac):
        """Restore local ARP cache for counter attack ARP Spoofing attack

        Args:
            impersonated_ip (str): IP address that the attacker is trying to impersonate
            false_mac (str): MAC address that the attacker is trying to bind to the impersonated_ip
            actual_mac (str): Actual MAC address of the impersonated_ip
        """

        self.log_warning(self.ARP_SPOOFING_DETECTION_MSG.format(self.local_ip, impersonated_ip, false_mac, actual_mac))
        self.restore_local_arp_cache(host_ip=impersonated_ip, host_mac=actual_mac)

    def log_warning(self, message):
        """Display a warning log message

        Args:
            message (str): Message to be displayed
        """
        logging.warning(message)

    def restore_local_arp_cache(self, host_ip, host_mac):
        """Restore local ARP cache deleting the host_ip entry and writting it again

        Args:
            host_ip (str): IP address for the host to be written to the local cache.
            host_mac (str): Actual MAC address of host_ip.
        """
        os.system(f"sudo arp -d {host_ip}")
        os.system(f"sudo arp -s {host_ip} {host_mac} temp")
        self.log_info(f"Restored local ARP cache: {host_ip} is at {host_mac}")
        
    def log_info(self, message):
        """Display a info log message

        Args:
            message (str): Message to be displayed
        """
        logging.info(message)

    def someone_is_trying_to_impersonate_me(self, destination_ip, destination_mac, false_mac):
        """Send ARP packets to the destination_ip trying to restore our MAC reference in destination machine

        Args:
            destination_ip (str): IP address for the device where the local MAC address reference will be restored.
            destination_mac (str): MAC address of destination_ip device.
            false_mac (str): MAC address that the attacker is trying to bind to our local machine's IP
        """
        self.log_warning(self.ARP_SPOOFING_DETECTION_MSG.format(destination_ip, self.local_ip, false_mac,self.local_mac))
        self.send_arp_packets(destination_ip=destination_ip, destination_mac=destination_mac)
    
    
    def send_arp_packets(self, destination_ip, destination_mac):
        """Send ARP packets for restore local MAC address reference in destination machine

        Args:
            destination_ip (str): IP address for the device where the local MAC address reference will be restored.
            destination_mac (str): MAC address of destination_ip device.
        """
        local_ip = self.local_ip
        local_mac = self.local_mac

        arp_response = ARP(
                pdst=destination_ip,
                hwdst=destination_mac,
                psrc=local_ip,
                hwsrc=local_mac,
                op='is-at'
            )
        sendp(Ether(dst=destination_mac)/arp_response, verbose=0, count=50)
        self.log_info(f"ARP packets sent to {destination_ip}: {local_ip} is at {local_mac}")

if __name__ == "__main__":
    arp_spoofing_detector = ARPSpoofingDetectorAndResponse()
    arp_spoofing_detector.start_detection()