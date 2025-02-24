# ARP Spoofing Detector and Response

This Python script is designed to detect and respond to ARP spoofing attacks in Linux systems within a local network. It utilizes the Scapy library to sniff ARP packets and compare the MAC addresses to identify potential spoofing attempts.

## Features

- Detects ARP spoofing attempts by monitoring ARP packets.
- Logs detailed information about detected spoofing attempts.
- Restores local ARP cache entries to mitigate spoofing effects.
- Color-coded logging for better visibility in the console.
- Save logs information in a .log file

## Requirements

- Python 3.x
- Scapy library
- Access to run commands with `sudo` to sniff packets and modify local ARP cache

You can install the required library using pip:

```bash
pip install scapy
```
## Usage

1. **Prepare Known Devices**: Create a known_devices.json file in the same directory as the script. This file can either be empty or not exist at all, but for optimal performance, it is recommended to include a list of known devices with their IP and MAC addresses. Having this information allows the script to more accurately detect ARP spoofing attempts:

 ```json
[
    {
        "ip_address": "192.168.55.1",
        "mac_address": "11:22:33:44:55:66"
    },
    {
        "ip_address":"192.168.55.2",
        "mac_address":"77:88:99:AA:BB:CC"
    }
]
```

2. **Run the Script**: Execute the script with Python. You will need to run it with elevated privileges to allow it to sniff packets and modify local ARP cache.

	`sudo python arp_spoofing_detector_and_response.py`

3. **Monitor Output**: The script will start sniffing ARP packets and log any detected spoofing attempts. The logs will be saved in a file named with the current timestamp.
## Logging

The script uses a custom logging configuration that outputs messages to both the console and a log file. The log messages are color-coded based on their severity level, but the script only displays at two levels, `WARNING` and `INFO`:

    DEBUG: Cyan
    INFO: Green
    WARNING: Red
    ERROR: Yellow
    CRITICAL: Magenta
## Main Functions

    __init__(): Initializes the detector, sets up logging, and loads known devices.
    
    start_detection(): Begins sniffing ARP packets.
    
    process_packet(packet): Processes each ARP packet to detect spoofing.
    
    get_mac(ip): Retrieves the MAC address for a given IP.
    
    restore_local_arp_cache(host_ip, host_mac): Restores the local ARP cache for a specified IP.
    
    send_arp_packets(destination_ip, destination_mac, host_ip, host_mac): Sends ARP packets to restore MAC address references.
## License

This project is licensed under the MIT License. See the LICENSE file for details.
## Acknowledgments

    Scapy - For packet manipulation and sniffing capabilities.

Feel free to modify any sections to better fit your project or add any additional information that you think is necessary!
