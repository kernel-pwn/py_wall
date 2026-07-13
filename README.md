# Enhanced Firewall System
The Enhanced Firewall System is a comprehensive network security solution designed to detect and block malicious traffic, specifically targeting the Nimda worm. This system utilizes a combination of static blacklisting, signature-based detection, and anomaly detection using a sliding window rate limiter to identify and block suspicious IP addresses. The project aims to provide a robust and efficient security solution for network administrators and developers.

## Features
- **Static Blacklisting**: Blocks IP addresses listed in a blacklist file
- **Signature-based Detection**: Identifies the Nimda worm using a specific byte signature
- **Anomaly Detection**: Uses a sliding window rate limiter to detect and block IP addresses that exceed a certain threshold of packets per second
- **Centralized Logging**: Logs security events to a centralized log file
- **Whitelisting**: Allows trusted IP addresses to bypass security checks
- **Packet Callback Function**: Handles incoming packets and applies various detection mechanisms

## Tech Stack
* **scapy**: A Python-based interactive packet manipulation program and library
* **os** and **sys**: Used for interacting with the operating system and accessing system-specific parameters
* **time**: Used for handling time-related functions
* **collections**: Used for the `defaultdict` data structure
* **iptables**: A command-line utility used to configure the Linux kernel firewall
* **Python**: The primary programming language used for development

## Installation
To install the Enhanced Firewall System, follow these steps:
1. **Prerequisites**: Ensure you have Python and scapy installed on your system
2. **Clone the Repository**: Clone the repository using `git clone`
3. **Install Dependencies**: Install the required dependencies using `pip install -r requirements.txt`
4. **Configure iptables**: Configure iptables to work with the firewall system

## Usage
1. **Run the Firewall**: Run the firewall system using `python firewall_enhanced.py`
2. **Test the Firewall**: Use the `nimda_packet.py` file to simulate a Nimda worm attack and test the firewall's detection capabilities

## Project Structure
```markdown
.
├── firewall_enhanced.py
├── nimda_packet.py
├── requirements.txt
├── README.md
└── logs
    └── security.log
```

## Contributing
Contributions are welcome and encouraged. To contribute, please fork the repository, make your changes, and submit a pull request.

