![Python](https://img.shields.io/badge/Language-Python-blue?logo=python)
![Library](https://img.shields.io/badge/Library-Scapy-yellow)
![License](https://img.shields.io/badge/License-Apache%202.0-lightgrey)
![Status](https://img.shields.io/badge/Status-In%20Progress-orange)

# PoisonNet

## 📘 Introduction

**PoisonNet** is an educational toolkit designed for **network administrators, cybersecurity students, and educators** to analyze and understand how ARP spoofing and DNS redirection work within a controlled network environment.

This program is based on the ARP and DNS protocols:
- **ARP (Adress Resolution Protocol):** Allows to map an IPv4 address to a MAC address on the same local area network (LAN). This is essential for machines on the same subnet to communicate at the link level, because Ethernet frames require MAC addresses for physical transmission.\
  Communication occurs between a host that sends a broadcast ARP Request (destination MAC address ff:ff:ff:ff:ff:ff) asking “Who has IP X.X.X.X?”, and the target host that responds with a unicast ARP Reply with its MAC, addressed to the requester.
- **DNS (Domain Name System):** Translates human-readable domain names into IP addresses (e.g. www.google.com to 8.8.8.8) that machines use to communicate wiith each other. It is the “naming system” of the Internet.\
  Communication occurs between the client sending a query, and the server responding with an answer that may contain one or more records (A, AAAA, CNAME, MX...).

This project employs three basic hacking and cybersecurity techniques:
- **Sniffing:** To listen, capture, and examine packets circulating on a network.
- **Spoofing:** Impersonating network users by sending packets with forged headers, tricking devices into sending traffic to the attacker or to fake destinations.
- **MITM (Man in the Middle):** The attacker positions himself between two communicating parties without being detected by the victims, intercepts, and can modify and forward the traffic.

The tool allows you to:
- Simulate **ARP poisoning** to inspect traffic redirection.
- Perform **DNS spoofing** for testing DNS integrity.
- Capture and log **ARP and DNS packets** for later analysis.
- Study **network security concepts** in a controlled setting.

⚠️ **Important:** This project is strictly for educational use, research, or testing on networks **you own or have explicit permission to audit**.


## ⚙️ Requirements and Installation

### 1. System requirements
- **Operating system:** Linux (Debian or Ubuntu recommended).
- **Python version:** 3.7 or higher.
- **Privileges:** Root or `sudo` access required for ARP/DNS operations.

### 2. Install dependencies

You need to install the `scapy` library, a powerful interactive packet manipulation library:

    sudo apt update
    sudo apt install python3-pip
    pip install scapy

### 3. Clone the repository

Then, clone the repository to your system:

    git clone https://github.com/oritp/poison-net.git
    cd poison-net
    
### 4. Execution

To run the tool do the following:

    sudo python3 poisonnet.py


## 🌐​ Usage

Once the program is running, the main menu will appear with **various options**. Below is an explanation of what each option does in terms of code and network traffic:

### 1. ARP spoofing

This option performs the spoofing technique on the ARP protocol.

First, it runs `start_arp_spoofing()`, which launches a daemon thread executing `arp_spoofing()`, thereby obtaining the MAC addresses, constructing fake ARP replies and, continuously sending ARP frames to both the target and the gateway to "poison" their ARP tables.

The goal is for the target to believe the attacker's MAC address is that of the gateway, and for the gateway to believe the attacker's MAC address is that of the target, thus creating an interceptor or MITM.

If the ARP packets are not redirected to the compromised target, we can disconnect it. If we redirect them correctly, we will become observers and monitor all packet traffic between the attacked machine and the router.

The process can be interrupted manually with the `Ctrl+C` combination, although it is recommended to clear the ARP tables with option 4 afterwards, as they will remain corrupted until they expire.


### 2. DNS spoofing

This option performs the spoofing technique on the DNS protocol.

First, it runs `start_arp_spoofing()` to maintain the MITM position, and then `start_dns_spoofing()`, which sets a fake IP address and enables IP forwarding to redirect/route DNS traffic.

It listens for UDP traffic on port 53 on the specified interface and, when it detects a DNS query from the target, creates and sends a fake DNS response.

The goal is to ensure that queries from the compromised or targeted machine are not resolved correctly and that the user is redirected to a desired host regardless of the search performed.

The process can be interrupted manually with the `Ctrl+C` combination, although it is recommended to clear the iptables rules with option 5 afterwards, as they will remain corrupted until they expire.


### 3. ARP and DNS sniffing

This option allows you to sniff packet traffic and obtain log files with information for analyzing ARP and DNS activity.

First, run `start_arp_poofing()` to maintain the MITM position and, `start_sniffing()`, starting a thread that listens for traffic and records it.

When a packet is captured with `process_packet()`, it is analyzed and classified according to whether it is ARP (extracting requests/replies) or DNS (extracting queries/answers) and written to the corresponding log file.

To stop the process, press `Ctrl+C`, ending the thread and preserving the log files.


### 4. Restore ARP

This option runs `restore_arp()`. It obtains the correct MAC addresses and sends authentic ARP replies to correct the target and router's ARP tables, returning the network to its normal state.

### 5. Restore DNS

This option runs `restore_dns()`. It flushes the NAT (Network Address Translation) table and thus remove any added DNS redirect rules.

### 6. Exit

This option exits the main menu, terminating the program. If there are any daemon threads running (e.g. spoofing), they may continue to run, so it is recommended to reset ARP and clear DNS rules before exiting to avoid leaving the network in an unsafe state.


## ⚖️ Responsible use and warning

This project is provided **for educational purposes** and is intended for network administrators who want to **audit and study** the behavior of their own infrastructure.

**Do not** use this tool on third-party networks without explicit permission.

The author is not responsible for any misuse of this software.

> ***Ethical Hacking Reminder:***\
  *Understanding how attacks work is essential to defend against them.*


## 📄 License

This project is distributed under the **Apache-2.0 License** with an educational use clause.

You are free to use, modify, and share the code as long as you do not use it for malicious purposes.


## 👦 Author

This project was developed by *@oritp* for educational and administrative network analysis.

I hope you find it useful. Enjoy! :)
