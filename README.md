![Python](https://img.shields.io/badge/Language-Python-blue?logo=python)
![Library](https://img.shields.io/badge/Library-Scapy-yellow)
![License](https://img.shields.io/badge/License-Apache%202.0-lightgrey)
![Status](https://img.shields.io/badge/Status-In%20Progress-orange)

# PoisonNet

## 📘 Introduction

**PoisonNet** is an educational toolkit designed for **network administrators, cybersecurity students, and educators** to analyze and understand how ARP spoofing and DNS redirection work within a controlled network environment.

This program is based on the ARP and DNS protocols:
- **ARP (Adress Resolution Protocol):** Allows to map an IPv4 address to a MAC address on the same local area network (LAN). This is essential for machines on the same subnet to communicate at the link level, because Ethernet frames require MAC addresses for physical transmission.
- **DNS (Domain Name System):** Translates human-readable domain names into IP addresses (ex. www.google.com to 8.8.8.8) that machines use to communicate wiith each other. It is the “naming system” of the Internet.

The tool allows you to:
- Simulate **ARP poisoning** to inspect traffic redirection.
- Perform **DNS spoofing** for testing DNS integrity.
- Capture and log **ARP and DNS packets** for later analysis.
- Study **network security concepts** in a controlled setting.

⚠️ **Important:** This project is strictly for educational use, research, or testing on networks **you own or have explicit permission to audit**.


## ⚙️ Requirements and Installation

### 1. System requirements
- **Operating system:** Linux (Debian or Ubuntu recommended).
- **Python version:** 3.8 or higher.
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

    sudo python3 poison-tool.py


## 🌐​ Usage

Once the program is running, the main menu will appear with **various options**. Below is an explanation of what each option does in terms of code and network traffic:

### 1. ARP spoofing


### 2. DNS spoofing


### 3. ARP and DNS sniffing


### 4. Restore ARP


### 5. Restore DNS


### 6. Exit


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
