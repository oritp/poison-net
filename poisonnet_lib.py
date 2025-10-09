import os
import time
import datetime
import threading
import random
import scapy.all as scapy
from scapy.all import conf, sniff, ARP, DNS, IP, UDP, DNSQR, DNSRR

FAKE_IP = None

def random_mac():
    """ Generate a random MAC address """
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))

def get_mac(ip):
    """ Get the MAC adress of a device by giving its IP adress """
    arp_request = scapy.ARP(pdst=ip)
    broadcast_mac = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast_mac / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print("[!] Could not get the target or router MAC.")
    return None

def get_interface():
    iface = input("Enter the network interface (leave blank to auto-detect): ")
    if not iface:
        iface = conf.iface
    return iface
