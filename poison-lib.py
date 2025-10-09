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

def process_packet(packet):
    """ Procesa los paquetes ARP y DNS """
    data = ""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ARP Packet Processing
    if packet.haslayer(ARP):
        if packet.op == 1:  # ARP Request
            data = f"[{timestamp}] ARP Request: {packet.psrc} asks: \"Who is {packet.pdst}?\"\n"
        elif packet.op == 2:  # ARP Reply
            data = f"[{timestamp}] ARP Reply: {packet.psrc} answers with MAC: {packet.hwsrc}\n"
        write_log(arp_log, data)

    # DNS Packet Processing
    if packet.haslayer(DNS) and packet.haslayer(UDP):
        dns_layer = packet[DNS]
        ip_src = packet[IP].src if packet.haslayer(IP) else "Unknown"
        ip_dst = packet[IP].dst if packet.haslayer(IP) else "Unknown"
        
        if dns_layer.qr == 0 and dns_layer.qd:  # DNS Request
            dns_query = dns_layer.qd.qname.decode('utf-8') if dns_layer.qd.qname else "Unknown"
            data = (
                f"[{timestamp}] Request DNS:\n"
                f"- Client: {ip_src}\n"
                f"- Query: {dns_query}\n"
            )
        elif dns_layer.qr == 1:  # DNS Reply
            answers = []
            an = dns_layer.an
            records = an if isinstance(an, list) else [an] if an else []
            for record in records:
                rtype = record.get_field("type").i2repr(record, record.type) if hasattr(record, "type") else "Unknown"
                rdata = getattr(record, "rdata", "No rdata")
                answers.append(f"{rtype}: {rdata}")
            if not answers:
                answers.append("No answers")
            data = (
                f"[{timestamp}] Reply DNS:\n"
                f"- DNS Server: {ip_src}\n"
                f"- IP Resolved: {answers}\n"
            )
        write_log(dns_log, data)
