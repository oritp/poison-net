from poisonnet_lib import (
    get_interface,
    start_arp_spoofing,
    start_dns_spoofing,
    start_sniffing,
    restore_arp,
    restore_dns
)

def main():
    print("""
    ===========================
             PoisonNet        
    ===========================
    1. ARP spoofing
    2. DNS spoofing
    3. ARP and DNS sniffing
    4. Restore ARP
    5. Restore DNS
    6. Exit
    """)
    
    while True:
        option = input("Select an option: ")
        if option == "1":
            print("\nYou choose ARP spoofing.")
            target_ip = input("Enter the target IP: ")
            gateway_ip = input("Enter the router IP: ")
            interface = get_interface()
            start_arp_spoofing(target_ip, gateway_ip, interface)
        elif option == "2":
            print("\nYou choose DNS spoofing.")
            target_ip = input("Enter the target IP: ")
            gateway_ip = input("Enter the router IP: ")
            fake_ip = input("Enter the chosen IP: ")
            interface = get_interface()
            start_arp_spoofing(target_ip, gateway_ip, interface)
            start_dns_spoofing(interface, target_ip, fake_ip)
        elif option == "3":
            print("\nYou choose ARP and DNS sniffing.")
            target_ip = input("Enter the target IP: ")
            gateway_ip = input("Enter the router IP: ")
            interface = get_interface()
            start_arp_spoofing(target_ip, gateway_ip, interface)
            start_sniffing(interface, target_ip)
        elif option == "4":
            print("\nYou choose ARP restoring.")
            target_ip = input("Enter the target IP: ")
            gateway_ip = input("Enter the router IP: ")
            restore_arp(target_ip, gateway_ip)
        elif option == "5":
            print("\nYou choose DNS restoring.")
            restore_dns()
        elif option == "6":
            print("Exiting...")
            break
        else:
            print("[!] Invalid option.")

if __name__ == "__main__":
    main()
