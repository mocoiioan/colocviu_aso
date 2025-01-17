from scapy.all import ARP, Ether, srp
import ipaddress

def get_mac_vendor(mac_address):
    """Caută vendorul MAC address-ului (OUI)."""
    oui_db = {
        "00-05-69": "VMware",
        "00-0C-29": "VMware",
        "00-1C-14": "VMware",
        "00-50-56": "VMware",
        "00-15-FF": "Microsoft Hyper-V",
        "00-03-FF": "Microsoft Hyper-V",
        "00-0F-4B": "Oracle VM VirtualBox",
        "08-00-27": "Oracle VM VirtualBox",
        "52-54-00": "QEMU",
        "00-16-3E": "Xen",
        # Adăugați mai multe OUI-uri cunoscute pentru VM-uri dacă este necesar
    }
    prefix = mac_address[:8].upper()
    return oui_db.get(prefix, "Necunoscut")

def scan_vlan(vlan_network):
    """Scanează un VLAN pentru a identifica posibile mașini virtuale."""
    print(f"Scanning VLAN: {vlan_network}")
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=vlan_network)
    answered, unanswered = srp(arp_request, timeout=2, verbose=False)

    virtual_machines = []
    for send, receive in answered:
        ip_address = receive[ARP].psrc
        mac_address = receive[Ether].src
        vendor = get_mac_vendor(mac_address)
        if vendor != "Necunoscut":
            virtual_machines.append((ip_address, mac_address, vendor))
            print(f"Posibilă mașină virtuală găsită:")
            print(f"  IP: {ip_address}")
            print(f"  MAC: {mac_address}")
            print(f"  Vendor (OUI): {vendor}")
            print("-" * 20)
        else:
            print(f"Dispozitiv găsit:")
            print(f"  IP: {ip_address}")
            print(f"  MAC: {mac_address}")
            print(f"  Vendor (OUI): {vendor}")
            print("-" * 20)

    if not virtual_machines:
        print("Nu s-au găsit mașini virtuale probabile.")

if __name__ == "__main__":
    # Introduceți rețeaua VLAN-ului pe care doriți să o scanați (ex: "192.168.1.0/24")
    vlan_network_to_scan = "192.168.1.0/24"

    try:
        ipaddress.ip_network(vlan_network_to_scan)
    except ValueError:
        print("Format de rețea VLAN invalid. Folosiți formatul CIDR (ex: 192.168.1.0/24).")
        exit()

    scan_vlan(vlan_network_to_scan)