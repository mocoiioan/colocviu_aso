import scapy.all as scapy
import socket
import os

def get_default_gateway():
    """
    Get the default gateway of the machine using the `ip` or `route` command.
    """
    try:
        # Try to fetch the default gateway
        if os.name == "nt":  # Windows
            response = os.popen("ipconfig | findstr /i \"Default Gateway\"").read()
        else:  # Unix/Linux/macOS
            response = os.popen("ip route show default").read()
        
        # Extract the gateway IP address
        for line in response.splitlines():
            if "default via" in line or "Default Gateway" in line:
                return line.split()[-1].strip()
    except Exception as e:
        print(f"[ERROR] Unable to determine default gateway: {e}")
    return None

def scan_vlans(ip_range):
    """
    Perform an ARP scan on the specified IP range to detect active devices.
    """
    print(f"\nScanning VLAN for active devices in range: {ip_range}")
    try:
        # Send ARP requests to the entire IP range
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

        devices = []
        for element in answered_list:
            devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc})

        return devices
    except Exception as e:
        print(f"[ERROR] Error while scanning: {e}")
        return []

def display_devices(devices):
    """
    Display the list of active devices with their IP and MAC addresses.
    """
    if len(devices) == 0:
        print("\nNo active devices found.")
    else:
        print("\nActive devices found:")
        print("-" * 40)
        print(f"{'IP Address':<18}{'MAC Address':<18}")
        print("-" * 40)
        for device in devices:
            print(f"{device['ip']:<18}{device['mac']:<18}")
        print("-" * 40)

def main():
    """
    Main function to execute the VLAN scanning script.
    """
    print("Active VM Identifier Script\n")
    
    # Get the default gateway and construct the IP range
    gateway = get_default_gateway()
    if not gateway:
        print("[ERROR] Unable to determine the default gateway. Exiting.")
        return

    # Assuming a /24 subnet mask (e.g., 192.168.1.1 -> 192.168.1.0/24)
    ip_range = f"{'.'.join(gateway.split('.')[:-1])}.0/24"

    # Scan the VLAN for active devices
    devices = scan_vlans(ip_range)

    # Display the results
    display_devices(devices)

if __name__ == "__main__":
    main()