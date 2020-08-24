#!/usr/bin/env python
import netfilterqueue as netq
import scapy.all as scapy

def see_packet(packet):
    use_packet = scapy.IP(packet.get_payload())
    print(use_packet.show())
    packet.accept()

queue = netq.NetfilterQueue()
queue.bind(0,see_packet)
queue.run()