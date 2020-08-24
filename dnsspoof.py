#!/usr/bin/env python
import netfilterqueue as netq

def see_packet(packet):
    print(packet)
    packet.accept()                #without this the packet is not reachable to the destination

queue = netq.NetfilterQueue()
queue.bind(0,see_packet)
queue.run()