#!/usr/bin/env python3

import re

from scapy.all import (
    IntField,
    Packet,
    StrFixedLenField,
    XByteField,
    Ether,
    IP,
    UDP,
    send,
    sniff
)


class Adder(Packet):
    name = "adder"
    fields_desc = [ StrFixedLenField("A", "A", length=1),
                    StrFixedLenField("D", "D", length=1),
                    XByteField("ver_maj", 0x00),
                    XByteField("ver_min", 0x01),
                    XByteField("seq_num", 0x00),
                    XByteField("is_result", 0x00),
                    IntField("num", 0x00) ]

class AdderSender:
    def __init__(self, dest_ip, dest_port = 1234, src_port = 1234, dest_mac = '08:00:00:00:01:03'):
        self.src_port = src_port
        self.dest_mac = dest_mac
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.seq_num = 0
    def send(self, num, seq_num = -1):
        if seq_num == -1:
            seq_num = self.seq_num
            self.seq_num += 1

        pkt = (
            IP(dst=self.dest_ip) / 
            UDP(sport = self.src_port, dport=self.dest_port) / 
            Adder(
                A='A', D='D', ver_maj=0x00, ver_min=0x01, 
                seq_num=seq_num, is_result=0x00, num=num
            )
        )

        send(pkt)

class AdderReceiver:
    def __init__(self):
        self.filter = 'udp port 1234'

    def handle_pkt(self, pkt):
        if pkt.haslayer(Adder):
            print("Received packet:")
            print("    num: ", pkt[Adder].num)
            print("    seq_num: ", pkt[Adder].seq_num)


    def receive(self):
        sniff(filter=self.filter, prn=self.handle_pkt)

def main():
    iface = 'eth0'

    node_type = input("Is this a sender or receiver? (s/r): ")
    if node_type == 's':
        sender = AdderSender(
            dest_ip = '10.0.1.3',
            dest_port = 1234
        )
        while True:
            num = input("Enter a number to send: ")
            try:
                num = int(num)
            except ValueError:
                print("Invalid number")
                continue
            sender.send(num)

    elif node_type == 'r':
        receiver = AdderReceiver()
        while True:
            receiver.receive()

if __name__ == '__main__':
    main()
