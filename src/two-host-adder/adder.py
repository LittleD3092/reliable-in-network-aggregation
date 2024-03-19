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
    sendp,
    sniff,
    bind_layers
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
            Ether(dst=self.dest_mac, type = 0x0800) /
            IP(dst=self.dest_ip) / 
            UDP(sport = self.src_port, dport=self.dest_port) / 
            Adder(
                A='A', D='D', ver_maj=0x00, ver_min=0x01, 
                seq_num=seq_num, is_result=0x00, num=num
            )
        )

        sendp(pkt, iface="eth0")

class AdderReceiver:
    def __init__(self):
        self.filter = 'port 1234'

    def handle_pkt(self, pkt):
        if pkt.haslayer(Adder):
            print("Received packet:")
            print("    num: ", pkt[Adder].num)
            print("    seq_num: ", pkt[Adder].seq_num)
        else:
            print("Received non-Adder packet")
            pkt.show()


    def receive(self):
        sniff(filter=self.filter, prn=self.handle_pkt, iface="eth0")

def parse_num(num):
    if num[0] == '[' and num[-1] == ']':
        num = num[1:-1]
        if ',' in num:
            return [int(x) for x in num.split(',')]
        elif ' ' in num:
            return [int(x) for x in num.split(' ')]
        elif ':' in num:
            arr = num.split(':')
            if len(arr) == 2:
                return list(range(int(arr[0]), int(arr[1])))
            elif len(arr) == 3:
                return list(range(int(arr[0]), int(arr[1]), int(arr[2])))
        else:
            return [int(num)]
    else:
        return [int(num)]

def main():
    bind_layers(UDP, Adder, dport=1234)
    node_type = input("Is this a sender or receiver? (s/r): ")
    if node_type == 's':
        sender = AdderSender(
            dest_ip = '10.0.1.3',
            dest_port = 1234
        )
        while True:
            num = input("Enter a number (numbers) to send: ")
            parsed_nums = parse_num(num)
            for i in parsed_nums:
                sender.send(i)

    elif node_type == 'r':
        receiver = AdderReceiver()
        while True:
            receiver.receive()

if __name__ == '__main__':
    main()
