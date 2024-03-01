#!/usr/bin/env python3

import re

from scapy.all import (
    Ether,
    IntField,
    Packet,
    StrFixedLenField,
    XByteField,
    bind_layers,
    srp1,
    sendp,
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

bind_layers(Ether, Adder, type=0x1234)

class NumParseError(Exception):
    pass

class OpParseError(Exception):
    pass

class Token:
    def __init__(self,type,value = None):
        self.type = type
        self.value = value

def receiver(pkt):
    print("number:", pkt[Adder].num, "seq_num:", pkt[Adder].seq_num)

def main():
    iface = 'eth0'

    node_type = input("Is this a sender or receiver? (s/r): ")
    if node_type == 's':
        while True:
            num = int(input("Enter a number: "))
            seq = int(input("Enter a sequence number(0~255): "))

            # send and receive ack
            try:
                pkt = Ether(dst='00:04:00:00:00:00', type=0x1234) / Adder(num=num, seq_num=seq)
                pkt = pkt/' '
                resp = srp1(pkt, iface=iface, timeout=1, verbose=False)
                if resp:
                    if resp[Adder] and resp[Adder].is_result == 0x00:
                        print("ACK received, number saved. seq_num:", resp[Adder].seq_num)
                    elif resp[Adder] and resp[Adder].is_result == 0x01:
                        print("ACK received, result added. seq_num:", resp[Adder].seq_num, "result:", resp[Adder].num)
                        resultPkt = Ether(dst='00:04:00:00:00:00', type=0x1234) / Adder(num=resp[Adder].num, seq_num=resp[Adder].seq_num, is_result=0x01)
                        resultPkt = resultPkt/' '
                        sendp(resultPkt, iface=iface, verbose=False)
                    else:
                        print("Cannot parse ACK")
                else:
                    print("ACK not received")
            except Exception as error:
                print(error)

    elif node_type == 'r':
        while True:
            try:
                sniff(iface=iface, prn=receiver, filter="ether proto 0x1234", count=1, timeout = 1)
            except Exception as error:
                print(error)


if __name__ == '__main__':
    main()
