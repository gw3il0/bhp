#! /usr/bin/python3

import os
import socket
import struct
import threading
from ipaddress import ip_address, ip_network
from ctypes import *

# host to listen on 
host = "192.168.1.11"

# subnet to target
tgt_subnet = "192.168.1.0/24"

# magic we'll check ICMP responses for
tgt_message = "PYTH0NRUL3S!"


def udp_sender(sub_net, magic_message):
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    for ip in ip_network(sub_net).hosts():
        sender.sendto(magic_message.encode('utf-8'), (str(ip), 65212)) 


class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_uint32),
        ("dst", c_uint32)
        ]
    
    def __new__(cls, socket_buffer=None):
        return cls.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.socket_buffer = socket_buffer

        # map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        # human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("@I", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I", self.dst))

        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except IndexError:
            self.protocol = str(self.protocol_num)


class ICMP(Structure):
    _fields_ = [
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("checksum", c_ushort),
        ("unused", c_ushort),
        ("next_hop_mtu", c_ushort)
        ]

    def __new__(cls, socket_buffer):
        return cls.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        self.socket_buffer = socket_buffer


# create a raw socket and bind it to pulic interface
if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host, 0))

# include IP headers in cpature
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# if on Windows, sned some ioctl to  set up promiscuous mode
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

t = threading.Thread(target=udp_sender, args=(tgt_subnet, tgt_message))
t.start()

try:
    while True:

        # read a single packet
        raw_buffer = sniffer.recvfrom(65535)[0]

        # create an IP header from the first 20 bytes of the buffer
        ip_header = IP(raw_buffer[:20])

        print(f"Protocol: {ip_header.protocol} {ip_header.src_address} -> {ip_header.dst_address}")

        # if it's ICMP we want it
        if ip_header.protocol == "ICMP":

            # calculate where our ICMP packet starts
            offset = ip_header.ihl * 4
            buf = raw_buffer[offset:offset + sizeof(ICMP)]

            #create our ICMP structure
            icmp_header = ICMP(buf)

            print(f"ICMP -> Type: {icmp_header.type} Code: {icmp_header.code}")

            # check for TYPE 3 and CODE 3 which indicates a host is up
            # but no port available to talk to
            if icmp_header.code == 3 and icmp_header.type == 3:
                
                tgt = ip_address(ip_header.src_address)
                # check we're receiving the response that lands in our subnet
                if tgt in ip_network(tgt_subnet) and tgt != host:

                    # test for magic message
                    if raw_buffer[len(raw_buffer) - len(tgt_message):] == bytes(tgt_message, 'utf-8'):
                        print(f"Host up: {ip_header.src_address}")


# handle CTRL-C                                
except KeyboardInterrupt:
    # if on Windows turn off promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
