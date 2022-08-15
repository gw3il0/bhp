#! /usr/bin/python3

from header_parser_ctypes import IP
import os
import socket
import struct

# host to listen on
HOST = "192.168.1.11"

def main():
    # create a raw socket, bind to public interface
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0 ))

    # include IP header in output
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    
    headers, ip = sniffer.recvfrom(65565)

    headers = IP(headers)

    # read one packet
    print(f"src:{str(headers.src_address)},dest:{str(headers.dst_address)}")

    # if on Windows, turn off promiscuous mode
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == '__main__':
    main()
