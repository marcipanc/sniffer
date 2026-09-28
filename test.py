import socket
import struct
import binascii

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

while True:
    packet, addr = s.recvfrom(65565)

    ethernet_header = packet[0:14]
    eth_header = struct.unpack("!6s6s2s", ethernet_header)

    print(
        "Destination MAC: "
        + binascii.hexlify(eth_header[0]).decode()
        + " Source MAC: "
        + binascii.hexlify(eth_header[1]).decode()
        + " Type: "
        + binascii.hexlify(eth_header[2]).decode()
    )
