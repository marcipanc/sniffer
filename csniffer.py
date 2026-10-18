#!/usr/bin/env python3
"""Console version of sniffer"""

import argparse
import socket
import struct
import sys
from pathlib import Path

from src.packet_capture import PacketCapture
from src.pcap_encoder import PcapEncoder

ERROR_EXCEPTION = 1
ERROR_PYTHON_VERSION = 2

ROW_TEMPLATE = (
    "{ttl:<6}{src_ip:<18}{src_mac:<20}{src_port:<12}"
    "{dst_ip:<18}{dst_mac:<20}{dst_port:<12}{proto:<10}"
)

if sys.version_info < (3, 12):
    print("Use python >= 3.12", file=sys.stderr)
    sys.exit(ERROR_PYTHON_VERSION)

__version__ = "0.1"
__author__ = "Dima Borisov"
__email__ = "dim4ig2007@gmail.com"


def parse_args():
    parser = argparse.ArgumentParser(
        prog="csniffer",
        description="Captures and writes network traffic to file in pcap format",
        epilog=f"Author: {__author__} <{__email__}>",
    )

    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="show detailed information and traffic in console",
    )

    parser.add_argument(
        "-c", "--count", action="store", type=int, help="count of packets to write"
    )

    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="path to the file to write",
    )

    parser.add_argument(
        "--proto",
        type=lambda s: s.upper(),
        nargs="+",
        help="filter packets by protocols (e.g --proto tcp, udp, icmp)",
    )

    args = parser.parse_args()

    if not args.verbose and not args.output:
        parser.error(
            "specify at least one of these flags: -v (--verbose) or -o (--output)"
        )

    return args


BASE_PROTOCOL_MAP = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
}


def parse_packet(packet: bytes):
    ethernet_header = packet[:14]
    dest_mac = ":".join(f"{b:02x}" for b in ethernet_header[:6])
    source_mac = ":".join(f"{b:02x}" for b in ethernet_header[6:12])

    ip_header = packet[14:34]
    unpacked = struct.unpack("!BBHHHBBH4s4s", ip_header)

    ttl = unpacked[5]
    protocol = unpacked[6]
    src_ip_bytes = unpacked[8]
    dst_ip_bytes = unpacked[9]

    src_ip = socket.inet_ntoa(src_ip_bytes)
    dst_ip = socket.inet_ntoa(dst_ip_bytes)

    header_length = (0x0F & ip_header[0]) * 4

    transport_offset = 14 + header_length
    transport = packet[transport_offset:]
    if protocol in (6, 17):  # TCP, UDP
        source_port = int.from_bytes(transport[:2], "big")
        dest_port = int.from_bytes(transport[2:4], "big")
    else:
        source_port = dest_port = 0

    proto_name = BASE_PROTOCOL_MAP.get(protocol, "UNKNOWN")

    return proto_name, src_ip, source_mac, source_port, dst_ip, dest_mac, dest_port, ttl


def proceed_capturing(count, capture, encoder, target_protocols, file, verbose):
    captured = 0
    while True:
        if count > 0 and captured >= count:
            break

        packet = capture.next_packet()
        if not packet:
            raise ValueError("Packet was None")

        proto, src_ip, src_mac, src_port, dst_ip, dst_mac, dst_port, ttl = parse_packet(
            packet
        )

        clean_target_protocols = [p.replace(",", "") for p in target_protocols]
        if clean_target_protocols and proto not in clean_target_protocols:
            continue

        if file:
            file.write(encoder.encode(packet))

        if verbose:
            print(
                ROW_TEMPLATE.format(
                    ttl=ttl,
                    src_ip=src_ip,
                    src_mac=src_mac,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_mac=dst_mac,
                    dst_port=dst_port,
                    proto=proto,
                )
            )

        captured += 1


def main():
    args = parse_args()
    capture = PacketCapture()
    encoder = PcapEncoder()

    file = args.output
    if file:
        file = Path(file)
    count = args.count or 0
    verbose = args.verbose
    target_protocols = list(args.proto) if args.proto else []

    f = None

    try:
        if file:
            f = open(file, "wb")
            f.write(encoder.header())

        capture.start()

        if verbose:
            print(
                ROW_TEMPLATE.format(
                    ttl="TTL",
                    src_ip="Source IP",
                    src_mac="Source MAC",
                    src_port="Src Port",
                    dst_ip="Dest IP",
                    dst_mac="Dest MAC",
                    dst_port="Dst Port",
                    proto="Protocol",
                )
            )

        proceed_capturing(count, capture, encoder, target_protocols, f, verbose)

    except KeyboardInterrupt:
        pass

    except (FileNotFoundError, ValueError, RuntimeError) as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(ERROR_EXCEPTION)

    finally:
        capture.stop()
        if f:
            f.close()


if __name__ == "__main__":
    main()
