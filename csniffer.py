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

ROW_TEMPLATE = "{ttl:<6}{src:<18}{dst:<18}{proto:<10}"

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
    ip_header = packet[14:34]
    unpacked = struct.unpack("!BBHHHBBH4s4s", ip_header)

    ttl = unpacked[5]
    protocol = unpacked[6]
    src_ip_bytes = unpacked[8]
    dst_ip_bytes = unpacked[9]

    src_ip = socket.inet_ntoa(src_ip_bytes)
    dst_ip = socket.inet_ntoa(dst_ip_bytes)

    proto_name = BASE_PROTOCOL_MAP.get(protocol, "UNKNOWN")

    return proto_name, src_ip, dst_ip, ttl


def main():
    args = parse_args()
    capture = PacketCapture()
    encoder = PcapEncoder()

    file = args.output
    if file:
        file = Path(file)
    count = args.count or 0
    verbose = args.verbose
    target_protocols = [proto for proto in args.proto if args.proto]

    f = None

    try:
        if file:
            f = open(file, "wb")
            f.write(encoder.header())

        capture.start()

        if verbose:
            print(f"{'TTL':<6}{'Source IP':<18}{'Destination IP':<18}{'Protocol':<10}")

        captured = 0
        while True:
            if count > 0 and captured >= count:
                break

            packet = capture.next_packet()
            if not packet:
                raise ValueError("Packet was None")

            proto, src, dst, ttl = parse_packet(packet)

            if target_protocols and proto not in target_protocols:
                continue

            if f:
                f.write(encoder.encode(packet))

            if verbose:
                print(f"{ttl:<6}{src:<18}{dst:<18}{proto:<10}")

            captured += 1

        capture.stop()
        if f:
            f.close()

    except (FileNotFoundError, ValueError, RuntimeError) as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(ERROR_EXCEPTION)

    finally:
        capture.stop()
        if f:
            f.close()


if __name__ == "__main__":
    main()
