#!/usr/bin/env python3
"""Console version of sniffer"""

import argparse
import sys
from pathlib import Path

from src.packet_capture import PacketCapture
from src.pcap_encoder import PcapEncoder

ERROR_EXCEPTION = 1
ERROR_PYTHON_VERSION = 2

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
        "-c", "--count", required=True, action="store", help="count of packets to write"
    )

    parser.add_argument(
        "-o",
        "--output",
        required=True,
        type=str,
        action="store",
        help="path to the file to write",
    )

    args = parser.parse_args()

    return args


def main():
    args = parse_args()
    capture = PacketCapture()
    encoder = PcapEncoder()
    file = Path(args.output)
    count = args.count

    try:
        with open(file, "wb") as f:
            f.write(encoder.header())

            capture.start()

            for _ in range(count):
                packet = capture.next_packet()
                if not packet:
                    raise ValueError("Packet was None")
                f.write(encoder.encode(packet))

            capture.stop()

    except (FileNotFoundError, ValueError, RuntimeError) as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(ERROR_EXCEPTION)


if __name__ == "__main__":
    main()
