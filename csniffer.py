#!/usr/bin/env python3
"""Console version of sniffer"""

import argparse
import shutil
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
        prog="sniffer",
        description="Captures and writes network traffic to file in pcap format",
        epilog=f"Author: {__author__} <{__email__}>",
    )

    group = parser.add_mutually_exclusive_group(required=True)

    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="verbose",
        help="show detailed information and traffic in console",
    )

    group.add_argument(
        "-c", "--count", action="store_true", help="count of packets to write"
    )

    parser.add_argument("PATH", type=str, help="path to the file to write")

    return parser.parse_args()


def main():
    args = parse_args()
    capture = PacketCapture()
    encoder = PcapEncoder()
    path_to_file = Path(args.PATH)

    try:
        ...

    except (FileNotFoundError, ValueError, RuntimeError) as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(ERROR_EXCEPTION)
