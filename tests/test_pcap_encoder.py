import time
import struct
import pytest
from src.pcap_encoder import PcapEncoder
from src.constants import DEFAULT_SNAPLEN


def test_header():
    encoder = PcapEncoder()
    header = encoder.header()

    assert len(header) == 24
    assert header[:4] == b"\xd4\xc3\xb2\xa1"

    magic, major, minor, r1, r2, snaplen, linktype = struct.unpack("<IHHIIII", header)
    assert magic == 0xA1B2C3D4
    assert major == 2
    assert minor == 4
    assert r1 == 0
    assert r2 == 0
    assert snaplen == DEFAULT_SNAPLEN
    assert linktype == 1


def test_packet_record():
    packet = b"\x00" * 100

    before = time.time()
    record = PcapEncoder()._packet_record(packet, DEFAULT_SNAPLEN)
    after = time.time()

    assert len(record) == 16

    ts_sec, ts_usec, captured_len, original_len = struct.unpack("<IIII", record)

    assert int(before) <= ts_sec <= int(after)
    assert 0 <= ts_usec < 1_000_000

    assert captured_len == 100
    assert original_len == 100


def test_packet_record_truncates():
    packet = b"\x00" * 100
    record = PcapEncoder()._packet_record(packet, snaplen=50)

    _, _, captured_len, original_len = struct.unpack("<IIII", record)
    assert captured_len == 50
    assert original_len == 100


def test_encode():
    packet = b"\xaa" * 100
    encoded = PcapEncoder().encode(packet, snaplen=50)

    assert len(encoded) == 16 + 50

    _, _, captured_len, original_len = struct.unpack("<IIII", encoded[:16])
    assert (captured_len, original_len) == (50, 100)

    assert encoded[16:] == packet[:50]
