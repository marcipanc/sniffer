from src.constants import DEFAULT_SNAPLEN
import time
import struct


class PcapEncoder:
    def __init__(self): ...

    def encode(self, packet: bytes, snaplen: int = DEFAULT_SNAPLEN) -> bytes:
        return self._packet_record(packet, snaplen) + packet[:snaplen]

    def header(self) -> bytes:
        return struct.pack(
            "<IHHIIII",
            0xA1B2C3D4,  # Magic number
            0x0002,  # Major version (will not change)
            0x0004,  # Minor version (will not change)
            0,  # Reserved
            0,  # Reserved
            DEFAULT_SNAPLEN,  # Snaplen
            1,  # Linktype and additional info
        )

    def _packet_record(self, packet: bytes, snaplen: int) -> bytes:
        ts = time.time()
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)

        if ts_usec >= 1_000_000:
            ts_sec += 1
            ts_usec -= 1_000_000

        original_len = len(packet)
        captured_len = min(original_len, snaplen)

        return struct.pack(
            "<IIII",
            ts_sec,  # Timestamp, seconds
            ts_usec,  # Timestamp, milliseconds
            captured_len,  # Length of captured packet part
            original_len,  # Length of original packet
        )
