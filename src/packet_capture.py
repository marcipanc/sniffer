import socket
import queue
import threading
from constants import MAX_QUEUE_SIZE, TIMEOUT_MAX, PACKET_SIZE


class PacketCapture:
    def __init__(self):
        self._packet_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self._sock: socket.socket | None = None
        self._running = False
        self._thread = None
        self._dropped = 0
        self._captured = 0

    def _create_socket(self) -> socket.socket:
        try:
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)
            )
            sock.settimeout(TIMEOUT_MAX)
            return sock
        except PermissionError:
            raise PermissionError("Try sudo to use this program")

    def _capture_packets(self) -> None:
        if not self._sock:
            raise ValueError("Socket was None")
        while self._running:
            try:
                packet, _ = self._sock.recvfrom(PACKET_SIZE)

            except TimeoutError:
                continue  # Awake and check flag

            except OSError as e:
                if self._running:
                    print(f"capture error: {e}")
                break

            try:
                self._packet_queue.put_nowait(packet)
                self._captured += 1
            except queue.Full:
                self._dropped += 1

    def start(self) -> None:
        if self._running:
            return
        self._sock = self._create_socket()
        self._running = True
        self._thread = threading.Thread(target=self._capture_packets, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
        if self._sock:
            self._sock.close()
            self._sock = None

    def next_packet(self, timeout: float | None = None) -> bytes | None:
        try:
            return self._packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None
