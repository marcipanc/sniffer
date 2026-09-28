import socket
import queue
import threading
from src.constants import MAX_QUEUE_SIZE, TIMEOUT_MAX, PACKET_SIZE


class PacketCapture:
    """Capture raw Ethernet packets.

    Runs a background thread that reads from an AF_PACKET socket
    and pushes packets into an internal queue. Use `start()` / `stop()`
    to control capture and 'next_packet()' to consume packets.

    Attributes:
        _packet_queue: FIFO of captured packets as `bytes`
        _sock: Raw capture socket, may be `None` if not `_running`
        _running: `True` when capture thread is started, `False` otherwise
        _thread: Capture worker thread, may be `None` if not `_running`
        _dropped: Number of dropped packets due to full queue
        _captured: Number of successfully captured packets
    """

    def __init__(self):
        self._packet_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self._sock: socket.socket | None = None
        self._running = False
        self._thread = None
        self._dropped = 0
        self._captured = 0

    def _create_socket(self) -> socket.socket:
        """Open a raw AF_PACKET socket and set is as 'self._sock'."""
        try:
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)
            )
            sock.settimeout(TIMEOUT_MAX)
            return sock
        except PermissionError:
            raise PermissionError("Try sudo to use this program")

    def _capture_packets(self) -> None:
        """Read raw Ethernet packets from the socket and enque them."""
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
        """Start packet capture in a background daemon thread."""
        if self._running:
            return
        self._sock = self._create_socket()
        self._running = True
        self._thread = threading.Thread(target=self._capture_packets, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Signal the capture thread to stop."""
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
        """Pop the oldest packet in the queue"""
        try:
            return self._packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None
