import pytest
from src import packet_capture
import socket
from src.constants import TIMEOUT_MAX


class FakeSocket:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.timeout = None
        self.closed = False

    def settimeout(self, t) -> None:
        self.timeout = t

    def close(self) -> None:
        self.closed = True

    def recvfrom(self, n) -> tuple[bytes, object]:
        raise TimeoutError


def test_init():
    cap = packet_capture.PacketCapture()
    assert cap._packet_queue.empty()
    assert cap._sock is None
    assert not cap._running
    assert cap._thread is None
    assert cap._dropped == 0
    assert cap._captured == 0


def test_create_socket(monkeypatch):
    created = []

    def factory(*a, **kw):
        s = FakeSocket(*a, **kw)
        created.append(s)
        return s

    monkeypatch.setattr(packet_capture.socket, "socket", factory)

    cap = packet_capture.PacketCapture()
    sock = cap._create_socket()

    assert len(created) == 1
    fake = created[0]
    assert sock is fake
    assert fake.args == (socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))


def test_create_socket_permission_error(monkeypatch):
    def boom(*a, **kw):
        raise PermissionError

    monkeypatch.setattr(packet_capture.socket, "socket", boom)

    cap = packet_capture.PacketCapture()
    with pytest.raises(PermissionError, match="Try sudo"):
        cap._create_socket()


def test_next_packet():
    cap = packet_capture.PacketCapture()
    cap._packet_queue.put("test data")
    assert cap.next_packet(0) == "test data"
    assert cap._packet_queue.empty()
    assert cap.next_packet(0) is None


class FakeThread:
    def __init__(self, target=None, daemon=None, **kw):
        self.target = target
        self.daemon = daemon
        self.started = False
        self.joined = False
        self.join_timeout = None

    def start(self):
        self.started = True

    def join(self, timeout=None):
        self.joined = True
        self.join_timeout = timeout


def test_start_creates_socket_and_thread(monkeypatch):
    fake_sock = FakeSocket()
    created_threads = []

    def sock_factory(*a, **kw):
        return fake_sock

    def thread_factory(*a, **kw):
        t = FakeThread(*a, **kw)
        created_threads.append(t)
        return t

    monkeypatch.setattr(packet_capture.socket, "socket", sock_factory)
    monkeypatch.setattr(packet_capture.threading, "Thread", thread_factory)

    cap = packet_capture.PacketCapture()
    cap.start()

    assert cap._running is True
    assert cap._sock is fake_sock
    assert cap._thread is not None
    assert len(created_threads) == 1
    assert created_threads[0].started is True
    assert created_threads[0].daemon is True
    assert created_threads[0].target == cap._capture_packets


def test_start_is_idempotent(monkeypatch):
    fake_sock = FakeSocket()
    calls = {"sock": 0, "thread": 0}

    def sock_factory(*a, **kw):
        calls["sock"] += 1
        return fake_sock

    def thread_factory(*a, **kw):
        calls["thread"] += 1
        return FakeThread(*a, **kw)

    monkeypatch.setattr(packet_capture.socket, "socket", sock_factory)
    monkeypatch.setattr(packet_capture.threading, "Thread", thread_factory)

    cap = packet_capture.PacketCapture()
    cap.start()
    cap.start()

    assert calls["sock"] == 1
    assert calls["thread"] == 1


def test_stop_signals_thread_and_closes_socket(monkeypatch):
    fake_sock = FakeSocket()
    created_threads = []

    def thread_factory(*a, **kw):
        t = FakeThread(*a, **kw)
        created_threads.append(t)
        return t

    monkeypatch.setattr(packet_capture.socket, "socket", lambda *a, **kw: fake_sock)
    monkeypatch.setattr(packet_capture.threading, "Thread", thread_factory)

    cap = packet_capture.PacketCapture()
    cap.start()
    cap.stop()

    assert cap._running is False
    assert cap._sock is None
    assert cap._thread is None
    assert created_threads[0].joined is True
    assert fake_sock.closed is True


def test_stop_without_start_is_noop():
    cap = packet_capture.PacketCapture()
    cap.stop()

    assert cap._running is False
    assert cap._sock is None
    assert cap._thread is None


def test_stop_is_idempotent(monkeypatch):
    fake_sock = FakeSocket()

    monkeypatch.setattr(packet_capture.socket, "socket", lambda *a, **kw: fake_sock)
    monkeypatch.setattr(packet_capture.threading, "Thread", FakeThread)

    cap = packet_capture.PacketCapture()
    cap.start()
    cap.stop()
    cap.stop()

    assert cap._running is False
    assert cap._sock is None
    assert cap._thread is None
    assert fake_sock.closed is True
