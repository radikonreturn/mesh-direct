from __future__ import annotations

import socket

from direct_transfer.core.endpoint import Endpoint
from direct_transfer.core.service import DirectPeerService


class FakeSocket:
    def __init__(self, family, socket_type, protocol, attempts):
        self.family = family
        self._attempts = attempts
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        self._attempts.append((self.family, address))
        if self.family == socket.AF_INET6:
            raise OSError("unreachable")

    def close(self):
        self.closed = True


def test_first_address_failure_falls_through_to_second(monkeypatch):
    records = [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 5000, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.20", 5000)),
    ]
    attempts = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: records)
    monkeypatch.setattr(
        socket,
        "socket",
        lambda family, socket_type, protocol: FakeSocket(
            family, socket_type, protocol, attempts
        ),
    )

    connection, resolved = DirectPeerService._open_connection(
        Endpoint("peer.example", 5000)
    )

    assert resolved.ip == "192.0.2.20"
    assert connection.family == socket.AF_INET
    assert [attempt[0] for attempt in attempts] == [socket.AF_INET6, socket.AF_INET]


def test_duplicate_resolver_results_are_ignored(monkeypatch):
    duplicate = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.20", 5000))
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *args, **kwargs: [duplicate, duplicate]
    )
    assert (
        len(DirectPeerService._resolve_candidates(Endpoint("peer.example", 5000))) == 1
    )
