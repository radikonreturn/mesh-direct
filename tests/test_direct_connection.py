from __future__ import annotations

import socket
import time

import pytest
from conftest import wait_until

from direct_transfer.core.endpoint import Endpoint
from direct_transfer.core.service import (
    ConnectionState,
    DirectConnectionError,
    DirectPeerService,
)


def _start_pair(app_paths, free_port, approval_timeout=2.0):
    left = DirectPeerService(
        port=free_port(), paths=app_paths("left"), approval_timeout=approval_timeout
    )
    right = DirectPeerService(
        port=free_port(), paths=app_paths("right"), approval_timeout=approval_timeout
    )
    left.start()
    right.start()
    assert wait_until(lambda: left.transfer.file_server.is_alive())
    assert wait_until(lambda: right.transfer.file_server.is_alive())
    time.sleep(0.05)
    return left, right


def _pair_and_trust(left, right):
    right_result = left.pair(Endpoint("127.0.0.1", right.port))
    left_result = right.pair(Endpoint("127.0.0.1", left.port))
    assert right_result.state is ConnectionState.AWAITING_TRUST
    assert left_result.state is ConnectionState.AWAITING_TRUST
    left.trust(right_result.identity.device_id, "right")
    right.trust(left_result.identity.device_id, "left")
    return left_result.identity.device_id, right_result.identity.device_id


def test_loopback_pair_trust_and_authenticated_reconnect(app_paths, free_port):
    left, right = _start_pair(app_paths, free_port)
    try:
        _, right_id = _pair_and_trust(left, right)
        connected = left.connect(Endpoint("127.0.0.1", right.port))
        assert connected.state is ConnectionState.AUTHENTICATED
        assert connected.identity.device_id == right_id
    finally:
        left.stop()
        right.stop()


def test_same_identity_at_new_endpoint_stays_trusted(app_paths, free_port):
    left, right = _start_pair(app_paths, free_port)
    try:
        _, right_id = _pair_and_trust(left, right)
        result = left.connect(Endpoint("localhost", right.port))
        assert result.state is ConnectionState.AUTHENTICATED
        assert result.identity.device_id == right_id
    finally:
        left.stop()
        right.stop()


def test_endpoint_identity_change_is_terminal(app_paths, free_port):
    client, first = _start_pair(app_paths, free_port)
    endpoint = Endpoint("127.0.0.1", first.port)
    try:
        result = client.pair(endpoint)
        client.trust(result.identity.device_id, "server")
    finally:
        first.stop()
    replacement = DirectPeerService(port=first.port, paths=app_paths("replacement"))
    replacement.start()
    time.sleep(0.05)
    try:
        with pytest.raises(DirectConnectionError, match="identity changed"):
            client.connect(endpoint)
    finally:
        client.stop()
        replacement.stop()


def test_connection_refused(app_paths, free_port):
    service = DirectPeerService(port=free_port(), paths=app_paths("client"))
    with pytest.raises(DirectConnectionError, match="Connection refused"):
        service.pair(Endpoint("127.0.0.1", free_port()))


def test_resolution_failure(app_paths, free_port, monkeypatch):
    service = DirectPeerService(port=free_port(), paths=app_paths("client"))
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: (_ for _ in ()).throw(socket.gaierror()),
    )
    with pytest.raises(DirectConnectionError, match="Host not found"):
        service.pair("missing.invalid")


def test_timeout_has_clear_error(app_paths, free_port, monkeypatch):
    service = DirectPeerService(port=free_port(), paths=app_paths("client"))
    monkeypatch.setattr(service, "_resolve", lambda endpoint: "192.0.2.1")
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError()),
    )
    with pytest.raises(DirectConnectionError, match="timed out"):
        service.pair("example.test")


def test_protocol_mismatch(app_paths, free_port):
    port = free_port()
    listener = socket.socket()
    listener.bind(("127.0.0.1", port))
    listener.listen()

    def incompatible():
        connection, _ = listener.accept()
        connection.sendall((2).to_bytes(4, "big") + b"{}")
        connection.close()
        listener.close()

    import threading

    threading.Thread(target=incompatible, daemon=True).start()
    service = DirectPeerService(port=free_port(), paths=app_paths("client"))
    with pytest.raises(DirectConnectionError, match="incompatible pairing protocol"):
        service.pair(Endpoint("127.0.0.1", port))
