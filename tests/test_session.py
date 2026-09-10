import socket
import threading

import pytest

from direct_transfer.core.identity import DeviceIdentity
from direct_transfer.core.session import (
    AuthenticationError,
    client_handshake,
    server_handshake,
)
from direct_transfer.core.trust import TrustStore


def _handshake(tmp_path):
    client = DeviceIdentity.load_or_create(tmp_path / "client")
    server = DeviceIdentity.load_or_create(tmp_path / "server")
    client_store = TrustStore(tmp_path / "client-trust.json")
    server_store = TrustStore(tmp_path / "server-trust.json")
    client_peer = client_store.trust(server.device_id, "server", server.public_key)
    server_store.trust(client.device_id, "client", client.public_key)
    left, right = socket.socketpair()
    outcome = []
    thread = threading.Thread(
        target=lambda: outcome.append(server_handshake(right, server, server_store))
    )
    thread.start()
    client_session = client_handshake(left, client, client_peer)
    thread.join()
    left.close()
    right.close()
    return client_session, outcome[0]


def test_mutual_authenticated_session_and_fresh_keys(tmp_path):
    first_client, first_server = _handshake(tmp_path / "first")
    second_client, second_server = _handshake(tmp_path / "second")
    assert first_client.key == first_server.key
    assert second_client.key == second_server.key
    assert first_client.key != second_client.key


def test_untrusted_session_is_rejected(tmp_path):
    client = DeviceIdentity.load_or_create(tmp_path / "client")
    server = DeviceIdentity.load_or_create(tmp_path / "server")
    fake_client_trust = TrustStore(tmp_path / "client-trust.json")
    server_peer = fake_client_trust.trust(server.device_id, "server", server.public_key)
    left, right = socket.socketpair()
    errors = []

    def reject():
        try:
            server_handshake(right, server, TrustStore(tmp_path / "empty.json"))
        except Exception as error:
            errors.append(error)
        finally:
            right.close()

    thread = threading.Thread(target=reject)
    thread.start()
    with pytest.raises(ConnectionError):
        client_handshake(left, client, server_peer)
    thread.join()
    assert isinstance(errors[0], AuthenticationError)
    left.close()
    right.close()
