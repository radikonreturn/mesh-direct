from __future__ import annotations

import os
import socket
import time
from types import SimpleNamespace

from conftest import wait_until

from direct_transfer.core.identity import DeviceIdentity
from direct_transfer.core.inbox import IncomingRequestManager
from direct_transfer.core.models import TransferStatus
from direct_transfer.core.protocol import (
    receive_control_frame,
    receive_data_frame,
)
from direct_transfer.core.transfer import FileClient, FileServer
from direct_transfer.core.trust import TrustStatus, TrustStore
from direct_transfer.utils.config import CHUNK_SIZE


def _trusted_engine(tmp_path, port, server_type=FileServer):
    client_identity = DeviceIdentity.load_or_create(tmp_path / "client-id")
    server_identity = DeviceIdentity.load_or_create(tmp_path / "server-id")
    client_trust = TrustStore(tmp_path / "client-trust.json")
    server_trust = TrustStore(tmp_path / "server-trust.json")
    client_trust.trust(server_identity.device_id, "server", server_identity.public_key)
    server_trust.trust(client_identity.device_id, "client", client_identity.public_key)
    holder = []

    def accept(request):
        holder[0].accept_request(request.transfer_id)

    manager = IncomingRequestManager(accept)
    holder.append(manager)
    server = server_type(
        port=port,
        receive_dir=str(tmp_path / "received"),
        identity=server_identity,
        trust_store=server_trust,
        incoming_manager=manager,
        approval_timeout=2,
    )
    peer = SimpleNamespace(
        device_id=server_identity.device_id,
        public_key=server_identity.public_key,
        trust_status=TrustStatus.TRUSTED,
        protocol_version=3,
    )
    client = FileClient(
        port=port,
        identity=client_identity,
        trust_store=client_trust,
        peer_resolver=lambda _ip: peer,
        approval_timeout=2,
    )
    return server, client


class InterruptOnceServer(FileServer):
    interrupted = False

    def _receive_v3_file_data(
        self, connection, session_key, offer, offered, partial_path, info
    ):
        if self.interrupted:
            return super()._receive_v3_file_data(
                connection, session_key, offer, offered, partial_path, info
            )
        control = receive_control_frame(connection, session_key)
        assert control["offset"] == 0
        data = receive_data_frame(connection, session_key)
        partial_path.parent.mkdir(parents=True, exist_ok=True)
        partial_path.write_bytes(data)
        info.bytes_transferred = len(data)
        self.interrupted = True
        connection.close()
        raise ConnectionResetError("simulated interruption")


class CorruptingServer(FileServer):
    def _receive_v3_file_data(
        self, connection, session_key, offer, offered, partial_path, info
    ):
        result = super()._receive_v3_file_data(
            connection, session_key, offer, offered, partial_path, info
        )
        with partial_path.open("r+b") as handle:
            handle.seek(0)
            handle.write(b"x")
        return result


def test_interrupted_transfer_retries_and_resumes(tmp_path, free_port):
    port = free_port()
    server, client = _trusted_engine(tmp_path, port, InterruptOnceServer)
    source = tmp_path / "resume.bin"
    content = os.urandom(CHUNK_SIZE * 3)
    source.write_bytes(content)
    server.start()
    time.sleep(0.05)
    try:
        client.send("127.0.0.1", str(source))
        assert wait_until(
            lambda: (
                bool(client.get_transfers())
                and client.get_transfers()[-1].status is TransferStatus.COMPLETE
            ),
            timeout=8,
        )
        info = client.get_transfers()[-1]
        assert info.retry_count == 1
        assert info.resume_offset == CHUNK_SIZE
        assert (tmp_path / "received" / source.name).read_bytes() == content
    finally:
        client.shutdown()
        server.shutdown()
        server.join(timeout=2)


def test_hash_mismatch_is_terminal_and_not_committed(tmp_path, free_port):
    port = free_port()
    server, client = _trusted_engine(tmp_path, port, CorruptingServer)
    source = tmp_path / "corrupt.bin"
    source.write_bytes(b"correct data")
    server.start()
    time.sleep(0.05)
    try:
        client.send("127.0.0.1", str(source))
        assert wait_until(
            lambda: (
                bool(client.get_transfers())
                and client.get_transfers()[-1].status is TransferStatus.FAILED
            )
        )
        assert client.get_transfers()[-1].retry_count == 0
        assert not (tmp_path / "received" / source.name).exists()
    finally:
        client.shutdown()
        server.shutdown()
        server.join(timeout=2)


def test_malformed_unauthenticated_client_is_closed(app_paths, free_port):
    from direct_transfer.core.service import DirectPeerService

    service = DirectPeerService(port=free_port(), paths=app_paths("server"))
    service.start()
    time.sleep(0.05)
    try:
        with socket.create_connection(("127.0.0.1", service.port), timeout=1) as sock:
            sock.sendall((2).to_bytes(4, "big") + b"{}")
            sock.settimeout(2)
            assert sock.recv(1) == b""
        assert service.transfer.get_transfers() == []
    finally:
        service.stop()


def test_server_bounds_concurrent_unauthenticated_connections(app_paths, free_port):
    from direct_transfer.core.service import DirectPeerService
    from direct_transfer.utils.config import MAX_CONCURRENT_TRANSFER_SESSIONS

    service = DirectPeerService(port=free_port(), paths=app_paths("server"))
    service.start()
    time.sleep(0.05)
    sockets = []
    try:
        for _ in range(MAX_CONCURRENT_TRANSFER_SESSIONS + 3):
            sockets.append(socket.create_connection(("127.0.0.1", service.port)))
        assert wait_until(
            lambda: (
                service.transfer.file_server.active_session_count
                == MAX_CONCURRENT_TRANSFER_SESSIONS
            )
        )
        assert (
            service.transfer.file_server.active_session_count
            <= MAX_CONCURRENT_TRANSFER_SESSIONS
        )
    finally:
        for sock in sockets:
            sock.close()
        service.stop()


def test_clean_shutdown_releases_port(app_paths, free_port):
    from direct_transfer.core.service import DirectPeerService

    port = free_port()
    service = DirectPeerService(port=port, paths=app_paths("server"))
    service.start()
    time.sleep(0.05)
    service.stop()
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("127.0.0.1", port))
