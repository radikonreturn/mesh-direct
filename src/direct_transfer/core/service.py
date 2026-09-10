"""Application-level direct peer API; UI code never handles sockets."""

from __future__ import annotations

import socket
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from direct_transfer.core.address_book import AddressBook, AddressBookEntry
from direct_transfer.core.endpoint import Endpoint
from direct_transfer.core.history import TransferHistoryStore, TransferRecord
from direct_transfer.core.identity import DeviceIdentity
from direct_transfer.core.pairing import PairingIdentity, PairingInbox, client_pair
from direct_transfer.core.paths import AppPaths
from direct_transfer.core.session import (
    AuthenticationError,
    ProtocolError,
    client_handshake,
)
from direct_transfer.core.transfer import SecureTransfer
from direct_transfer.core.trust import TrustStatus, TrustStore
from direct_transfer.utils.config import (
    CONNECT_TIMEOUT,
    HANDSHAKE_TIMEOUT,
    TRANSFER_PORT,
)


class ConnectionState(Enum):
    IDENTITY_RECEIVED = "identity_received"
    AWAITING_TRUST = "awaiting_trust"
    AUTHENTICATED = "authenticated"
    IDENTITY_CHANGED = "identity_changed"


class DirectConnectionError(ConnectionError):
    """A safe, user-facing direct connection failure."""


@dataclass(frozen=True)
class ConnectionResult:
    endpoint: Endpoint
    resolved_ip: str
    identity: PairingIdentity
    state: ConnectionState


@dataclass(frozen=True)
class _ResolvedPeer:
    device_id: str
    public_key: str
    trust_status: TrustStatus
    hostname: str
    protocol_version: int = 3


class DirectPeerService:
    """Own identity, trust, address book, listener, transfers, inbox, and history."""

    def __init__(
        self,
        *,
        port: int = TRANSFER_PORT,
        paths: AppPaths | None = None,
        approval_timeout: float = 120.0,
    ) -> None:
        self.paths = paths or AppPaths.default()
        self.paths.ensure()
        self.identity = DeviceIdentity.load_or_create(self.paths.identity)
        self.trust_store = TrustStore(self.paths.trust)
        self.address_book = AddressBook(self.paths.address_book)
        self.history = TransferHistoryStore(self.paths.history)
        self.pairing_inbox = PairingInbox()
        self.port = port
        self._outbound_pairings: dict[str, tuple[PairingIdentity, Endpoint]] = {}
        self._resolved: dict[str, _ResolvedPeer] = {}
        self.transfer = SecureTransfer(
            transfer_port=port,
            receive_dir=str(self.paths.received),
            identity=self.identity,
            trust_store=self.trust_store,
            peer_resolver=self._resolve_peer,
            history_store=self.history,
            approval_timeout=approval_timeout,
            on_pairing=self.pairing_inbox.publish,
            partial_dir=str(self.paths.partials),
        )

    def start(self) -> None:
        self.transfer.start_server()

    def stop(self) -> None:
        self.transfer.stop_server()

    def pair(
        self,
        endpoint: Endpoint | str,
        progress: Callable[[str], None] | None = None,
    ) -> ConnectionResult:
        target = Endpoint.parse(endpoint) if isinstance(endpoint, str) else endpoint
        if progress:
            progress("Resolving")
        resolved_ip = self._resolve(target)
        if progress:
            progress("Connecting")
        try:
            with socket.create_connection(
                (resolved_ip, target.port), timeout=CONNECT_TIMEOUT
            ) as connection:
                connection.settimeout(HANDSHAKE_TIMEOUT)
                remote = client_pair(connection, self.identity, resolved_ip, self.port)
        except Exception as error:
            raise self._friendly_error(error) from error
        status = self.trust_store.assess(remote.device_id, remote.public_key)
        known_at_endpoint = self.address_book.find_endpoint(target.host, target.port)
        if (
            known_at_endpoint is not None
            and known_at_endpoint.device_id != remote.device_id
        ) or status == TrustStatus.CHANGED:
            state = ConnectionState.IDENTITY_CHANGED
        elif status == TrustStatus.TRUSTED:
            state = ConnectionState.IDENTITY_RECEIVED
        else:
            state = ConnectionState.AWAITING_TRUST
        self._outbound_pairings[remote.device_id] = (remote, target)
        if progress:
            progress("Identity received")
        self._resolved[resolved_ip] = _ResolvedPeer(
            remote.device_id, remote.public_key, status, target.host
        )
        return ConnectionResult(target, resolved_ip, remote, state)

    def connect(
        self,
        endpoint: Endpoint | str,
        progress: Callable[[str], None] | None = None,
    ) -> ConnectionResult:
        result = self.pair(endpoint, progress)
        if result.state == ConnectionState.IDENTITY_CHANGED:
            raise DirectConnectionError("Device identity changed")
        if (
            self.trust_store.assess(
                result.identity.device_id, result.identity.public_key
            )
            != TrustStatus.TRUSTED
        ):
            return result
        trusted = self.trust_store.get(result.identity.device_id)
        if trusted is None:
            return result
        try:
            with socket.create_connection(
                (result.resolved_ip, result.endpoint.port), timeout=CONNECT_TIMEOUT
            ) as connection:
                connection.settimeout(HANDSHAKE_TIMEOUT)
                client_handshake(connection, self.identity, trusted)
        except Exception as error:
            self.address_book.record_error(
                result.identity.device_id, str(self._friendly_error(error))
            )
            raise self._friendly_error(error) from error
        self.address_book.record_success(
            result.identity.device_id, result.endpoint, result.resolved_ip
        )
        if progress:
            progress("Authenticated")
        return ConnectionResult(
            result.endpoint,
            result.resolved_ip,
            result.identity,
            ConnectionState.AUTHENTICATED,
        )

    def trust(
        self, device_id: str, friendly_name: str | None = None
    ) -> AddressBookEntry:
        pairing = self._outbound_pairings.get(device_id)
        if pairing is not None:
            identity, endpoint = pairing
        else:
            identity = self.pairing_inbox.get(device_id)
            if identity is None:
                raise KeyError(device_id)
            endpoint = Endpoint(identity.peer_ip, identity.transfer_port)
        name = (friendly_name or endpoint.host)[:80]
        trusted = self.trust_store.trust(device_id, name, identity.public_key)
        entry = AddressBookEntry(
            device_id,
            name,
            trusted.fingerprint,
            trusted.public_key,
            endpoint.host,
            identity.peer_ip,
            endpoint.port,
        )
        self.address_book.put(entry)
        self.pairing_inbox.remove(device_id)
        self._resolved[identity.peer_ip] = _ResolvedPeer(
            device_id, identity.public_key, TrustStatus.TRUSTED, endpoint.host
        )
        return entry

    def forget_device(self, device_id: str) -> bool:
        removed = self.trust_store.untrust(device_id)
        self.address_book.forget(device_id)
        return removed

    def send_files(
        self,
        device_id_or_endpoint: str | Endpoint,
        paths: list[str | Path],
        message: str | None = None,
    ) -> str:
        if isinstance(device_id_or_endpoint, Endpoint):
            connected = self.connect(device_id_or_endpoint)
            if connected.state != ConnectionState.AUTHENTICATED:
                raise AuthenticationError("New device requires fingerprint approval")
            device_id = connected.identity.device_id
        elif device_id_or_endpoint.startswith("mp-"):
            device_id = device_id_or_endpoint
        else:
            connected = self.connect(Endpoint.parse(device_id_or_endpoint))
            if connected.state != ConnectionState.AUTHENTICATED:
                raise AuthenticationError("New device requires fingerprint approval")
            device_id = connected.identity.device_id
        entry = self.address_book.get(device_id)
        trusted = self.trust_store.get(device_id)
        if entry is None or trusted is None:
            raise AuthenticationError("Peer is not trusted")
        resolved_ip = self._resolve(entry.endpoint)
        self._resolved[resolved_ip] = _ResolvedPeer(
            device_id, trusted.public_key, TrustStatus.TRUSTED, entry.last_hostname
        )
        return self.transfer.send_file(
            resolved_ip,
            [str(path) for path in paths],
            message,
            port=entry.transfer_port,
        )

    def cancel_transfer(self, transfer_id: str) -> bool:
        return self.transfer.cancel_transfer(transfer_id)

    def accept_transfer(self, transfer_id: str) -> bool:
        return self.transfer.accept_request(transfer_id)

    def reject_transfer(self, transfer_id: str) -> bool:
        return self.transfer.reject_request(transfer_id)

    def get_pending_requests(self):
        return self.transfer.get_pending_requests()

    def get_history(self, limit: int = 500) -> list[TransferRecord]:
        return self.history.list_transfers(limit=limit)

    def _resolve_peer(self, peer_ip: str):
        return self._resolved.get(peer_ip)

    @staticmethod
    def _resolve(endpoint: Endpoint) -> str:
        try:
            records = socket.getaddrinfo(
                endpoint.host, endpoint.port, type=socket.SOCK_STREAM
            )
        except socket.gaierror as error:
            raise DirectConnectionError("Host not found") from error
        if not records:
            raise DirectConnectionError("Host not found")
        return records[0][4][0]

    @staticmethod
    def _friendly_error(error: Exception) -> DirectConnectionError:
        if isinstance(error, DirectConnectionError):
            return error
        if isinstance(error, socket.timeout | TimeoutError):
            return DirectConnectionError("Connection timed out")
        if isinstance(error, ConnectionRefusedError):
            return DirectConnectionError("Connection refused")
        if isinstance(error, AuthenticationError):
            return DirectConnectionError(str(error) or "Authentication failed")
        if isinstance(error, ProtocolError):
            return DirectConnectionError(
                str(error) or "Peer uses incompatible protocol"
            )
        if isinstance(error, OSError):
            return DirectConnectionError("Peer is unreachable")
        return DirectConnectionError("Connection failed")
