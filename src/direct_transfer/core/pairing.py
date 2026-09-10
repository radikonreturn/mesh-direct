"""Signed identity exchange used before protocol-v3 trust exists."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from direct_transfer.core.identity import (
    DEVICE_ID_PATTERN,
    DeviceIdentity,
    decode_public_key,
    device_id_from_public_key,
    fingerprint_from_public_key,
)
from direct_transfer.core.session import ProtocolError, _receive_json, _send_json
from direct_transfer.utils.config import PAIRING_REQUEST_TTL

PAIRING_VERSION = 1
_DOMAIN = b"direct-transfer-pairing-v1\x00"


@dataclass(frozen=True)
class PairingIdentity:
    device_id: str
    public_key: str
    fingerprint: str
    peer_ip: str
    received_at: float
    transfer_port: int


class PairingInbox:
    def __init__(
        self,
        max_pending: int = 32,
        ttl: float = PAIRING_REQUEST_TTL,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_pending <= 0:
            raise ValueError("max_pending must be positive")
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        self._max_pending = max_pending
        self._ttl = ttl
        self._clock = clock
        self._items: dict[str, tuple[PairingIdentity, float]] = {}
        self._lock = threading.RLock()

    def publish(self, identity: PairingIdentity) -> None:
        with self._lock:
            self._prune_expired_locked()
            if (
                identity.device_id not in self._items
                and len(self._items) >= self._max_pending
            ):
                raise ProtocolError("Pairing inbox is full")
            self._items[identity.device_id] = (
                identity,
                self._clock() + self._ttl,
            )

    def get(self, device_id: str) -> PairingIdentity | None:
        with self._lock:
            self._prune_expired_locked()
            entry = self._items.get(device_id)
            return entry[0] if entry is not None else None

    def all(self) -> list[PairingIdentity]:
        with self._lock:
            self._prune_expired_locked()
            return sorted(
                (entry[0] for entry in self._items.values()),
                key=lambda item: item.received_at,
                reverse=True,
            )

    def prune_expired(self) -> int:
        with self._lock:
            return self._prune_expired_locked()

    def remove(self, device_id: str) -> bool:
        with self._lock:
            return self._items.pop(device_id, None) is not None

    def reject(self, device_id: str) -> bool:
        """Dismiss a pending identity without persisting any trust decision."""
        return self.remove(device_id)

    def _prune_expired_locked(self) -> int:
        now = self._clock()
        expired = [
            device_id
            for device_id, (_, deadline) in self._items.items()
            if deadline <= now
        ]
        for device_id in expired:
            self._items.pop(device_id, None)
        return len(expired)


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _signed(value: dict) -> bytes:
    return _DOMAIN + _canonical(
        {key: item for key, item in value.items() if key != "signature"}
    )


def _hello(
    identity: DeviceIdentity,
    role: str,
    nonce: bytes,
    transfer_port: int,
    peer_hash: str | None = None,
) -> dict:
    value = {
        "type": "pair_hello",
        "version": PAIRING_VERSION,
        "role": role,
        "device_id": identity.device_id,
        "identity_key": identity.public_key,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "transfer_port": transfer_port,
    }
    if peer_hash is not None:
        value["peer_hello_hash"] = peer_hash
    value["signature"] = base64.b64encode(identity.sign(_signed(value))).decode("ascii")
    return value


def _validate(value: object, role: str) -> dict:
    if (
        not isinstance(value, dict)
        or value.get("type") != "pair_hello"
        or value.get("version") != PAIRING_VERSION
        or value.get("role") != role
    ):
        raise ProtocolError("Peer uses incompatible pairing protocol")
    device_id = value.get("device_id")
    public_key = value.get("identity_key")
    if (
        not isinstance(device_id, str)
        or not DEVICE_ID_PATTERN.fullmatch(device_id)
        or not isinstance(public_key, str)
    ):
        raise ProtocolError("Invalid pairing identity")
    try:
        key = decode_public_key(public_key)
        derived_device_id = device_id_from_public_key(public_key)
    except (ValueError, base64.binascii.Error) as error:
        raise ProtocolError("Invalid pairing identity key") from error
    if derived_device_id != device_id:
        raise ProtocolError("Pairing identity does not match public key")
    try:
        nonce = base64.b64decode(value.get("nonce", ""), validate=True)
        signature = base64.b64decode(value.get("signature", ""), validate=True)
    except (ValueError, TypeError, base64.binascii.Error) as error:
        raise ProtocolError("Invalid pairing proof") from error
    if len(nonce) != 32 or len(signature) != 64:
        raise ProtocolError("Invalid pairing proof")
    port = value.get("transfer_port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ProtocolError("Invalid pairing port")
    try:
        key.verify(signature, _signed(value))
    except InvalidSignature as error:
        raise ProtocolError("Pairing signature verification failed") from error
    return value


def _result(value: dict, peer_ip: str) -> PairingIdentity:
    public_key = value["identity_key"]
    return PairingIdentity(
        value["device_id"],
        public_key,
        fingerprint_from_public_key(public_key),
        peer_ip,
        time.time(),
        value["transfer_port"],
    )


def client_pair(
    sock, identity: DeviceIdentity, peer_ip: str, local_port: int
) -> PairingIdentity:
    hello = _hello(identity, "client", os.urandom(32), local_port)
    _send_json(sock, hello)
    response = _validate(_receive_json(sock), "server")
    if response.get("peer_hello_hash") != hashlib.sha256(_canonical(hello)).hexdigest():
        raise ProtocolError("Pairing transcript mismatch")
    return _result(response, peer_ip)


def server_pair(
    sock, identity: DeviceIdentity, peer_ip: str, hello: dict, local_port: int
) -> PairingIdentity:
    request = _validate(hello, "client")
    response = _hello(
        identity,
        "server",
        os.urandom(32),
        local_port,
        hashlib.sha256(_canonical(request)).hexdigest(),
    )
    _send_json(sock, response)
    return _result(request, peer_ip)
