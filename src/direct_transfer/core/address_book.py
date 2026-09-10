"""Persistent address book keyed by cryptographic device identity."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from direct_transfer.core.endpoint import Endpoint
from direct_transfer.core.identity import (
    DEVICE_ID_PATTERN,
    device_id_from_public_key,
    fingerprint_from_public_key,
)


@dataclass(frozen=True)
class AddressBookEntry:
    device_id: str
    friendly_name: str
    fingerprint: str
    public_key: str
    last_hostname: str
    last_resolved_ip: str | None
    transfer_port: int
    last_successful_connection: float | None = None
    last_connection_error: str | None = None

    @property
    def endpoint(self) -> Endpoint:
        return Endpoint(self.last_hostname, self.transfer_port)


class AddressBook:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        self._entries: dict[str, AddressBookEntry] = {}
        self._load()

    def all(self) -> list[AddressBookEntry]:
        with self._lock:
            return sorted(
                self._entries.values(), key=lambda item: item.friendly_name.casefold()
            )

    def get(self, device_id: str) -> AddressBookEntry | None:
        with self._lock:
            return self._entries.get(device_id)

    def find_endpoint(self, host: str, port: int) -> AddressBookEntry | None:
        with self._lock:
            return next(
                (
                    item
                    for item in self._entries.values()
                    if item.last_hostname == host and item.transfer_port == port
                ),
                None,
            )

    def put(self, entry: AddressBookEntry) -> None:
        if (
            not DEVICE_ID_PATTERN.fullmatch(entry.device_id)
            or device_id_from_public_key(entry.public_key) != entry.device_id
            or fingerprint_from_public_key(entry.public_key) != entry.fingerprint
        ):
            raise ValueError("Invalid device ID")
        Endpoint(entry.last_hostname, entry.transfer_port)
        if not entry.friendly_name or len(entry.friendly_name) > 80:
            raise ValueError("Invalid friendly name")
        with self._lock:
            self._entries[entry.device_id] = entry
            self._save()

    def record_success(
        self, device_id: str, endpoint: Endpoint, resolved_ip: str
    ) -> None:
        with self._lock:
            current = self._entries[device_id]
            self._entries[device_id] = replace(
                current,
                last_hostname=endpoint.host,
                transfer_port=endpoint.port,
                last_resolved_ip=resolved_ip,
                last_successful_connection=time.time(),
                last_connection_error=None,
            )
            self._save()

    def record_error(self, device_id: str, message: str) -> None:
        with self._lock:
            current = self._entries.get(device_id)
            if current is not None:
                self._entries[device_id] = replace(
                    current, last_connection_error=message[:512]
                )
                self._save()

    def forget(self, device_id: str) -> bool:
        with self._lock:
            existed = self._entries.pop(device_id, None) is not None
            if existed:
                self._save()
            return existed

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            records = raw.get("devices", {})
            if not isinstance(records, dict):
                return
            for key, value in records.items():
                entry = AddressBookEntry(**value)
                if (
                    key == entry.device_id
                    and device_id_from_public_key(entry.public_key) == entry.device_id
                    and fingerprint_from_public_key(entry.public_key)
                    == entry.fingerprint
                ):
                    Endpoint(entry.last_hostname, entry.transfer_port)
                    self._entries[key] = entry
        except (
            FileNotFoundError,
            OSError,
            ValueError,
            TypeError,
            json.JSONDecodeError,
        ):
            self._entries = {}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = (
            json.dumps(
                {
                    "version": 1,
                    "devices": {
                        key: asdict(value)
                        for key, value in sorted(self._entries.items())
                    },
                },
                indent=2,
                sort_keys=True,
            ).encode()
            + b"\n"
        )
        descriptor, name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", dir=self.path.parent
        )
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        except OSError:
            temporary.unlink(missing_ok=True)
            raise
