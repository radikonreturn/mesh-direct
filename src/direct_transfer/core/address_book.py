"""Persistent address book keyed by cryptographic device identity."""

from __future__ import annotations

import base64
import ipaddress
import json
import math
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
from direct_transfer.utils.logger import get_logger

log = get_logger(__name__)


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
        self._validate_entry(entry)
        with self._lock:
            self._entries[entry.device_id] = entry
            self._save()

    @staticmethod
    def _validate_entry(entry: AddressBookEntry) -> None:
        try:
            valid_identity = (
                isinstance(entry.device_id, str)
                and DEVICE_ID_PATTERN.fullmatch(entry.device_id) is not None
                and device_id_from_public_key(entry.public_key) == entry.device_id
                and fingerprint_from_public_key(entry.public_key) == entry.fingerprint
            )
        except (TypeError, ValueError, base64.binascii.Error):
            valid_identity = False
        if not valid_identity:
            raise ValueError("Invalid cryptographic identity")
        Endpoint(entry.last_hostname, entry.transfer_port)
        if (
            not isinstance(entry.friendly_name, str)
            or not entry.friendly_name
            or entry.friendly_name != entry.friendly_name.strip()
            or len(entry.friendly_name) > 80
            or not entry.friendly_name.isprintable()
        ):
            raise ValueError("Invalid friendly name")
        if entry.last_resolved_ip is not None:
            if not isinstance(entry.last_resolved_ip, str):
                raise ValueError("Invalid resolved address")
            ipaddress.ip_address(entry.last_resolved_ip)
        timestamp = entry.last_successful_connection
        if timestamp is not None and (
            isinstance(timestamp, bool)
            or not isinstance(timestamp, (int, float))
            or not math.isfinite(float(timestamp))
            or timestamp < 0
        ):
            raise ValueError("Invalid connection timestamp")
        error = entry.last_connection_error
        if error is not None and (
            not isinstance(error, str) or len(error) > 512 or not error.isprintable()
        ):
            raise ValueError("Invalid connection error")

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
            if not isinstance(raw, dict):
                raise TypeError("address book must be an object")
            records = raw.get("devices", {})
            if not isinstance(records, dict):
                raise TypeError("devices must be an object")
        except FileNotFoundError:
            return
        except (OSError, TypeError, json.JSONDecodeError) as error:
            log.warning("Ignoring invalid address book %s: %s", self.path, error)
            self._entries = {}
            return

        loaded: dict[str, AddressBookEntry] = {}
        for key, value in records.items():
            try:
                if not isinstance(value, dict):
                    raise TypeError("record must be an object")
                entry = AddressBookEntry(**value)
                if key != entry.device_id:
                    raise ValueError("record key does not match device ID")
                self._validate_entry(entry)
            except (
                TypeError,
                ValueError,
                base64.binascii.Error,
            ) as error:
                log.warning(
                    "Skipping invalid address record %s: %s", str(key)[:24], error
                )
                continue
            loaded[key] = entry
        self._entries = loaded

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
