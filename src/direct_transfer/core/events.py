"""Lightweight application event boundary for core worker notifications."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass

from direct_transfer.core.inbox import IncomingTransferRequest
from direct_transfer.core.models import TransferInfo
from direct_transfer.core.pairing import PairingIdentity
from direct_transfer.utils.logger import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class IncomingTransferOffered:
    request: IncomingTransferRequest


@dataclass(frozen=True)
class TransferUpdated:
    transfers: tuple[TransferInfo, ...]


@dataclass(frozen=True)
class TransferCompleted:
    transfer: TransferInfo


@dataclass(frozen=True)
class TransferFailed:
    transfer: TransferInfo


@dataclass(frozen=True)
class PairingOffered:
    identity: PairingIdentity


@dataclass(frozen=True)
class PeerStateChanged:
    device_id: str


TransferEvent = (
    IncomingTransferOffered | TransferUpdated | TransferCompleted | TransferFailed
)


CoreEvent = (
    IncomingTransferOffered
    | TransferUpdated
    | TransferCompleted
    | TransferFailed
    | PairingOffered
    | PeerStateChanged
)


class EventPublisher:
    """Thread-safe in-process publisher; subscribers choose thread dispatch."""

    def __init__(self) -> None:
        self._subscribers: list[Callable[[CoreEvent], None]] = []
        self._lock = threading.RLock()

    def subscribe(self, callback: Callable[[CoreEvent], None]) -> None:
        with self._lock:
            if callback not in self._subscribers:
                self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[CoreEvent], None]) -> None:
        with self._lock:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

    def publish(self, event: CoreEvent) -> None:
        with self._lock:
            subscribers = tuple(self._subscribers)
        for callback in subscribers:
            try:
                callback(event)
            # A UI/callback failure must never abort a network worker. This is the
            # top-level defensive boundary between independent subscribers.
            except Exception as error:  # noqa: BLE001
                log.error("Transfer event subscriber failed: %s", error)
