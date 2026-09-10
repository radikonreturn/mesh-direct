"""Select a useful local IPv4 address without performing peer discovery."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from dataclasses import dataclass

import psutil


@dataclass(frozen=True)
class LocalIPv4:
    interface: str
    address: str


def usable_local_ipv4_interfaces() -> list[LocalIPv4]:
    """Return UP, usable IPv4 interfaces, deduplicated by address."""
    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    found: dict[str, LocalIPv4] = {}
    for name, entries in addresses.items():
        state = stats.get(name)
        if state is not None and not state.isup:
            continue
        for entry in entries:
            if entry.family != socket.AF_INET or not _is_usable(entry.address):
                continue
            found.setdefault(entry.address, LocalIPv4(name, entry.address))
    return sorted(found.values(), key=lambda item: (item.interface, item.address))


def select_local_ipv4(
    candidates: Iterable[LocalIPv4], preferred_address: str | None = None
) -> str | None:
    """Choose the OS-routed address, then a private LAN address, then global."""
    usable = [item for item in candidates if _is_usable(item.address)]
    if (
        preferred_address
        and _is_usable(preferred_address)
        and any(item.address == preferred_address for item in usable)
    ):
        return preferred_address
    if not usable:
        return None

    def rank(item: LocalIPv4) -> tuple[int, str, str]:
        address = ipaddress.ip_address(item.address)
        return (0 if address.is_private else 1, item.interface, item.address)

    return min(usable, key=rank).address


def primary_local_ipv4() -> str | None:
    """Return a useful local address, or None when the host has none."""
    candidates = usable_local_ipv4_interfaces()
    return select_local_ipv4(candidates, _default_route_ipv4())


def _default_route_ipv4() -> str | None:
    """Ask the OS which source address it would route; no packet is sent."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))
            address = probe.getsockname()[0]
    except OSError:
        return None
    return address if _is_usable(address) else None


def _is_usable(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(
        address.version == 4
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_unspecified
    )
