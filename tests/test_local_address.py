from __future__ import annotations

from direct_transfer.core.local_address import LocalIPv4, select_local_ipv4


def test_loopback_and_link_local_are_excluded():
    candidates = [
        LocalIPv4("loop", "127.0.0.1"),
        LocalIPv4("link", "169.254.10.4"),
    ]
    assert select_local_ipv4(candidates) is None


def test_valid_lan_ipv4_is_preferred_over_public_address():
    candidates = [
        LocalIPv4("public", "8.8.8.8"),
        LocalIPv4("lan", "192.168.1.24"),
    ]
    assert select_local_ipv4(candidates) == "192.168.1.24"


def test_default_route_address_wins_without_interface_name_assumptions():
    candidates = [
        LocalIPv4("virtual-a", "172.20.0.1"),
        LocalIPv4("adapter-b", "10.0.0.15"),
    ]
    assert select_local_ipv4(candidates, "10.0.0.15") == "10.0.0.15"


def test_no_usable_address_returns_none():
    assert select_local_ipv4([]) is None
