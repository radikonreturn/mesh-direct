from __future__ import annotations

import socket

import pytest

from direct_transfer.core.service import DirectPeerService
from direct_transfer.core.transfer import ServerState


def test_successful_bind_reports_listening(app_paths, free_port):
    service = DirectPeerService(port=free_port(), paths=app_paths("server"))
    try:
        assert service.start() is ServerState.LISTENING
        assert service.transfer.file_server.listener_family is not None
    finally:
        service.stop()


def test_occupied_port_reports_failure_and_shutdown_is_clean(app_paths, free_port):
    port = free_port()
    first = DirectPeerService(port=port, paths=app_paths("first"))
    second = DirectPeerService(port=port, paths=app_paths("second"))
    try:
        assert first.start() is ServerState.LISTENING
        assert second.start() is ServerState.FAILED
        second.stop()
        assert second.transfer.file_server.state is ServerState.FAILED
    finally:
        first.stop()


def test_ipv6_listener_when_runtime_supports_it(app_paths, free_port):
    service = DirectPeerService(port=free_port(), paths=app_paths("ipv6"))
    try:
        assert service.start() is ServerState.LISTENING
        if service.transfer.file_server.listener_family != socket.AF_INET6:
            pytest.skip("runtime fell back to an IPv4 listener")
        with socket.create_connection(("::1", service.port), timeout=1):
            pass
    finally:
        service.stop()
