from __future__ import annotations

import socket
import time
from pathlib import Path

import pytest

from direct_transfer.core.paths import AppPaths


@pytest.fixture
def app_paths(tmp_path: Path):
    def make(name: str) -> AppPaths:
        root = tmp_path / name
        return AppPaths(
            root,
            root / "identity",
            root / "trust.json",
            root / "address.json",
            root / "history.sqlite3",
            root / "partials",
            root / "received",
        )

    return make


@pytest.fixture
def free_port():
    def allocate() -> int:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

    return allocate


def wait_until(predicate, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False
