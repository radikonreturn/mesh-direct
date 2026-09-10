from __future__ import annotations

import asyncio
import threading
import time
from types import SimpleNamespace

from textual.widgets import DataTable

from direct_transfer.core.events import (
    EventPublisher,
    IncomingTransferOffered,
    PairingOffered,
)
from direct_transfer.core.inbox import IncomingFile, IncomingTransferRequest
from direct_transfer.core.pairing import PairingIdentity, PairingInbox
from direct_transfer.core.transfer import ServerState
from direct_transfer.tui.dashboard import DirectTransferApp
from direct_transfer.tui.screens import InboxScreen, TrustedScreen


class FakeService:
    def __init__(self):
        self.started = False
        self.local_ipv4 = "192.168.1.24"
        self.port = 5000
        self.events = EventPublisher()
        self.address_book = SimpleNamespace(all=lambda: [])
        self.transfer = SimpleNamespace(get_transfers=lambda: [])
        self.pairing_inbox = PairingInbox()
        self.trust_store = SimpleNamespace(get=lambda device_id: None)
        self.pending = []
        self.dismissed = []

    def start(self):
        self.started = True
        return ServerState.LISTENING

    def stop(self):
        self.started = False

    def get_pending_requests(self):
        return list(self.pending)

    def dismiss_pairing(self, device_id):
        self.dismissed.append(device_id)
        return self.pairing_inbox.reject(device_id)

    def accept_transfer(self, transfer_id):
        return False

    def reject_transfer(self, transfer_id):
        return False


def test_dashboard_is_keyboard_first_and_has_core_tables():
    asyncio.run(_exercise_dashboard())


async def _exercise_dashboard():
    service = FakeService()
    app = DirectTransferApp(service)
    async with app.run_test(size=(100, 32)) as pilot:
        assert service.started
        assert len(app.query_one("#peers", DataTable).columns) == 4
        assert len(app.query_one("#transfers", DataTable).columns) == 5
        assert "LOCAL 192.168.1.24:5000" in str(
            app.query_one("#local-address").render()
        )
        await pilot.press("c")
        assert app.screen.query_one("#address")
        await pilot.press("escape")


def _request() -> IncomingTransferRequest:
    return IncomingTransferRequest(
        "a" * 32,
        "mp-12345678",
        "192.168.1.30",
        "laptop-dev",
        (
            IncomingFile("file-1", "one.bin", 1024, "0" * 64),
            IncomingFile("file-2", "two.bin", 2048, "1" * 64),
        ),
        3072,
        None,
        time.time(),
    )


def test_incoming_offer_notifies_and_refreshes_open_inbox():
    asyncio.run(_exercise_incoming_offer())


async def _exercise_incoming_offer():
    service = FakeService()
    app = DirectTransferApp(service)
    notifications = []
    async with app.run_test(size=(100, 32)) as pilot:
        app.notify = lambda message, **kwargs: notifications.append(message)
        app.push_screen(InboxScreen())
        await pilot.pause()
        request = _request()
        service.pending.append(request)
        worker = threading.Thread(
            target=service.events.publish,
            args=(IncomingTransferOffered(request),),
        )
        worker.start()
        await pilot.pause()
        worker.join(timeout=1)
        assert not worker.is_alive()
        assert "Incoming transfer from laptop-dev" in notifications[0]
        assert app.screen.query_one("#inbox-table", DataTable).row_count == 1


def test_pending_pairing_refreshes_and_can_be_dismissed():
    asyncio.run(_exercise_pending_pairing())


async def _exercise_pending_pairing():
    service = FakeService()
    app = DirectTransferApp(service)
    identity = PairingIdentity(
        "mp-12345678", "key", "fingerprint", "192.168.1.31", time.time(), 5000
    )
    async with app.run_test(size=(100, 32)) as pilot:
        app.push_screen(TrustedScreen())
        await pilot.pause()
        service.pairing_inbox.publish(identity)
        service.events.publish(PairingOffered(identity))
        await pilot.pause()
        table = app.screen.query_one("#trusted-table", DataTable)
        assert table.row_count == 1
        app.screen.action_reject_pairing()
        assert service.dismissed == [identity.device_id]
        assert service.pairing_inbox.all() == []
        assert service.address_book.all() == []
        assert service.trust_store.get(identity.device_id) is None
