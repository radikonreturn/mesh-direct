from __future__ import annotations

import asyncio
from types import SimpleNamespace

from textual.widgets import DataTable

from direct_transfer.tui.dashboard import DirectTransferApp


class FakeService:
    def __init__(self):
        self.started = False
        self.address_book = SimpleNamespace(all=lambda: [])
        self.transfer = SimpleNamespace(get_transfers=lambda: [])

    def start(self):
        self.started = True

    def stop(self):
        self.started = False


def test_dashboard_is_keyboard_first_and_has_core_tables():
    asyncio.run(_exercise_dashboard())


async def _exercise_dashboard():
    service = FakeService()
    app = DirectTransferApp(service)
    async with app.run_test(size=(100, 32)) as pilot:
        assert service.started
        assert len(app.query_one("#peers", DataTable).columns) == 4
        assert len(app.query_one("#transfers", DataTable).columns) == 5
        await pilot.press("c")
        assert app.screen.query_one("#address")
        await pilot.press("escape")
