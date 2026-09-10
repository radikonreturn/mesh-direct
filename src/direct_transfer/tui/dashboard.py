from __future__ import annotations

import threading
from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Label, Static

from direct_transfer.core.endpoint import Endpoint
from direct_transfer.core.events import (
    CoreEvent,
    IncomingTransferOffered,
    PairingOffered,
    PeerStateChanged,
)
from direct_transfer.core.service import (
    ConnectionResult,
    ConnectionState,
    DirectConnectionError,
    DirectPeerService,
)
from direct_transfer.core.transfer import ServerState
from direct_transfer.tui.modals import ConnectDialog, SendDialog, TrustDialog
from direct_transfer.tui.screens import HistoryScreen, InboxScreen, TrustedScreen


class DirectTransferApp(App):
    CSS_PATH = "styles/dashboard.tcss"
    TITLE = "Direct Transfer"
    BINDINGS = [
        ("c", "connect", "Connect"),
        ("s", "send", "Send"),
        ("i", "inbox", "Inbox"),
        ("h", "history", "History"),
        ("t", "trusted", "Trusted Devices"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, service: DirectPeerService) -> None:
        super().__init__()
        self.service = service
        self._selected_device: str | None = None
        self._ui_thread_id: int | None = None

    def compose(self) -> ComposeResult:
        local_address = self.service.local_ipv4 or "—"
        with Horizontal(id="topbar"):
            yield Label("Direct Transfer", id="title")
            yield Static(
                f"LOCAL {local_address}:{self.service.port}", id="local-address"
            )
        yield Static(
            "Directly reachable peers · authenticated end to end", id="subtitle"
        )
        with Vertical(classes="section"):
            yield Label("Direct peers", classes="section-title")
            yield DataTable(id="peers")
        with Vertical(classes="section transfers-section"):
            yield Label("Transfers", classes="section-title")
            yield DataTable(id="transfers")
        yield Static("Starting listener", id="status")
        yield Footer()

    def on_mount(self) -> None:
        self._ui_thread_id = threading.get_ident()
        self.service.events.subscribe(self._on_core_event)
        peers = self.query_one("#peers", DataTable)
        peers.add_columns("Name", "Address", "Trust", "Last")
        transfers = self.query_one("#transfers", DataTable)
        transfers.add_columns("File", "Peer", "Progress", "Speed", "Status")
        state = self.service.start()
        if state == ServerState.LISTENING:
            address = self.service.local_ipv4 or "—"
            self._set_status(f"Listening · {address}:{self.service.port}")
        elif state == ServerState.FAILED:
            self._set_status(
                f"Unable to listen on port {self.service.port}", error=True
            )
        else:
            self._set_status("Listener startup timed out", error=True)
        self.refresh_data()
        self.set_interval(0.5, self.refresh_data)

    def on_unmount(self) -> None:
        self.service.events.unsubscribe(self._on_core_event)
        self.service.stop()

    def _on_core_event(self, event: CoreEvent) -> None:
        if threading.get_ident() == self._ui_thread_id:
            self._apply_core_event(event)
        else:
            self.call_from_thread(self._apply_core_event, event)

    def _apply_core_event(self, event: CoreEvent) -> None:
        if isinstance(event, IncomingTransferOffered):
            request = event.request
            sender = request.peer_name or request.peer_device_id
            self.notify(
                f"Incoming transfer from {sender} · {len(request.files)} "
                f"files · {_size(request.total_size)}\nPress I to review",
                title="Incoming transfer",
                timeout=8,
            )
            if isinstance(self.screen, InboxScreen):
                self.screen.refresh_rows()
        elif isinstance(event, PairingOffered):
            self.notify(
                f"Pairing request from {event.identity.peer_ip}\nPress T to review",
                title="New pairing request",
                timeout=8,
            )
            if isinstance(self.screen, TrustedScreen):
                self.screen.refresh_rows()
        elif isinstance(event, PeerStateChanged):
            self.refresh_data()
            if isinstance(self.screen, TrustedScreen):
                self.screen.refresh_rows()

    def refresh_data(self) -> None:
        peers = self.query_one("#peers", DataTable)
        cursor = peers.cursor_row
        peers.clear()
        for item in self.service.address_book.all():
            last = "never" if item.last_successful_connection is None else "known"
            peers.add_row(
                item.friendly_name,
                str(item.endpoint),
                "TRUSTED",
                last,
                key=item.device_id,
            )
        if peers.row_count and cursor is not None:
            peers.move_cursor(row=min(cursor, peers.row_count - 1))
        transfers = self.query_one("#transfers", DataTable)
        transfers.clear()
        for item in self.service.transfer.get_transfers():
            transfers.add_row(
                item.filename,
                item.peer_device_id or item.peer_ip,
                f"{item.progress:5.1f}%",
                f"{item.speed_mbps:.1f} MB/s",
                item.status.value,
            )

    def action_connect(self) -> None:
        self.push_screen(ConnectDialog(), self._begin_connect)

    def _begin_connect(self, value: tuple[Endpoint, str | None] | None) -> None:
        if value is not None:
            self._connect_worker(*value)

    @work(thread=True, exclusive=True, group="connection")
    def _connect_worker(self, endpoint: Endpoint, name: str | None) -> None:
        self.call_from_thread(self._set_status, f"Resolving {endpoint.host}")
        try:
            result = self.service.connect(
                endpoint,
                progress=lambda state: self.call_from_thread(self._set_status, state),
            )
        except DirectConnectionError as error:
            self.call_from_thread(self._set_status, str(error), True)
            return
        if result.state == ConnectionState.AWAITING_TRUST:
            self.call_from_thread(self._ask_trust, result, name)
        else:
            self.call_from_thread(self._connected, result)

    def _ask_trust(self, result: ConnectionResult, name: str | None) -> None:
        self._set_status("Identity received · awaiting trust")
        self.push_screen(
            TrustDialog(result.identity, result.endpoint),
            lambda approved: self._finish_trust(approved, result, name),
        )

    def _finish_trust(
        self, approved: bool, result: ConnectionResult, name: str | None
    ) -> None:
        if not approved:
            self._set_status("Device not trusted")
            return
        self.service.trust(result.identity.device_id, name)
        self._set_status("Trusted · reconnect to authenticate")
        self.refresh_data()

    def _connected(self, result: ConnectionResult) -> None:
        self._selected_device = result.identity.device_id
        self._set_status(f"Authenticated · {result.identity.device_id}")
        self.refresh_data()

    def _set_status(self, message: str, error: bool = False) -> None:
        status = self.query_one("#status", Static)
        status.update(message)
        status.set_class(error, "error")

    def action_send(self) -> None:
        peers = self.query_one("#peers", DataTable)
        if peers.row_count:
            self._selected_device = str(
                peers.coordinate_to_cell_key(peers.cursor_coordinate).row_key.value
            )
        if not self._selected_device:
            self.notify("Connect to or select a trusted peer first", severity="warning")
            return
        self.push_screen(SendDialog(), self._send)

    def _send(self, value: tuple[str, str | None] | None) -> None:
        if value is None:
            return
        path, message = value
        if not Path(path).is_file():
            self.notify("File does not exist", severity="error")
            return
        transfer_id = self.service.send_files(self._selected_device, [path], message)
        self._set_status(f"Transfer offered · {transfer_id[:12]}")

    def action_inbox(self) -> None:
        self.push_screen(InboxScreen())

    def action_history(self) -> None:
        self.push_screen(HistoryScreen())

    def action_trusted(self) -> None:
        self.push_screen(TrustedScreen())


def _size(value: int) -> str:
    amount = float(value)
    for suffix in ("B", "KB", "MB", "GB", "TB"):
        if amount < 1024 or suffix == "TB":
            return (
                f"{amount:.0f} {suffix}" if suffix == "B" else f"{amount:.1f} {suffix}"
            )
        amount /= 1024
    return str(value)
