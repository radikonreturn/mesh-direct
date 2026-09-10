from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Label, Static


class InboxScreen(Screen):
    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
        ("a", "accept", "Accept"),
        ("r", "reject", "Reject"),
    ]

    def compose(self) -> ComposeResult:
        yield Label("Transfer inbox", classes="screen-title")
        yield Static(
            "Select an offer. File data is not written until you accept.",
            classes="screen-help",
        )
        yield DataTable(id="inbox-table")
        yield Static("No offer selected.", id="inbox-detail")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("Sender", "Device", "Files", "Size", "Message")
        self.refresh_rows()
        self.set_interval(1.0, self.refresh_rows)

    def refresh_rows(self) -> None:
        table = self.query_one(DataTable)
        table.clear()
        for request in self.app.service.get_pending_requests():
            table.add_row(
                request.peer_name or request.peer_ip,
                request.peer_device_id,
                str(len(request.files)),
                _size(request.total_size),
                request.message or "—",
                key=request.transfer_id,
            )
        self._show_selected()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "inbox-table":
            self._show_selected()

    def _show_selected(self) -> None:
        transfer_id = self._selected()
        detail = self.query_one("#inbox-detail", Static)
        if transfer_id is None:
            detail.update("No incoming offers.")
            return
        request = next(
            (
                item
                for item in self.app.service.get_pending_requests()
                if item.transfer_id == transfer_id
            ),
            None,
        )
        if request is None:
            detail.update("No offer selected.")
            return
        trusted = self.app.service.trust_store.get(request.peer_device_id)
        fingerprint = trusted.fingerprint if trusted else "Unavailable"
        files = "\n".join(
            f"  {item.name}  {_size(item.size)}" for item in request.files[:20]
        )
        if len(request.files) > 20:
            files += f"\n  …and {len(request.files) - 20} more"
        detail.update(
            f"Fingerprint  {fingerprint}\n"
            f"Source       {request.peer_ip}\n"
            f"Files\n{files}\n"
            f"Message      {request.message or '—'}"
        )

    def _selected(self) -> str | None:
        table = self.query_one(DataTable)
        return (
            str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)
            if table.row_count
            else None
        )

    def action_accept(self) -> None:
        transfer_id = self._selected()
        if transfer_id and self.app.service.accept_transfer(transfer_id):
            self.notify("Transfer accepted")
            self.refresh_rows()

    def action_reject(self) -> None:
        transfer_id = self._selected()
        if transfer_id and self.app.service.reject_transfer(transfer_id):
            self.notify("Transfer rejected")
            self.refresh_rows()


class HistoryScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        yield Label("Transfer history", classes="screen-title")
        yield DataTable(id="history-table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns(
            "Direction", "Peer", "Files", "Bytes", "Resume", "Status", "Error"
        )
        for item in self.app.service.get_history():
            table.add_row(
                item.direction,
                item.peer_hostname or item.peer_ip,
                str(item.file_count),
                _size(item.bytes_transferred),
                _size(item.resume_offset) if item.resumed else "—",
                item.status,
                item.error or "—",
            )


class TrustedScreen(Screen):
    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
        ("a", "approve", "Approve pairing"),
        ("r", "reject_pairing", "Reject pairing"),
        ("f", "forget", "Forget"),
    ]

    def compose(self) -> ComposeResult:
        yield Label("Trusted devices", classes="screen-title")
        yield Static(
            "Trust follows the device key, never its network address.",
            classes="screen-help",
        )
        yield DataTable(id="trusted-table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("Name", "Device ID", "Fingerprint", "Address", "State")
        self.refresh_rows()
        self.set_interval(1.0, self.refresh_rows)

    def refresh_rows(self) -> None:
        table = self.query_one(DataTable)
        selected = table.cursor_row
        table.clear()
        for item in self.app.service.pairing_inbox.all():
            table.add_row(
                item.peer_ip,
                item.device_id,
                item.fingerprint,
                f"{item.peer_ip}:{item.transfer_port}",
                "AWAITING TRUST",
                key=f"pending:{item.device_id}",
            )
        for item in self.app.service.address_book.all():
            table.add_row(
                item.friendly_name,
                item.device_id,
                item.fingerprint,
                str(item.endpoint),
                "TRUSTED",
                key=item.device_id,
            )
        if table.row_count and selected is not None:
            table.move_cursor(row=min(selected, table.row_count - 1))

    def action_approve(self) -> None:
        table = self.query_one(DataTable)
        if not table.row_count:
            return
        key = str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)
        if not key.startswith("pending:"):
            self.notify("Select an awaiting pairing request", severity="warning")
            return
        self.app.service.trust(key.removeprefix("pending:"))
        self.refresh_rows()
        self.notify("Device trusted; the peer can now reconnect")

    def action_reject_pairing(self) -> None:
        table = self.query_one(DataTable)
        if not table.row_count:
            return
        key = str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)
        if not key.startswith("pending:"):
            self.notify("Select an awaiting pairing request", severity="warning")
            return
        if self.app.service.dismiss_pairing(key.removeprefix("pending:")):
            self.refresh_rows()
            self.notify("Pairing request dismissed")

    def action_forget(self) -> None:
        table = self.query_one(DataTable)
        if not table.row_count:
            return
        device_id = str(
            table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        )
        if device_id.startswith("pending:"):
            self.notify("Approve or leave the pending request", severity="warning")
            return
        if self.app.service.forget_device(device_id):
            self.refresh_rows()
            self.notify("Device forgotten")


def _size(value: int) -> str:
    amount = float(value)
    for suffix in ("B", "KB", "MB", "GB", "TB"):
        if amount < 1024 or suffix == "TB":
            return (
                f"{amount:.0f} {suffix}" if suffix == "B" else f"{amount:.1f} {suffix}"
            )
        amount /= 1024
    return str(value)
