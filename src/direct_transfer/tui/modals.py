from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static

from direct_transfer.core.endpoint import Endpoint, EndpointError
from direct_transfer.core.pairing import PairingIdentity


class ConnectDialog(ModalScreen[tuple[Endpoint, str | None] | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]

    def action_cancel(self) -> None:
        self.dismiss(None)

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Label("Connect to peer", classes="dialog-title")
            yield Label("Address", classes="field-label")
            yield Input(placeholder="server.example.com:5000", id="address")
            yield Label("Optional name", classes="field-label")
            yield Input(placeholder="Home Server", id="name")
            yield Static("", id="dialog-error")
            with Horizontal(classes="dialog-actions"):
                yield Button("Cancel", id="cancel")
                yield Button("Connect", id="connect", variant="primary")

    def on_mount(self) -> None:
        self.query_one("#address", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        try:
            endpoint = Endpoint.parse(self.query_one("#address", Input).value)
        except EndpointError as error:
            self.query_one("#dialog-error", Static).update(str(error))
            return
        name = self.query_one("#name", Input).value.strip() or None
        self.dismiss((endpoint, name))


class TrustDialog(ModalScreen[bool]):
    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, identity: PairingIdentity, endpoint: Endpoint) -> None:
        super().__init__()
        self.identity = identity
        self.endpoint = endpoint

    def action_cancel(self) -> None:
        self.dismiss(False)

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog trust-dialog"):
            yield Label("New device", classes="dialog-title")
            yield Static(
                f"Host       {self.endpoint}\nDevice     {self.identity.device_id}\nFingerprint\n{self.identity.fingerprint}",
                classes="identity-block",
            )
            yield Static(
                "Compare this fingerprint with the other device before trusting it.",
                classes="dialog-help",
            )
            with Horizontal(classes="dialog-actions"):
                yield Button("Cancel", id="cancel")
                yield Button("Trust device", id="trust", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "trust")


class SendDialog(ModalScreen[tuple[str, str | None] | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]

    def action_cancel(self) -> None:
        self.dismiss(None)

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Label("Send files", classes="dialog-title")
            yield Label("File path", classes="field-label")
            yield Input(placeholder="/path/to/file", id="path")
            yield Label("Optional message", classes="field-label")
            yield Input(placeholder="Transfer note", id="message")
            yield Static("", id="dialog-error")
            with Horizontal(classes="dialog-actions"):
                yield Button("Cancel", id="cancel")
                yield Button("Offer", id="offer", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        path = self.query_one("#path", Input).value.strip()
        if not path:
            self.query_one("#dialog-error", Static).update("Choose a file to send")
            return
        self.dismiss((path, self.query_one("#message", Input).value.strip() or None))
