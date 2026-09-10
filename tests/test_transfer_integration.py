from __future__ import annotations

from conftest import wait_until
from test_direct_connection import _pair_and_trust, _start_pair

from direct_transfer.core.models import TransferStatus


def test_accepted_encrypted_transfer_and_history(app_paths, free_port, tmp_path):
    sender, receiver = _start_pair(app_paths, free_port, approval_timeout=5)
    try:
        _, receiver_id = _pair_and_trust(sender, receiver)
        source = tmp_path / "payload.bin"
        source.write_bytes(b"authenticated payload" * 4096)
        transfer_id = sender.send_files(receiver_id, [source], "test transfer")
        assert wait_until(lambda: bool(receiver.get_pending_requests()))
        assert not list(receiver.paths.received.glob("payload*"))
        assert receiver.accept_transfer(transfer_id)
        assert wait_until(
            lambda: any(
                item.transfer_id == transfer_id
                and item.status is TransferStatus.COMPLETE
                for item in sender.transfer.get_transfers()
            )
        )
        assert (
            receiver.paths.received / "payload.bin"
        ).read_bytes() == source.read_bytes()
        assert wait_until(
            lambda: (
                receiver.history.get_transfer(transfer_id) is not None
                and receiver.history.get_transfer(transfer_id).status == "complete"
            )
        )
    finally:
        sender.stop()
        receiver.stop()


def test_rejected_transfer_writes_no_payload(app_paths, free_port, tmp_path):
    sender, receiver = _start_pair(app_paths, free_port, approval_timeout=5)
    try:
        _, receiver_id = _pair_and_trust(sender, receiver)
        source = tmp_path / "rejected.bin"
        source.write_bytes(b"no")
        transfer_id = sender.send_files(receiver_id, [source])
        assert wait_until(lambda: bool(receiver.get_pending_requests()))
        assert receiver.reject_transfer(transfer_id)
        assert wait_until(
            lambda: any(
                item.transfer_id == transfer_id
                and item.status is TransferStatus.REJECTED
                for item in sender.transfer.get_transfers()
            )
        )
        assert not (receiver.paths.received / source.name).exists()
    finally:
        sender.stop()
        receiver.stop()


def test_cancel_pending_transfer(app_paths, free_port, tmp_path):
    sender, receiver = _start_pair(app_paths, free_port, approval_timeout=5)
    try:
        _, receiver_id = _pair_and_trust(sender, receiver)
        source = tmp_path / "cancel.bin"
        source.write_bytes(b"cancel")
        transfer_id = sender.send_files(receiver_id, [source])
        assert wait_until(lambda: bool(receiver.get_pending_requests()))
        assert sender.cancel_transfer(transfer_id)
        assert wait_until(
            lambda: any(
                item.transfer_id == transfer_id
                and item.status is TransferStatus.CANCELLED
                for item in sender.transfer.get_transfers()
            )
        )
        assert not (receiver.paths.received / source.name).exists()
    finally:
        sender.stop()
        receiver.stop()


def test_collision_uses_new_destination(app_paths, free_port, tmp_path):
    sender, receiver = _start_pair(app_paths, free_port, approval_timeout=5)
    try:
        _, receiver_id = _pair_and_trust(sender, receiver)
        source = tmp_path / "same.txt"
        source.write_text("new")
        receiver.paths.received.mkdir(parents=True, exist_ok=True)
        (receiver.paths.received / "same.txt").write_text("old")
        transfer_id = sender.send_files(receiver_id, [source])
        assert wait_until(lambda: bool(receiver.get_pending_requests()))
        receiver.accept_transfer(transfer_id)
        assert wait_until(lambda: (receiver.paths.received / "same (1).txt").exists())
        assert (receiver.paths.received / "same.txt").read_text() == "old"
        assert (receiver.paths.received / "same (1).txt").read_text() == "new"
    finally:
        sender.stop()
        receiver.stop()
