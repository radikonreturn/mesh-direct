import time

from direct_transfer.core.history import (
    TransferFileRecord,
    TransferHistoryStore,
    TransferRecord,
)


def test_completed_failed_and_resumed_history(tmp_path):
    store = TransferHistoryStore(tmp_path / "history.sqlite3")
    for transfer_id, status in (
        ("a" * 32, "complete"),
        ("b" * 32, "failed"),
        ("c" * 32, "resuming"),
    ):
        store.create_transfer(
            TransferRecord(
                transfer_id,
                "mp-12345678",
                "127.0.0.1",
                "peer",
                "send",
                status,
                None,
                1,
                10,
                10 if status == "complete" else 4,
                time.time(),
                time.time() if status in {"complete", "failed"} else None,
                "network" if status == "failed" else None,
                status == "resuming",
                4 if status == "resuming" else 0,
            ),
            [
                TransferFileRecord(
                    None, transfer_id, "file-0", "x", None, 10, None, 4, status
                )
            ],
        )
    reopened = TransferHistoryStore(store.path)
    assert reopened.get_transfer("a" * 32).status == "complete"
    assert reopened.get_transfer("b" * 32).error == "network"
    assert reopened.get_transfer("c" * 32).status == "interrupted"
    assert reopened.get_transfer("c" * 32).resumed is True
    assert reopened.get_transfer("c" * 32).resume_offset == 4
    assert reopened.get_files("a" * 32)[0].filename == "x"
