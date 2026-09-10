import hashlib
import socket
import threading

import pytest
from cryptography.exceptions import InvalidTag

from direct_transfer.core.protocol import (
    ProtocolError,
    receive_control_frame,
    send_encrypted_frame,
    validate_chunk_control,
    validate_filename,
    validate_offer,
)
from direct_transfer.core.resume import (
    PartialTransferStore,
    commit_partial_file,
    resolve_destination_collision,
)


def offer(name="report.pdf", size=3, digest=None):
    return validate_offer(
        {
            "type": "transfer_offer",
            "version": 3,
            "transfer_id": "a" * 32,
            "count": 1,
            "total_size": size,
            "files": [
                {
                    "file_id": "file-0",
                    "name": name,
                    "size": size,
                    "sha256": digest or hashlib.sha256(b"abc").hexdigest(),
                }
            ],
        }
    )


@pytest.mark.parametrize(
    "name", ["../x", "..\\x", "/tmp/x", "CON", "bad/child", "name. ", "\x00bad"]
)
def test_path_traversal_and_unsafe_names(name):
    with pytest.raises(ProtocolError):
        validate_filename(name)


def test_malformed_offer_and_chunk_rejected():
    with pytest.raises(ProtocolError):
        validate_offer(
            {"type": "transfer_offer", "version": 3, "transfer_id": "bad", "files": []}
        )
    with pytest.raises(ProtocolError):
        validate_chunk_control(
            {
                "type": "chunk",
                "transfer_id": "b" * 32,
                "file_id": "file-0",
                "index": 0,
                "offset": 0,
                "size": 1,
            },
            transfer_id="a" * 32,
            file_id="file-0",
            expected_index=0,
            expected_offset=0,
            remaining=3,
        )


def test_aes_gcm_frame_round_trip_and_tag_failure():
    left, right = socket.socketpair()
    key = b"k" * 32
    thread = threading.Thread(
        target=send_encrypted_frame, args=(left, key, {"ok": True})
    )
    thread.start()
    assert receive_control_frame(right, key) == {"ok": True}
    thread.join()
    left.close()
    right.close()
    left, right = socket.socketpair()
    thread = threading.Thread(
        target=send_encrypted_frame, args=(left, key, {"ok": True})
    )
    thread.start()
    with pytest.raises(InvalidTag):
        receive_control_frame(right, b"x" * 32)
    thread.join()
    left.close()
    right.close()


def test_resume_offsets_and_metadata(tmp_path):
    transfer = offer()
    store = PartialTransferStore(tmp_path)
    state = store.prepare(transfer)["file-0"]
    state.partial_path.write_bytes(b"ab")
    assert store.prepare(transfer)["file-0"].offset == 2
    with pytest.raises(ProtocolError):
        store.validate_resume_state(
            {
                "type": "resume_state",
                "transfer_id": transfer.transfer_id,
                "files": [{"file_id": "file-0", "offset": 4}],
            },
            transfer,
        )


def test_collision_safe_atomic_commit(tmp_path):
    received = tmp_path / "received"
    received.mkdir()
    (received / "report.pdf").write_bytes(b"old")
    assert (
        resolve_destination_collision(received, "report.pdf").name == "report (1).pdf"
    )
    partial = tmp_path / "partial"
    partial.write_bytes(b"new")
    final = commit_partial_file(partial, received, "report.pdf")
    assert final.name == "report (1).pdf"
    assert final.read_bytes() == b"new"
    assert (received / "report.pdf").read_bytes() == b"old"
