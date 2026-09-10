from __future__ import annotations

import pytest

from direct_transfer.core.pairing import PairingIdentity, PairingInbox
from direct_transfer.core.session import ProtocolError


def _identity(device_id: str, received_at: float = 1.0) -> PairingIdentity:
    return PairingIdentity(
        device_id, "key", "fingerprint", "10.0.0.2", received_at, 5000
    )


def test_expired_pairing_disappears_and_frees_capacity():
    now = [10.0]
    inbox = PairingInbox(max_pending=1, ttl=60, clock=lambda: now[0])
    inbox.publish(_identity("mp-00000001"))
    now[0] = 70.0

    inbox.publish(_identity("mp-00000002"))

    assert inbox.get("mp-00000001") is None
    assert [item.device_id for item in inbox.all()] == ["mp-00000002"]


def test_pairing_capacity_is_exact_and_remove_recovers_it():
    inbox = PairingInbox(max_pending=2, ttl=60, clock=lambda: 10.0)
    inbox.publish(_identity("mp-00000001"))
    inbox.publish(_identity("mp-00000002"))
    with pytest.raises(ProtocolError, match="full"):
        inbox.publish(_identity("mp-00000003"))

    assert inbox.reject("mp-00000001")
    inbox.publish(_identity("mp-00000003"))
    assert len(inbox.all()) == 2


def test_valid_pending_pairing_remains_until_ttl():
    now = [10.0]
    inbox = PairingInbox(ttl=60, clock=lambda: now[0])
    inbox.publish(_identity("mp-00000001"))
    now[0] = 69.999
    assert inbox.prune_expired() == 0
    assert inbox.get("mp-00000001") is not None
