import json

import pytest

from direct_transfer.core.identity import (
    DeviceIdentity,
    device_id_from_public_key,
    fingerprint_from_public_key,
)
from direct_transfer.core.trust import TrustStatus, TrustStore


def test_identity_persists(tmp_path):
    first = DeviceIdentity.load_or_create(tmp_path / "identity")
    second = DeviceIdentity.load_or_create(tmp_path / "identity")
    assert first.device_id == second.device_id
    assert first.public_key == second.public_key
    assert first.device_id == device_id_from_public_key(first.public_key)
    assert first.fingerprint == fingerprint_from_public_key(first.public_key)


def test_new_identity_requires_approval(tmp_path):
    identity = DeviceIdentity.load_or_create(tmp_path / "peer")
    store = TrustStore(tmp_path / "trust.json")
    assert store.assess(identity.device_id, identity.public_key) is TrustStatus.NEW
    store.trust(identity.device_id, "peer", identity.public_key)
    assert store.assess(identity.device_id, identity.public_key) is TrustStatus.TRUSTED


def test_trust_survives_network_location_change(tmp_path):
    identity = DeviceIdentity.load_or_create(tmp_path / "peer")
    store = TrustStore(tmp_path / "trust.json")
    store.trust(identity.device_id, "10.0.0.2", identity.public_key)
    store.trust(identity.device_id, "peer.example", identity.public_key)
    assert store.assess(identity.device_id, identity.public_key) is TrustStatus.TRUSTED


def test_changed_public_key_is_rejected(tmp_path):
    first = DeviceIdentity.load_or_create(tmp_path / "one")
    second = DeviceIdentity.load_or_create(tmp_path / "two")
    store = TrustStore(tmp_path / "trust.json")
    store.trust(first.device_id, "peer", first.public_key)
    payload = json.loads((tmp_path / "trust.json").read_text())
    payload["devices"][first.device_id]["public_key"] = second.public_key
    (tmp_path / "trust.json").write_text(json.dumps(payload))
    assert TrustStore(tmp_path / "trust.json").get(first.device_id) is None
    with pytest.raises(ValueError):
        store.trust(first.device_id, "peer", second.public_key)
