from __future__ import annotations

import json
from dataclasses import asdict

from direct_transfer.core.address_book import AddressBook, AddressBookEntry
from direct_transfer.core.identity import DeviceIdentity


def _entry(identity: DeviceIdentity, index: int) -> AddressBookEntry:
    return AddressBookEntry(
        identity.device_id,
        f"peer-{index}",
        identity.fingerprint,
        identity.public_key,
        f"peer-{index}.local",
        f"192.168.1.{index}",
        5000,
        1000.0 + index,
    )


def test_one_malformed_record_does_not_erase_valid_peers(tmp_path, caplog):
    entries = [
        _entry(DeviceIdentity.load_or_create(tmp_path / f"identity-{index}"), index)
        for index in range(1, 4)
    ]
    records = {entry.device_id: asdict(entry) for entry in entries}
    records["mp-deadbeef"] = {
        **asdict(entries[0]),
        "device_id": "mp-deadbeef",
        "last_successful_connection": "yesterday",
    }
    path = tmp_path / "address.json"
    path.write_text(json.dumps({"version": 1, "devices": records}))

    book = AddressBook(path)

    assert {entry.device_id for entry in book.all()} == {
        entry.device_id for entry in entries
    }
    assert "Skipping invalid address record" in caplog.text
