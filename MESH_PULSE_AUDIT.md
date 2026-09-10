# Mesh-Pulse selective port audit

Source inspected: `radikonreturn/mesh_pulse` at the repository head available on 2026-09-10.

## Reused and adapted

- `core/identity.py`: persistent Ed25519 key storage, public-key-derived device IDs, fingerprints, restrictive atomic writes.
- `core/trust.py`: key-bound explicit trust decisions and atomic JSON persistence. Discovery terminology and dependencies were removed.
- `core/session.py`: signed ephemeral X25519 protocol-v3 handshake, transcript binding, HKDF-SHA256, and trust enforcement. The domain separator was changed for this product.
- `utils/crypto.py`: only AES-256-GCM framing and bounded length-prefix reads. Fernet and passphrase/PBKDF2 compatibility were removed.
- `core/transfer_protocol.py`: bounded encrypted control/data frames, strict offer/chunk/response validation, SHA-256 metadata, and portable safe filenames. Legacy-v2 headers were removed.
- `core/transfer.py`: authenticated v3 offer/approval/stream/resume/cancel/retry engine, bounded receiver and sender workers, and history/event integration. Discovery resolution and all legacy-v2 branches were replaced with endpoint/address-book resolution.
- `core/resume.py`: validated partial metadata, safe offsets, SHA-256 verification, hidden partials, and collision-safe atomic commit. Partials now use a separate application-data directory.
- `core/inbox.py`, `core/transfer_models.py`, `core/transfer_lifecycle.py`, `core/events.py`, and `core/history.py`: approval state, lifecycle/event models, and SQLite persistence. History was extended with resume facts.
- Security/regression tests covering identity, v3 sessions, offers, path validation, cancellation, interruption/resume, collision handling, malformed clients, concurrency bounds, and history informed the adapted suite.
- The existing Textual dashboard, pairing modal, inbox, and styles were inspected for useful interaction patterns; the direct-product TUI was built separately around saved endpoints rather than copied.

## New direct-connect components

- `Endpoint` parsing and validation without eager DNS resolution.
- Signed two-stage pairing on the transfer listener.
- `DirectPeerService` application boundary.
- Persistent key-indexed address book with endpoint history.
- Direct peer dashboard, connect/send/trust dialogs, transfer inbox, history, and trusted-device screens.

## Intentionally not reused

UDP discovery, broadcast beacons/configuration, replay caches, peer presence states and timers, interface scanning, peer/discovery managers, monitoring, network intelligence, topology dashboards, health percentages, legacy protocol v2, passphrase-derived sessions, release/build automation, and LAN-specific assumptions.
