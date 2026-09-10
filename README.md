# Direct Transfer

Direct Transfer is a terminal-first application for sending files to a specific IP address or hostname. It has no peer discovery: you enter an endpoint, compare a cryptographic fingerprint, explicitly trust the device, and then use authenticated encrypted sessions.

```console
direct-transfer
direct-transfer --port 5000
direct-transfer --help
```

Endpoints accept IPv4, DNS and `.local` hostnames, and bracketed IPv6 with an optional port, for example `192.168.1.42`, `server.local:5000`, and `[2001:db8::1]:5000`. Parsing does not resolve names; resolution errors are shown while connecting.

## Security flow

The first connection exchanges signed persistent Ed25519 identities and displays the remote device ID and fingerprint. Trust is never automatic. Once both operators approve the keys, a fresh connection performs the protocol-v3 handshake: signed ephemeral X25519 keys, transcript-bound HKDF-SHA256 derivation, and AES-256-GCM encrypted control and data frames.

Incoming offers require approval before payload bytes are written. Accepted data streams to hidden partial files, resumes from validated offsets, receives an end-to-end SHA-256 check, and is committed without overwriting an existing destination. Transfer history is stored in SQLite without per-chunk writes.

## Reachability

The destination must be directly reachable. This works on the same LAN, a routed network, a VPN such as WireGuard or Tailscale, a public IP, or a DDNS name when routing and firewalls permit it. Direct Transfer does not implement NAT traversal, relay servers, STUN, TURN, UPnP, or automatic port forwarding.

Application state is stored in the platform-appropriate user data directory via `platformdirs`, never in the source checkout.

## Development

```console
python -m pip install -e '.[dev]'
pytest -q
ruff check .
ruff format --check .
```

The security and transfer engine selectively derives from the MIT-licensed [Mesh-Pulse](https://github.com/radikonreturn/mesh_pulse) implementation. Discovery, network monitoring, interface scanning, and LAN topology code were not ported.

