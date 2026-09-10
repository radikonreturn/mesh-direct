"""AES-256-GCM payload protection and bounded length-prefixed framing."""

from __future__ import annotations

import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from direct_transfer.utils.config import NONCE_SIZE


def encrypt_chunk(data: bytes, key: bytes) -> bytes:
    """Encrypt one independently authenticated frame with a fresh nonce."""
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, data, None)


def decrypt_chunk(payload: bytes, key: bytes) -> bytes:
    """Decrypt and authenticate one nonce-prefixed frame."""
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    if len(payload) < NONCE_SIZE + 16:
        raise ValueError("Encrypted frame is too short")
    nonce = payload[:NONCE_SIZE]
    return AESGCM(key).decrypt(nonce, payload[NONCE_SIZE:], None)


def pack_frame(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def unpack_frame(sock, max_size: int = 64 * 1024 * 1024) -> bytes:
    raw_length = _recv_exact(sock, 4)
    if len(raw_length) != 4:
        raise ConnectionError("Connection closed while reading frame length")
    length = struct.unpack(">I", raw_length)[0]
    if length > max_size:
        raise ValueError(f"Frame size {length} exceeds maximum allowed {max_size}")
    data = _recv_exact(sock, length)
    if len(data) != length:
        raise ConnectionError("Connection closed while reading frame data")
    return data


def _recv_exact(sock, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            break
        result.extend(chunk)
    return bytes(result)
