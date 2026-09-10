"""Parsing and display of directly reachable peer endpoints."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from direct_transfer.utils.config import TRANSFER_PORT, validate_port

_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?$")


class EndpointError(ValueError):
    """An endpoint is malformed; resolution is deliberately not attempted."""


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int = TRANSFER_PORT

    def __post_init__(self) -> None:
        host = self.host
        if not isinstance(host, str) or not host:
            raise EndpointError("Host is required")
        if host != host.strip() or any(character.isspace() for character in host):
            raise EndpointError("Address must not contain whitespace")
        if len(host) > 253:
            raise EndpointError("Host name is too long")
        try:
            port = validate_port(self.port)
        except (TypeError, ValueError) as error:
            raise EndpointError(str(error)) from error
        object.__setattr__(self, "port", port)
        self._validate_host(host)

    @staticmethod
    def _validate_host(host: str) -> None:
        try:
            ipaddress.ip_address(host)
            return
        except ValueError:
            pass
        if host.replace(".", "").isdecimal() and "." in host:
            raise EndpointError("Malformed IPv4 address")
        if ":" in host:
            raise EndpointError("Malformed IPv6 address")
        candidate = host[:-1] if host.endswith(".") else host
        if not candidate or any(
            not _HOST_LABEL.fullmatch(label) for label in candidate.split(".")
        ):
            raise EndpointError("Malformed host name")

    @classmethod
    def parse(cls, value: str, default_port: int = TRANSFER_PORT) -> Endpoint:
        if not isinstance(value, str) or not value:
            raise EndpointError("Address is required")
        if value != value.strip() or any(character.isspace() for character in value):
            raise EndpointError("Address must not contain whitespace")
        if value.startswith("["):
            close = value.find("]")
            if close < 0:
                raise EndpointError("Invalid IPv6 bracket syntax")
            host = value[1:close]
            rest = value[close + 1 :]
            if (
                not host
                or not rest.startswith(":")
                or len(rest) == 1
                or ":" in rest[1:]
            ):
                raise EndpointError("Invalid IPv6 endpoint")
            try:
                if ipaddress.ip_address(host).version != 6:
                    raise EndpointError("Brackets are only valid for IPv6")
            except ValueError as error:
                raise EndpointError("Malformed IPv6 address") from error
            return cls(host, cls._parse_port(rest[1:]))
        if "[" in value or "]" in value:
            raise EndpointError("Invalid bracket syntax")
        colon_count = value.count(":")
        if colon_count == 0:
            return cls(value, default_port)
        if colon_count == 1:
            host, raw_port = value.rsplit(":", 1)
            return cls(host, cls._parse_port(raw_port))
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError as error:
            raise EndpointError("Malformed IPv6 address") from error
        if parsed.version != 6:
            raise EndpointError("Malformed address")
        return cls(value, default_port)

    @staticmethod
    def _parse_port(value: str) -> int:
        if not value or not value.isascii() or not value.isdecimal():
            raise EndpointError("Port must be a number")
        try:
            return validate_port(int(value))
        except (TypeError, ValueError) as error:
            raise EndpointError(str(error)) from error

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"
