import pytest

from direct_transfer.core.endpoint import Endpoint, EndpointError


@pytest.mark.parametrize(
    ("raw", "host", "port"),
    [
        ("192.168.1.20", "192.168.1.20", 5000),
        ("192.168.1.20:6000", "192.168.1.20", 6000),
        ("host.local", "host.local", 5000),
        ("example.ddns.net:1234", "example.ddns.net", 1234),
        ("2001:db8::1", "2001:db8::1", 5000),
        ("[2001:db8::1]:5001", "2001:db8::1", 5001),
    ],
)
def test_parse_endpoint(raw, host, port):
    endpoint = Endpoint.parse(raw)
    assert (endpoint.host, endpoint.port) == (host, port)


@pytest.mark.parametrize(
    "raw",
    [
        "",
        " host",
        "host ",
        "bad host",
        "host:0",
        "host:65536",
        "host:no",
        "host:",
        "[2001:db8::1",
        "[127.0.0.1]:5000",
        "[]:5000",
        "999.2.3.4",
        "a" * 254,
    ],
)
def test_invalid_endpoint(raw):
    with pytest.raises(EndpointError):
        Endpoint.parse(raw)


def test_parsing_does_not_resolve_hostname(monkeypatch):
    monkeypatch.setattr(
        "socket.getaddrinfo", lambda *args: (_ for _ in ()).throw(AssertionError)
    )
    assert Endpoint.parse("not-resolved.example").host == "not-resolved.example"
