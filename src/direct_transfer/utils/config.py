"""Security and resource limits for direct transfers."""

from platformdirs import user_data_path

TRANSFER_PORT = 5000
TRANSFER_BACKLOG = 16
CHUNK_SIZE = 64 * 1024
HEADER_MAX_SIZE = 4096
MAX_FILES_PER_SESSION = 1024
MAX_FILE_SIZE = 100 * 1024 * 1024 * 1024
MAX_SESSION_SIZE = 1024 * 1024 * 1024 * 1024
MAX_RETRIES = 3
RETRY_DELAYS = (1.0, 2.0, 4.0)
MAX_CONCURRENT_TRANSFER_SESSIONS = 8
MAX_PENDING_TRANSFER_REQUESTS = 32
PAIRING_REQUEST_TTL = 90.0
CONNECT_TIMEOUT = 10.0
HANDSHAKE_TIMEOUT = 10.0
TRANSFER_APPROVAL_TIMEOUT = 120.0
CHUNK_TIMEOUT = 30.0
IDLE_TRANSFER_TIMEOUT = 60.0
NONCE_SIZE = 12

_DATA = user_data_path("direct-transfer", appauthor=False)
RECEIVE_DIR = str(_DATA / "received")


def validate_port(value: object, name: str = "port") -> int:
    if isinstance(value, bool):
        raise TypeError(f"{name} must be an integer port")
    try:
        port = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} must be an integer port") from error
    if not 1 <= port <= 65535:
        raise ValueError(f"{name} must be between 1 and 65535")
    return port
