"""Platform-appropriate persistent paths, kept outside the source checkout."""

from dataclasses import dataclass
from pathlib import Path

from platformdirs import user_data_path


@dataclass(frozen=True)
class AppPaths:
    root: Path
    identity: Path
    trust: Path
    address_book: Path
    history: Path
    partials: Path
    received: Path

    @classmethod
    def default(cls) -> "AppPaths":
        root = user_data_path("direct-transfer", appauthor=False)
        return cls(
            root=root,
            identity=root / "identity",
            trust=root / "trusted_devices.json",
            address_book=root / "address_book.json",
            history=root / "history.sqlite3",
            partials=root / "partials",
            received=root / "received",
        )

    def ensure(self) -> None:
        for directory in (self.root, self.identity, self.partials, self.received):
            directory.mkdir(parents=True, exist_ok=True)
