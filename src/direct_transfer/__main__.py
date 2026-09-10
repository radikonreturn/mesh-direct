from __future__ import annotations

import click

from direct_transfer import __version__
from direct_transfer.core.service import DirectPeerService
from direct_transfer.tui.dashboard import DirectTransferApp
from direct_transfer.utils.config import TRANSFER_PORT, validate_port


def _port(_context: click.Context, _parameter: click.Parameter, value: int) -> int:
    try:
        return validate_port(value)
    except (TypeError, ValueError) as error:
        raise click.BadParameter(str(error)) from error


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--port",
    default=TRANSFER_PORT,
    show_default=True,
    type=int,
    callback=_port,
    help="TCP port for incoming direct connections.",
)
@click.version_option(__version__)
def main(port: int) -> None:
    """Direct, authenticated peer-to-peer file transfer in your terminal."""
    service = DirectPeerService(port=port)
    DirectTransferApp(service).run()


if __name__ == "__main__":
    main()
