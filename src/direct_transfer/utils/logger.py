"""Package logging without global logging side effects."""

import logging


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
