"""Logging configuration for NetRecon."""

import logging
import sys
from pathlib import Path


def setup_logger(name: str = "netrecon", log_file: str = None, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        # Console handler (stderr to avoid mixing with rich output)
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.WARNING)
        fmt = logging.Formatter("[%(levelname)s] %(name)s: %(message)s")
        console_handler.setFormatter(fmt)
        logger.addHandler(console_handler)

        # File handler (optional)
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
            file_handler.setFormatter(file_fmt)
            logger.addHandler(file_handler)

    return logger
