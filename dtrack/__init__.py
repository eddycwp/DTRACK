"""DTrack - modular development-module vulnerability analysis system."""
from __future__ import annotations

import logging
from typing import Optional

__version__ = "0.1.0"

_LOGGER = logging.getLogger("dtrack")


def setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> None:
    _LOGGER.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    _LOGGER.handlers.clear()
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s | %(message)s", "%H:%M:%S")
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    _LOGGER.addHandler(sh)
    if log_file:
        try:
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(fmt)
            _LOGGER.addHandler(fh)
        except Exception as e:  # noqa: BLE001
            _LOGGER.warning("无法写入日志文件 %s: %s", log_file, e)


def get_logger(name: str = "dtrack") -> logging.Logger:
    return logging.getLogger(name)
