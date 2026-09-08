"""Entry point for the DTrack web server.

Run via ``dtrack web`` (see :mod:`dtrack.cli`). Launches a dependency-free
``http.server`` that exposes the REST API and serves the built Vue frontend.
"""
from __future__ import annotations

import os

from .handlers import run as _run


def run_web(host: str, port: int, db_path: str, config_path: str,
            dist_dir: str) -> None:
    _run(host, port, db_path, config_path, dist_dir)


# sensible defaults
def default_db_path() -> str:
    return os.path.join(os.getcwd(), "db", "dtrack.db")


def default_config_path() -> str:
    """配置文件缺省路径：优先 config/dtrack.toml，兼容旧的根目录 dtrack.toml。"""
    for name in ("config/dtrack.toml", "dtrack.toml"):
        p = os.path.join(os.getcwd(), name)
        if os.path.isfile(p):
            return p
    return os.path.join(os.getcwd(), "config", "dtrack.toml")


def default_dist_dir() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(here), ".", "static")
