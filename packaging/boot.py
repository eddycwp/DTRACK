"""PyInstaller 打包入口脚本。

双击 DTrack.exe（无命令行参数）时默认启动 Web 管理平台；
命令行参数与 `dtrack` CLI 完全一致（web / analyze / scan / fetch / config）。
"""
from __future__ import annotations

import sys

from dtrack.cli import main as cli_main


def main() -> int:
    argv = sys.argv[1:]
    if not argv:
        # 无参数时默认启动 Web 管理平台，方便直接双击使用
        argv = ["web"]
    return cli_main(argv)


if __name__ == "__main__":
    sys.exit(main())
