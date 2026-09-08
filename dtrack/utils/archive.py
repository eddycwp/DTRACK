"""归档相关工具（标准库实现）。"""
from __future__ import annotations

import io
import os
import zipfile


def zip_directory(dir_path: str) -> bytes:
    """将 ``dir_path`` 目录下的所有文件打包为 zip 字节。

    以目录名为基准计算相对路径（即压缩包内不含最外层目录本身），
    供奇安信二进制扫描等需要整体提交目录的场景使用。
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _dirs, files in os.walk(dir_path):
            for fn in files:
                fp = os.path.join(root, fn)
                z.write(fp, os.path.relpath(fp, dir_path))
    return buf.getvalue()
