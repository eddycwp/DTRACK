# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包脚本：DTrack -> Windows 单文件可执行程序。

构建命令（在项目根目录执行）：
    python -m PyInstaller --noconfirm --clean packaging/dtrack.spec

产物：dist/DTrack.exe（控制台程序，含前端静态资源与 reportlab）。
"""
import os

from PyInstaller.utils.hooks import collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, os.pardir))

a = Analysis(
    [os.path.join(SPECPATH, "boot.py")],
    pathex=[ROOT],
    binaries=[],
    datas=[
        # 前端构建产物（web 目录构建后输出到 dtrack/static）
        (os.path.join(ROOT, "dtrack", "static"), "dtrack/static"),
    ],
    # 显式收集 dtrack 包全部子模块（含 cli 中的延迟导入路径）
    hiddenimports=collect_submodules("dtrack"),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "PyQt5", "PySide2", "PySide6"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="DTrack",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
