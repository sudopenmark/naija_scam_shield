# naija_scam_shield.spec — PyInstaller build spec
# Author: Joshua Akadri
#
# Usage:
#   Windows:  pyinstaller naija_scam_shield.spec
#   Linux:    pyinstaller naija_scam_shield.spec
#
# Output:
#   dist/NaijaScamShield.exe  (Windows)
#   dist/NaijaScamShield      (Linux)

import sys
from pathlib import Path

block_cipher = None
APP_NAME = "NaijaScamShield"
SRC = Path(".").resolve()

a = Analysis(
    [str(SRC / "main.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=[
        (str(SRC / "assets"), "assets"),
        (str(SRC / "database"), "database"),
        (str(SRC / "core"), "core"),
    ],
    hiddenimports=[
        "PyQt6.QtCore",
        "PyQt6.QtWidgets",
        "PyQt6.QtGui",
        "PyQt6.QtNetwork",
        "PyQt6.sip",
        "requests",
        "whois",
        "reportlab",
        "reportlab.platypus",
        "reportlab.lib",
        "reportlab.pdfgen",
        "pyzbar",
        "cv2",
        "PIL",
        "sqlite3",
        "urllib.parse",
        "ssl",
        "socket",
        "json",
        "csv",
        "hashlib",
        "logging",
        "logging.handlers",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "pandas", "scipy"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name=APP_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # No console window on Windows
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(SRC / "assets" / "icon.ico") if sys.platform == "win32" else None,
)
