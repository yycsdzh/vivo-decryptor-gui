# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec: single-file, windowed build of the Vivo Suite backup decryptor GUI.
# Build:  pyinstaller vivo-decryptor.spec --noconfirm --clean
#
# OPTIONAL --onedir alternative: faster startup and usually fewer antivirus
# false positives (nothing self-extracts to %TEMP%). To use it, replace the
# single EXE(...) below with an EXE(exclude_binaries=True, ...) without a.binaries/a.datas,
# then add COLLECT(exe, a.binaries, a.datas, upx=False, name='VivoDecryptor').
# Ship the resulting dist/VivoDecryptor/ folder as a zip.
import os
from PyInstaller.utils.hooks import collect_all
from PyInstaller.utils.win32.versioninfo import (
    VSVersionInfo, FixedFileInfo, StringFileInfo, StringTable, StringStruct,
    VarFileInfo, VarStruct,
)

# Locate sources: next to this spec, or one directory up.
_here = os.path.abspath(SPECPATH)
_src = _here if os.path.exists(os.path.join(_here, 'gui.py')) else os.path.dirname(_here)

crypto_datas, crypto_binaries, crypto_hidden = collect_all('cryptography')

version_info = VSVersionInfo(
    ffi=FixedFileInfo(filevers=(1, 0, 0, 0), prodvers=(1, 0, 0, 0)),
    kids=[
        StringFileInfo([StringTable('040904B0', [
            StringStruct('FileVersion', '1.0.0'),
            StringStruct('ProductVersion', '1.0.0'),
            StringStruct('ProductName', 'VivoDecryptor'),
            StringStruct('FileDescription', 'Vivo Suite backup decryptor GUI'),
            StringStruct('OriginalFilename', 'VivoDecryptor.exe'),
        ])]),
        VarFileInfo([VarStruct('Translation', [1033, 1200])]),
    ],
)

a = Analysis(
    [os.path.join(_src, 'gui.py')],
    pathex=[_src],
    binaries=crypto_binaries,
    datas=crypto_datas,
    hiddenimports=['vivo_engine'] + crypto_hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='VivoDecryptor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,          # UPX disabled: reduces AV false positives
    console=False,      # --windowed
    icon=None,
    version=version_info,
)
