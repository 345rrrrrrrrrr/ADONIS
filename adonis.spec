# -*- mode: python ; coding: utf-8 -*-

import sys
import os
from PyInstaller.building.build_main import Analysis, PYZ, EXE, COLLECT, BUNDLE, TOC

block_cipher = None

# Build paths
root_dir = os.path.abspath(os.path.dirname(__file__))
src_dir = os.path.join(root_dir, 'src')

# Data files to include
data_files = [
    ('LICENSE', '.', 'DATA'),
    ('README.md', '.', 'DATA'),
]

# Include module directories
module_datas = []
module_dirs = [
    os.path.join(src_dir, 'modules', 'network_scanner'),
    os.path.join(src_dir, 'modules', 'debugger'),
    os.path.join(src_dir, 'modules', 'terminal'),
    os.path.join(src_dir, 'modules', 'packet_analyzer'),
    os.path.join(src_dir, 'modules', 'memory_editor'),
]

# Add UI resources
ui_resources = [(os.path.join(src_dir, 'ui', 'resources'), 'ui/resources')]

# Combine all data files
datas = data_files + module_datas + ui_resources

a = Analysis(
    [os.path.join(src_dir, 'main.py')],
    pathex=[root_dir],
    binaries=[],
    datas=datas,
    hiddenimports=[
        'pkg_resources.py2_warn',
        'PyQt5',
        'PyQt5.QtWidgets',
        'PyQt5.QtCore',
        'PyQt5.QtGui',
        'PyQt5.QtWebEngine',
        'yaml',
        'cryptography',
        'psutil',
        'paramiko',
        'scapy',
        'fastapi',
        'transformers',
        'torch',
        'nmap',
        'xml.etree.ElementTree',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
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
    name='adonis',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    icon=os.path.join(src_dir, 'ui', 'resources', 'icon.ico') if os.path.exists(os.path.join(src_dir, 'ui', 'resources', 'icon.ico')) else None,
)

# For macOS, create a .app bundle
if sys.platform == 'darwin':
    app = BUNDLE(
        exe,
        name='ADONIS.app',
        icon=os.path.join(src_dir, 'ui', 'resources', 'icon.icns') if os.path.exists(os.path.join(src_dir, 'ui', 'resources', 'icon.icns')) else None,
        bundle_identifier='org.adonistoolkit.adonis',
        info_plist={
            'CFBundleShortVersionString': '0.1.0',
            'NSHighResolutionCapable': 'True',
        },
    )