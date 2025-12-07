# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

# Hidden imports for packages that PyInstaller might miss
hidden_imports = [
    'PySide6.QtCore',
    'PySide6.QtGui',
    'PySide6.QtWidgets',
    'matplotlib.backends.backend_qtagg',
    'psutil',
    'dns',
    'dns.resolver',
    'cryptography',
    'schedule',
    # Explicitly import all src modules
    'src',
    'src.core',
    'src.core.config',
    'src.core.logger',
    'src.network',
    'src.network.monitor',
    'src.network.filter_engine',
    'src.network.app_control',
    'src.network.doh_resolver',
    'src.network.nextdns_client',
    'src.rules',
    'src.rules.blocklist_manager',
    'src.security',
    'src.security.cia_monitor',
    'src.utils',
    'src.utils.diagnostics',
    'src.gui',
    'src.gui.dashboard',
    'src.gui.widgets',
    'src.gui.app_control_tab',
    'src.gui.dns_tab',
    'src.gui.diagnostics_tab',
]

a = Analysis(
    ['main.py'],
    pathex=['.'],  # Add current directory to path
    binaries=[],
    datas=[],
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
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
    [],
    exclude_binaries=True,
    name='Defensiq',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # Set to False for GUI-only (no console window)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,  # Request administrator privileges
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='Defensiq',
)
