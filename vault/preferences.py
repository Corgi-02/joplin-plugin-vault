import base64
import ctypes
import json
import os
import sys
from pathlib import Path
from ctypes import wintypes

from .core import atomic_json, read_json, VaultError


def app_dir():
    return Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parents[1]


def data_dir():
    # Prefer a genuinely portable adjacent folder. Read-only installations
    # fall back to the current user's app-data directory.
    adjacent = app_dir() / 'VaultData'
    try:
        adjacent.mkdir(parents=True, exist_ok=True)
        probe = adjacent / '.write-test'
        with probe.open('wb'): pass
        probe.unlink()
        return adjacent
    except OSError:
        fallback = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'JoplinPluginVault'
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


class Blob(ctypes.Structure):
    _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_ubyte))]


def protect(value, decrypt=False):
    if os.name != 'nt': raise VaultError('凭据保存仅支持 Windows。')
    buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
    source, output = Blob(len(value), buffer), Blob()
    function = ctypes.windll.crypt32.CryptUnprotectData if decrypt else ctypes.windll.crypt32.CryptProtectData
    ok = function(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(output))
    if not ok: raise VaultError('本机凭据无法解密，请重新填写 WebDAV 密码。')
    try: return ctypes.string_at(output.pbData, output.cbData)
    finally: ctypes.windll.kernel32.LocalFree(output.pbData)


def load():
    config = read_json(data_dir() / 'preferences.json')
    warning = ''
    if config.get('dav_secret'):
        try: config['dav_password'] = protect(base64.b64decode(config['dav_secret']), True).decode('utf-8')
        except Exception: warning = '已记住的 WebDAV 密码不适用于此电脑，请重新输入。'
    return config, warning


def save(config, password='', remember=False):
    config = {k: v for k, v in config.items() if k not in ['dav_password', 'dav_secret', 'backup_password']}
    if remember and password:
        config['dav_secret'] = base64.b64encode(protect(password.encode('utf-8'))).decode()
    atomic_json(data_dir() / 'preferences.json', config)
