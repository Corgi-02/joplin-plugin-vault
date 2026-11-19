import base64
import os
import sys
from pathlib import Path
from .core import atomic_json, read_json
from .security import protect


def app_dir():
    return Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parents[1]


def data_dir():
    # Prefer a genuinely portable adjacent folder. Read-only installations
    # fall back to the current user's app-data directory.
    adjacent = app_dir() / 'VaultData'
    try:
        adjacent.mkdir(mode=0o700, parents=True, exist_ok=True)
        probe = adjacent / '.write-test'
        with probe.open('wb'): pass
        probe.unlink()
        return adjacent
    except OSError:
        fallback = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'JoplinPluginVault'
        fallback.mkdir(mode=0o700, parents=True, exist_ok=True)
        return fallback


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
