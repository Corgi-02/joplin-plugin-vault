"""Local temporary workspaces and persistent-log redaction."""
from __future__ import annotations

import contextlib
import os
import re
import shutil
import tempfile
from pathlib import Path


WORKSPACE_NAME = re.compile(r'jpv-(?:backup|verify|preview|restore)-[a-z0-9_]{8}')
MARKER = b'JoplinPluginVault temporary workspace v1\n'


def is_link(path):
    return path.is_symlink() or path.is_junction()


def temp_root():
    # Deliberately independent of portable data and user-selected backup paths.
    local = os.environ.get('LOCALAPPDATA')
    base = Path(local) if local else Path.home() / 'AppData/Local'
    if not base.is_absolute():
        raise OSError('本机临时目录必须为绝对路径。')
    root = base / 'JoplinPluginVault/temporary'
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if is_link(root) or is_link(root.parent):
        raise OSError('本机临时目录不能使用链接或联接。')
    return root


@contextlib.contextmanager
def workspace_lock(path):
    # Holding this handle also prevents a second instance from cleaning it.
    with path.open('r+b') as stream:
        if os.name == 'nt':
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == 'nt':
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


@contextlib.contextmanager
def private_workspace(kind):
    if kind not in {'backup', 'verify', 'preview', 'restore'}:
        raise ValueError('Unknown temporary workspace kind')
    with tempfile.TemporaryDirectory(prefix=f'jpv-{kind}-', dir=temp_root()) as directory:
        folder = Path(directory)
        # Creation is private (mode 0700, including Windows ACLs on Python 3.14).
        lock = folder / 'active.lock'
        lock.write_bytes(b'0')
        with workspace_lock(lock):
            (folder / '.jpv-workspace').write_bytes(MARKER)
            yield folder


def managed_workspace(folder, root):
    if (folder.parent != root or not WORKSPACE_NAME.fullmatch(folder.name)
            or is_link(folder) or not folder.is_dir()):
        return False
    marker, lock = folder / '.jpv-workspace', folder / 'active.lock'
    if is_link(marker) or is_link(lock) or not marker.is_file() or not lock.is_file():
        return False
    with marker.open('rb') as stream:
        return stream.read(len(MARKER) + 1) == MARKER


def stale_workspaces():
    root = temp_root()
    stale = []
    for folder in root.iterdir():
        try:
            if managed_workspace(folder, root):
                with workspace_lock(folder / 'active.lock'):
                    stale.append(folder)
        except OSError:
            continue
    return stale


def cleanup_workspaces(folders):
    root = temp_root()
    removed, skipped = 0, 0
    for folder in map(Path, folders):
        try:
            if not managed_workspace(folder, root):
                skipped += 1
                continue
            with workspace_lock(folder / 'active.lock'):
                # Reject links throughout before deleting anything.
                if any(is_link(Path(base) / name) for base, dirs, files in os.walk(folder)
                       for name in dirs + files):
                    skipped += 1
                    continue
                for child in folder.iterdir():
                    if child.name in {'active.lock', '.jpv-workspace'}:
                        continue
                    if child.is_dir():
                        shutil.rmtree(child)
                    else:
                        child.unlink()
                (folder / '.jpv-workspace').unlink()
            (folder / 'active.lock').unlink()
            folder.rmdir()
            removed += 1
        except OSError:
            skipped += 1
    return removed, skipped


def legacy_workspaces(backup_folder=''):
    # Legacy versions have no lock/ownership marker: report, never auto-delete.
    roots = {Path(tempfile.gettempdir())}
    if backup_folder and Path(backup_folder).is_absolute():
        roots.add(Path(backup_folder))
    found = []
    for root in roots:
        try:
            found.extend(p for p in root.iterdir()
                         if WORKSPACE_NAME.fullmatch(p.name) and not is_link(p) and p.is_dir())
        except OSError:
            continue
    return found


def redact_log(text):
    text = re.sub(r'https?://[^\s\'"<>；，]+', '[服务器地址]', str(text), flags=re.I)
    return re.sub(r'(?:[A-Za-z]:[\\/]|\\\\)[^\r\n\'"<>；，]*', '[本地路径]', text)
