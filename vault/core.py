from __future__ import annotations

import contextlib
import functools
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tarfile
import threading
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .security import private_workspace

MAGIC = b'JPVAULT1'
CHUNK = 1024 * 1024
MAX_TOTAL = 100 * 1024**3
MANAGED_KEYS = {'plugins.states', 'plugins.autoUpdateEnabled'}
ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$')
BACKUP_NAME = re.compile(r'^joplin-plugins-\d{8}T\d{6}Z-[a-f0-9]{8}\.jpv\.(zip|enc)$')


class VaultError(Exception):
    pass


def validate_backup_password(password, allow_unencrypted=False):
    if not password:
        if not allow_unencrypted:
            raise VaultError('请填写至少 8 个字符的备份密码；明文备份需显式选择并确认。')
    elif len(password) < 8:
        raise VaultError('备份密码请至少使用 8 个字符。')


def managed_key(key):
    return isinstance(key, str) and (key.startswith('plugin-') or key in MANAGED_KEYS)


def serialized(profile_index):
    def decorate(function):
        @functools.wraps(function)
        def wrapped(self, *args, **kwargs):
            self.guard()
            profile = kwargs.get('profile', args[profile_index] if len(args) > profile_index else None)
            layout = Layout.discover(profile)
            with self.operation(layout.root):
                return function(self, *args, **kwargs)
        return wrapped
    return decorate


def read_json(path: Path):
    return json.loads(path.read_text(encoding='utf-8-sig')) if path.exists() else {}


def atomic_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp-' + uuid.uuid4().hex)
    try:
        with tmp.open('x', encoding='utf-8') as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def digest(path: Path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        while data := f.read(CHUNK):
            h.update(data)
    return h.hexdigest()


def assert_joplin_closed():
    if os.name != 'nt':
        raise VaultError('此版本仅支持 Windows。')
    result = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq Joplin.exe', '/FO', 'CSV', '/NH'],
                            capture_output=True, creationflags=0x08000000, timeout=15)
    if result.returncode != 0:
        raise VaultError('无法确认 Joplin 是否退出，请稍后重试。')
    if b'joplin.exe' in result.stdout.lower():
        raise VaultError('请先在 Joplin 中选择“文件 → 退出”。仅关闭窗口可能仍在托盘运行。')


def assert_plain(path: Path):
    if path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction()):
        raise VaultError(f'不支持链接或联接目录：{path.name}')


def safe_remove(path: Path, parent: Path):
    absolute, base = path.resolve(), parent.resolve()
    if absolute == base or not absolute.is_relative_to(base):
        raise VaultError('清理路径超出允许范围。')
    assert_plain(path)
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)


def plain_files(folder: Path):
    if not folder.exists():
        return
    assert_plain(folder)
    for base, dirs, names in os.walk(folder, followlinks=False):
        for name in dirs + names:
            assert_plain(Path(base) / name)
        for name in sorted(names):
            yield Path(base) / name


@dataclass(frozen=True)
class Layout:
    profile: Path
    root: Path

    @classmethod
    def discover(cls, value):
        if not value or not str(value).strip():
            raise VaultError('请先填写或选择 Joplin 配置目录。')
        profile = Path(value).expanduser().absolute()
        assert_plain(profile)
        profile = profile.resolve()
        if not (profile / 'database.sqlite').is_file():
            raise VaultError('请选择已初始化的 Joplin 配置目录（需有 database.sqlite）。新电脑请先启动一次 Joplin，再退出。')
        root = profile.parent if profile.name.startswith('profile-') and (profile.parent / 'profiles.json').exists() else profile
        for folder in [profile, root, root / 'plugins', profile / 'plugin-data']:
            assert_plain(folder)
        return cls(profile, root)

    @property
    def plugins(self):
        return self.root / 'plugins'

    @property
    def data(self):
        return self.profile / 'plugin-data'

    @property
    def database(self):
        return self.profile / 'database.sqlite'


def db_settings(database: Path):
    try:
        with contextlib.closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=10)) as conn:
            return {k: v for k, v in conn.execute('SELECT key,value FROM settings') if managed_key(k)}
    except sqlite3.Error as exc:
        raise VaultError('无法读取 Joplin 插件设置数据库。') from exc


def package_manifest(path: Path):
    try:
        with tarfile.open(path, 'r:*') as archive:
            entry = next((x for x in archive if x.name in ['manifest.json', './manifest.json']), None)
            if entry is None or not entry.isfile() or entry.size > CHUNK:
                raise VaultError(f'插件包中没有有效 manifest：{path.name}')
            obj = json.load(archive.extractfile(entry))
        if not ID.fullmatch(str(obj.get('id', ''))):
            raise VaultError(f'插件标识无效：{path.name}')
        return obj
    except (tarfile.TarError, OSError, ValueError) as exc:
        raise VaultError(f'无法读取插件包：{path.name}') from exc


def inventory(layout: Layout, joplin_exe=''):
    settings = db_settings(layout.database)
    file_values = {}
    for name, folder in [('profile', layout.profile), ('root', layout.root)]:
        file_values[name] = {k: v for k, v in read_json(folder / 'settings.json').items() if managed_key(k)}
    state = settings.get('plugins.states')
    try:
        state = json.loads(state) if state else file_values['profile'].get('plugins.states', file_values['root'].get('plugins.states', {}))
        state = json.loads(state) if isinstance(state, str) else state
    except ValueError as exc:
        raise VaultError('插件启用状态格式无效，未创建备份。') from exc
    sources = {}
    builtins = Path(joplin_exe).parent / 'resources/build/defaultPlugins' if joplin_exe else None
    # User packages override bundled defaults, matching Joplin's loading order.
    for folder, bundled in [(builtins, True), (layout.plugins, False)]:
        if folder and folder.exists():
            assert_plain(folder)
            for path in sorted(folder.glob('*.jpl')):
                assert_plain(path)
                meta = package_manifest(path)
                sources[meta['id']] = (path, meta, bundled)
    plugins = []
    for plugin_id, (path, meta, bundled) in sorted(sources.items()):
        plugins.append({'id': plugin_id, 'name': meta.get('name', plugin_id), 'version': meta.get('version', ''),
                        'enabled': bool(state.get(plugin_id, {}).get('enabled', True)),
                        'deleted': bool(state.get(plugin_id, {}).get('deleted', False)),
                        'bundled': bundled, 'file': f'plugins/{plugin_id}.jpl'})
    warnings = ['系统钥匙串中的登录凭据不在备份中；外部路径或程序可能需要在新电脑重新配置。',
                '附着在笔记 user_data 中的插件信息随笔记同步，本工具不备份或覆盖笔记。']
    absolute_path_keys = {k for section in [settings, *file_values.values()] for k, v in section.items()
                          if isinstance(v, str) and re.search(r'(?:[A-Za-z]:[\\/]|\\\\[^\\]+\\)', v)}
    if absolute_path_keys:
        warnings.append('迁移后请检查这些含绝对路径的设置：' + '、'.join(sorted(absolute_path_keys)))
    absent = [k for k, v in state.items() if k not in sources and not v.get('deleted', False)]
    if absent:
        warnings.append('下列状态没有对应安装包（可能为遗留记录或未找到内建插件目录）：' + '、'.join(absent))
    return {'format': 'joplin-plugin-vault', 'version': 1, 'created_utc': datetime.now(timezone.utc).isoformat(),
            'platform': 'Windows', 'plugins': plugins, 'settings_database': settings,
            'settings_files': file_values, 'warnings': warnings}, sources


def encrypt(source: Path, destination: Path, password: str):
    salt, nonce = os.urandom(16), os.urandom(12)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 600_000, 32)
    header = MAGIC + salt + nonce
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    cipher.authenticate_additional_data(header)
    with source.open('rb') as src, destination.open('xb') as dst:
        dst.write(header)
        while data := src.read(CHUNK):
            dst.write(cipher.update(data))
        dst.write(cipher.finalize())
        dst.write(cipher.tag)


def decrypt(source: Path, destination: Path, password: str):
    if not password:
        raise VaultError('此备份已加密，请输入备份密码。')
    try:
        with source.open('rb') as src:
            header = src.read(36)
            if len(header) != 36 or header[:8] != MAGIC or source.stat().st_size < 52:
                raise VaultError('加密备份格式无效。')
            key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), header[8:24], 600_000, 32)
            src.seek(-16, os.SEEK_END)
            tag = src.read(16)
            src.seek(36)
            cipher = Cipher(algorithms.AES(key), modes.GCM(header[24:], tag)).decryptor()
            cipher.authenticate_additional_data(header)
            remaining = source.stat().st_size - 52
            with destination.open('xb') as dst:
                while remaining:
                    data = src.read(min(CHUNK, remaining))
                    if not data:
                        raise VaultError('加密备份不完整。')
                    remaining -= len(data)
                    dst.write(cipher.update(data))
                dst.write(cipher.finalize())
    except InvalidTag as exc:
        destination.unlink(missing_ok=True)
        raise VaultError('备份密码错误，或文件已损坏。') from exc


@contextlib.contextmanager
def open_archive(source: Path, password=''):
    with private_workspace('verify') as work:
        with source.open('rb') as f:
            encrypted = f.read(8) == MAGIC
        plain = Path(work) / 'decrypted.zip' if encrypted else source
        if encrypted:
            decrypt(source, plain, password)
        try:
            with zipfile.ZipFile(plain) as archive:
                yield archive
        except zipfile.BadZipFile as exc:
            raise VaultError('备份文件不完整或不是支持的备份格式。') from exc


def valid_member(name):
    if not isinstance(name, str) or any(c in name for c in '\\:<>"|?*') or name.startswith('/'):
        raise VaultError('备份包含非法路径。')
    parts = name.split('/')
    for part in parts:
        if not part or part in ['.', '..'] or part.rstrip(' .') != part or any(ord(c) < 32 for c in part):
            raise VaultError('备份包含非法路径。')
        if re.match(r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)', part, re.I):
            raise VaultError('备份包含 Windows 保留路径。')
    if name != 'manifest.json' and not (name.startswith('plugins/') or name.startswith('plugin-data/')):
        raise VaultError('备份包含插件环境以外的文件。')


def validate_archive(archive):
    infos = archive.infolist()
    if len(infos) > 100_000 or sum(x.file_size for x in infos) > MAX_TOTAL:
        raise VaultError('备份展开尺寸超出支持范围。')
    seen = set()
    for info in infos:
        valid_member(info.filename)
        if info.filename.casefold() in seen or info.is_dir() or ((info.external_attr >> 16) & 0o170000) == 0o120000:
            raise VaultError('备份包含重复文件、目录项或链接。')
        seen.add(info.filename.casefold())
    if 'manifest.json' not in archive.namelist() or archive.getinfo('manifest.json').file_size > 32 * CHUNK:
        raise VaultError('备份缺少有效清单。')
    try:
        manifest = json.loads(archive.read('manifest.json'))
    except (ValueError, UnicodeError) as exc:
        raise VaultError('备份清单不是有效的 JSON。') from exc
    if not isinstance(manifest, dict) or manifest.get('format') != 'joplin-plugin-vault' or manifest.get('version') != 1:
        raise VaultError('不支持此备份版本。')
    if (not isinstance(manifest.get('created_utc'), str)
            or not isinstance(manifest.get('plugins'), list)
            or not isinstance(manifest.get('settings_database'), dict)
            or not isinstance(manifest.get('settings_files'), dict)
            or any(k not in {'root', 'profile'} for k in manifest['settings_files'])
            or not isinstance(manifest.get('warnings', []), list)
            or any(not isinstance(w, str) for w in manifest.get('warnings', []))):
        raise VaultError('备份清单结构无效。')
    files = manifest.get('files', {})
    if not isinstance(files, dict) or set(files) | {'manifest.json'} != set(archive.namelist()):
        raise VaultError('备份清单与文件不一致。')
    for section in [manifest.get('settings_database', {}), *manifest.get('settings_files', {}).values()]:
        if not isinstance(section, dict) or any(not managed_key(k) for k in section):
            raise VaultError('备份包含非插件设置，已拒绝恢复。')
    if any(v is not None and not isinstance(v, str) for v in manifest.get('settings_database', {}).values()):
        raise VaultError('数据库设置类型无效。')
    expected_plugins = set()
    for plugin in manifest.get('plugins', []):
        if not isinstance(plugin, dict):
            raise VaultError('插件清单无效。')
        plugin_id = plugin.get('id', '')
        if (not isinstance(plugin_id, str) or not ID.fullmatch(plugin_id)
                or plugin_id.casefold() in expected_plugins or plugin.get('file') != f'plugins/{plugin_id}.jpl'
                or not isinstance(plugin.get('enabled'), bool)):
            raise VaultError('插件清单无效。')
        if plugin['file'] not in files:
            raise VaultError('备份缺少插件安装包。')
        expected_plugins.add(plugin_id.casefold())
    for name, meta in files.items():
        valid_member(name)
        if name.startswith('plugins/') and name not in {p['file'] for p in manifest['plugins']}:
            raise VaultError('存在未声明的插件包。')
        info = archive.getinfo(name)
        if not isinstance(meta, dict) or info.file_size != meta.get('size'):
            raise VaultError('备份文件尺寸校验失败。')
        h = hashlib.sha256()
        with archive.open(name) as f:
            while data := f.read(CHUNK):
                h.update(data)
        if h.hexdigest() != meta.get('sha256'):
            raise VaultError('备份文件完整性校验失败。')
    return manifest


class Engine:
    def __init__(self, guard: Callable = assert_joplin_closed):
        self.guard = guard
        self._local = threading.local()

    @contextlib.contextmanager
    def operation(self, root):
        root = Path(root).resolve()
        if getattr(self._local, 'root', None) == root:
            yield
            return
        path = root / '.plugin-vault-operation.lock'
        assert_plain(path)
        with path.open('a+b') as stream:
            if stream.tell() == 0: stream.write(b'0'); stream.flush()
            stream.seek(0)
            try:
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise VaultError('另一个备份或恢复操作正在处理此配置目录，请等待完成。') from None
            self._local.root = root
            try: yield
            finally:
                self._local.root = None
                stream.seek(0)
                if os.name == 'nt': msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else: fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    @serialized(0)
    def backup(self, profile, destination, password='', joplin_exe='', *, allow_unencrypted=False):
        validate_backup_password(password, allow_unencrypted)
        self.guard()
        layout = Layout.discover(profile)
        destination = Path(destination).expanduser().absolute().resolve()
        if destination == layout.profile or destination.is_relative_to(layout.plugins) or destination.is_relative_to(layout.data):
            raise VaultError('备份目录不能位于插件目录或插件数据目录中。')
        destination.mkdir(parents=True, exist_ok=True)
        manifest, sources = inventory(layout, joplin_exe)
        name = 'joplin-plugins-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
        target = destination / (name + ('.jpv.enc' if password else '.jpv.zip'))
        with private_workspace('backup') as work:
            plain = Path(work) / 'snapshot.zip'
            files = {}
            with zipfile.ZipFile(plain, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as archive:
                inputs = [(path, f'plugins/{pid}.jpl') for pid, (path, _, _) in sources.items()]
                inputs += [(path, 'plugin-data/' + path.relative_to(layout.data).as_posix()) for path in plain_files(layout.data)]
                for path, relative in inputs:
                    valid_member(relative)
                    before = path.stat()
                    h = hashlib.sha256()
                    size = 0
                    with path.open('rb') as src, archive.open(relative, 'w', force_zip64=True) as dst:
                        while chunk := src.read(CHUNK):
                            dst.write(chunk); h.update(chunk); size += len(chunk)
                    after = path.stat()
                    if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
                        raise VaultError('备份期间插件文件发生变化，请退出 Joplin 后重试。')
                    files[relative] = {'size': size, 'sha256': h.hexdigest()}
                manifest['files'] = files
                archive.writestr('manifest.json', json.dumps(manifest, ensure_ascii=False, indent=2))
            self.guard()
            pending = Path(work) / 'completed'
            if password:
                encrypt(plain, pending, password)
            else:
                shutil.copy2(plain, pending)
            # Verify our output before publishing it as a completed backup.
            with open_archive(pending, password) as archive:
                validate_archive(archive)
            # Only the completed output enters the chosen backup directory.
            # Copy first so publication remains atomic across local volumes.
            publishing = destination / ('.' + name + '-' + uuid.uuid4().hex + '.partial')
            try:
                with pending.open('rb') as src, publishing.open('xb') as dst:
                    shutil.copyfileobj(src, dst, CHUNK)
                    dst.flush()
                    os.fsync(dst.fileno())
                os.replace(publishing, target)
            finally:
                publishing.unlink(missing_ok=True)
        return target

    def preview(self, archive_path, profile, password=''):
        layout = Layout.discover(profile)
        # Bind the preview and its hash to the same immutable input copy.
        with private_workspace('preview') as work:
            frozen = Path(work) / 'input.backup'
            shutil.copyfile(archive_path, frozen)
            with open_archive(frozen, password) as archive:
                manifest = validate_archive(archive)
            archive_hash = digest(frozen)
        current = {package_manifest(p)['id'] for p in layout.plugins.glob('*.jpl')}
        saved = {p['id'] for p in manifest['plugins']}
        return {'manifest': manifest, 'target': str(layout.profile),
                'install': sorted(saved - current), 'replace': sorted(saved & current),
                'remove': sorted(current - saved), 'archive_sha256': archive_hash,
                'shared_plugins': layout.root != layout.profile}

    @serialized(1)
    def restore(self, archive_path, profile, recovery_dir, password='', joplin_exe='', expected_hash=None, fault=None, _recovering=False):
        if not _recovering:
            validate_backup_password(password)
        self.guard()
        layout = Layout.discover(profile)
        archive_path = Path(archive_path).absolute()
        # The original archive is copied before verification, preventing a
        # preview/restore race or replacement of the input during extraction.
        with private_workspace('restore') as work:
            work = Path(work)
            frozen = work / 'input.backup'
            shutil.copyfile(archive_path, frozen)
            if expected_hash and digest(frozen) != expected_hash:
                raise VaultError('备份文件在预览后发生变化，请重新预览。')
            with open_archive(frozen, password) as archive:
                manifest = validate_archive(archive)
                stage = work / 'stage'
                stage.mkdir()
                for name in manifest['files']:
                    output = stage / PurePosixPath(name)
                    output.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(name) as src, output.open('xb') as dst:
                        shutil.copyfileobj(src, dst, CHUNK)
                for plugin in manifest['plugins']:
                    meta = package_manifest(stage / plugin['file'])
                    if meta['id'] != plugin['id'] or meta.get('version', '') != plugin.get('version', ''):
                        raise VaultError('安装包与插件版本清单不一致。')
            journal = layout.profile / 'plugin-vault-recovery.json'
            if journal.exists() and not _recovering:
                raise VaultError('检测到之前未完成的恢复，请先查看恢复记录及恢复前快照。')
            recovery = archive_path if _recovering else self.backup(layout.profile, recovery_dir, password, joplin_exe)
            stash = layout.root / ('.jpv-swap-' + uuid.uuid4().hex)
            atomic_json(journal, {'status': 'applying', 'recovery_backup': str(recovery), 'stash': str(stash), 'started_utc': datetime.now(timezone.utc).isoformat()})
            stash.mkdir()
            swaps = []
            old_json = {}
            connection = None
            committed = False
            try:
                self.guard()
                connection = sqlite3.connect(layout.database, timeout=10)
                connection.execute('BEGIN IMMEDIATE')
                for key, value in list(connection.execute('SELECT key,value FROM settings')):
                    if managed_key(key):
                        connection.execute('DELETE FROM settings WHERE key=?', (key,))
                for key, value in manifest['settings_database'].items():
                    connection.execute('INSERT INTO settings(key,value) VALUES (?,?)', (key, value))
                for index, (source, target) in enumerate([(stage / 'plugins', layout.plugins), (stage / 'plugin-data', layout.data)]):
                    source.mkdir(exist_ok=True)
                    assert_plain(target)
                    previous = stash / str(index)
                    existed = target.exists()
                    if existed:
                        os.replace(target, previous)
                    swaps.append((target, previous, existed))
                    shutil.copytree(source, target)
                folders = [('root', layout.root), ('profile', layout.profile)]
                # For the default profile both locations are one file.
                for name, folder in folders:
                    path = folder / 'settings.json'
                    if path in old_json:
                        continue
                    old_json[path] = path.read_bytes() if path.exists() else None
                    obj = {k: v for k, v in read_json(path).items() if not managed_key(k)}
                    if layout.root == layout.profile:
                        merged = {**manifest.get('settings_files', {}).get('root', {}), **manifest.get('settings_files', {}).get('profile', {})}
                    else:
                        merged = dict(manifest.get('settings_files', {}).get(name, {}))
                    obj.update(merged)
                    atomic_json(path, obj)
                if fault:
                    fault()
                self.guard()
                connection.commit()
                committed = True
                connection.close(); connection = None
                atomic_json(journal, {'status': 'complete', 'recovery_backup': str(recovery), 'stash': str(stash)})
                safe_remove(stash, layout.root)
                journal.unlink()
                return {'recovery_backup': str(recovery), 'plugins': len(manifest['plugins']), 'settings': len(manifest['settings_database'])}
            except BaseException:
                if connection:
                    connection.rollback(); connection.close()
                if not committed:
                    try:
                        for target, previous, existed in reversed(swaps):
                            if target.exists(): safe_remove(target, target.parent)
                            if existed: os.replace(previous, target)
                        for path, content in old_json.items():
                            if content is None: path.unlink(missing_ok=True)
                            else:
                                temp = path.with_name(path.name + '.rollback')
                                temp.write_bytes(content); os.replace(temp, path)
                        if stash.exists(): safe_remove(stash, layout.root)
                        journal.unlink(missing_ok=True)
                    except BaseException as exc:
                        raise VaultError(f'恢复失败且自动回退未完成，请保留目录和恢复记录。恢复前快照：{recovery}') from exc
                else:
                    raise VaultError(f'数据已恢复，但收尾未完成。请查看恢复记录；恢复前快照：{recovery}')
                raise

    @serialized(0)
    def recover_interrupted(self, profile, password='', joplin_exe=''):
        self.guard()
        layout = Layout.discover(profile)
        journal = layout.profile / 'plugin-vault-recovery.json'
        if not journal.exists(): raise VaultError('此配置目录没有未完成的恢复记录。')
        record = read_json(journal)
        recovery = Path(record['recovery_backup'])
        if not recovery.is_file(): raise VaultError('恢复前快照已被移动，请先将其放回记录的位置。')
        with open_archive(recovery, password) as archive: validate_archive(archive)
        atomic_json(layout.profile / ('plugin-vault-recovery-previous-' + uuid.uuid4().hex + '.json'), record)
        result = self.restore(recovery, layout.profile, recovery.parent, password, joplin_exe,
                              digest(recovery), _recovering=True)
        old_stash = Path(record.get('stash', ''))
        if old_stash.name.startswith('.jpv-swap-') and old_stash.parent.resolve() == layout.root and old_stash.exists():
            safe_remove(old_stash, layout.root)
        return result


def list_local(folder):
    folder = Path(folder)
    if not folder.exists(): return []
    return [{'name': p.name, 'size': p.stat().st_size, 'modified': datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).isoformat()}
            for p in sorted(folder.iterdir(), reverse=True) if p.is_file() and BACKUP_NAME.fullmatch(p.name)]
