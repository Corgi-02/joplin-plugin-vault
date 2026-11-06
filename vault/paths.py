"""Read-only discovery of paths on the current Windows computer."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path


def existing_path(value, executable=False):
    if not isinstance(value, (str, os.PathLike)) or not str(value).strip(): return ''
    try:
        path = Path(os.path.expandvars(str(value).strip().strip('"'))).expanduser()
        if not path.is_absolute(): return ''
        valid = path.name.lower() == 'joplin.exe' and path.is_file() if executable else (path / 'database.sqlite').is_file()
        return str(path.resolve()) if valid else ''
    except (OSError, ValueError):
        return ''


def registry_executables():
    if os.name != 'nt': return []
    import winreg
    candidates = []

    def value(key, name):
        try:
            result = winreg.QueryValueEx(key, name)[0]
            return os.path.expandvars(result) if isinstance(result, str) else ''
        except OSError: return ''

    for hive in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
        for view in [winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY]:
            access = winreg.KEY_READ | view
            try:
                with winreg.OpenKey(hive, r'Software\Microsoft\Windows\CurrentVersion\App Paths\Joplin.exe', 0, access) as key:
                    candidates.append(value(key, ''))
            except OSError: pass
            try:
                with winreg.OpenKey(hive, r'Software\Microsoft\Windows\CurrentVersion\Uninstall', 0, access) as parent:
                    for index in range(winreg.QueryInfoKey(parent)[0]):
                        try:
                            with winreg.OpenKey(parent, winreg.EnumKey(parent, index)) as key:
                                if value(key, 'DisplayName').strip().casefold() != 'joplin': continue
                                location = value(key, 'InstallLocation')
                                if location: candidates.append(str(Path(location) / 'Joplin.exe'))
                                icon = value(key, 'DisplayIcon').strip()
                                if icon:
                                    # DisplayIcon is a file path with an optional icon index.
                                    candidates.append(re.sub(r',\s*-?\d+\s*$', '', icon).strip('"'))
                        except OSError: continue
            except OSError: pass
    return candidates


def default_joplin_exe():
    candidates = registry_executables()
    for variable, suffix in [('LOCALAPPDATA', 'Programs/Joplin/Joplin.exe'),
                             ('ProgramFiles', 'Joplin/Joplin.exe'), ('ProgramFiles(x86)', 'Joplin/Joplin.exe')]:
        if os.environ.get(variable): candidates.append(str(Path(os.environ[variable]) / suffix))
    return next((found for item in candidates if (found := existing_path(item, executable=True))), '')


def discover_profiles(joplin_exe='', saved_profile=''):
    roots = []
    saved = existing_path(saved_profile)
    if saved:
        path = Path(saved)
        roots.append(path.parent if path.name.startswith('profile-') and (path.parent / 'profiles.json').is_file() else path)
    exe = existing_path(joplin_exe, executable=True)
    if exe: roots.append(Path(exe).parent / 'JoplinProfile')
    roots.append(Path.home() / '.config/joplin-desktop')
    profiles, seen = [], set()
    for root in roots:
        entries = [('Default', root)]
        try:
            obj = json.loads((root / 'profiles.json').read_text(encoding='utf-8-sig'))
            items = obj.get('profiles', [])
            if isinstance(items, list):
                items = [item for item in items if isinstance(item, dict) and isinstance(item.get('id'), str)
                         and re.fullmatch(r'[A-Za-z0-9_-]+', item['id'])]
                items.sort(key=lambda item: item['id'] != obj.get('currentProfileId'))
                entries = [(str(item.get('name', item['id'])), root if item['id'] == 'default' else root / ('profile-' + item['id'])) for item in items]
                entries.append(('Default', root))
        except (OSError, ValueError, AttributeError): pass
        for name, path in entries:
            valid = existing_path(path)
            if valid and valid.casefold() not in seen:
                seen.add(valid.casefold()); profiles.append((name, valid))
    return profiles


def initial_paths(config):
    exe = existing_path(config.get('joplin_exe'), executable=True) or default_joplin_exe()
    saved = existing_path(config.get('profile'))
    profiles = discover_profiles(exe, saved)
    profile = saved or (profiles[0][1] if profiles else '')
    return profile, exe, profiles
