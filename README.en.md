# Joplin Plugin Vault

[简体中文](README.md) | English

A portable Windows x64 tool for backing up and restoring Joplin plugin environments locally or through WebDAV. The packaged application requires no Python installation. The application UI is in Simplified Chinese.

## Quick start

1. Extract the portable package and run `JoplinPluginVault.exe`.
2. Check the detected profile directory and `Joplin.exe` path, or select them manually. “读取插件清单” reads the current plugin inventory.
3. In Joplin, choose File → Quit and make sure its tray process has exited too.
4. Choose a local backup directory, enter and confirm a password of at least 8 characters, then click “创建完整插件备份”. Manual backups may omit the password, but plugin settings can contain API keys.
5. To restore, select the backup and target profile, enter the password, then click “校验备份并预览”. Review the changes before restoring. On a new computer, launch Joplin once to initialize its profile, then quit it.

Backups use `.jpv.zip`, or `.jpv.enc` when encrypted. Old backups are not deleted automatically. Backup passwords are never saved; a lost password cannot be recovered.

## What is backed up

Snapshots include `.jpl` packages, including custom versions and discoverable bundled plugins; enabled/deleted states; automatic update options; plugin settings in the database and configuration files; and regular files in the selected profile's `plugin-data` directory.

Restoring replaces the target plugin directory and the selected profile's plugin data, restores plugin settings, and removes target plugins absent from the snapshot. It does not replace the full database. Target notes, resources, accounts, encryption master keys, and note synchronization settings are preserved.

The following are excluded:

- System keychain passwords and some login sessions. Reauthorization may be necessary.
- External files, programs, and plugin dependencies. Absolute paths in settings may need adjustment; the preview identifies relevant setting keys.
- Plugin information stored in note `user_data`, which travels with note synchronization.

Each operation handles one Joplin profile. Profiles may share a plugin installation directory: restoring changes those shared packages, while database settings and plugin data are restored only for the selected profile.

## Paths and local data

Only existing paths are filled automatically. Valid manual selections are retained, and stale paths are detected again. “重新识别路径” starts a fresh scan. Custom `--profile` locations and unregistered portable installations may require manual selection.

- Common profile directory: `%USERPROFILE%\.config\joplin-desktop`. In Joplin, use Help → Open profile directory to confirm it.
- Common executable paths: `C:\Program Files\Joplin\Joplin.exe` or `%LOCALAPPDATA%\Programs\Joplin\Joplin.exe`.
- Preferences, logs, default backups, downloads, and recovery snapshots live in `VaultData` beside the application when writable; otherwise they use `%LOCALAPPDATA%\JoplinPluginVault`.

Keep the application and backup files when moving computers. Old profile paths do not need to be carried over. Logs do not contain passwords or plugin setting values.

## WebDAV and scheduled backups

Enter a dedicated backup folder URL, username, and password on the WebDAV tab. “测试读写连接” creates, reads, and deletes a randomly named temporary file. Use a separate folder from Joplin's note synchronization directory.

Upload automatically after a local backup, or upload a selected historical backup. Remote backups can be downloaded for preview and restoration. Uploads use a temporary file followed by MOVE; existing backups with the same name are not overwritten. A failed upload leaves the local backup intact.

The server needs Basic authentication and MKCOL, PROPFIND, PUT, MOVE, HEAD, GET, and DELETE support. If HEAD is unsupported or cannot confirm the size, verification tries WebDAV properties and then falls back to downloading the file for verification. HTTPS uses system certificate validation. For redirected endpoints, enter the final URL.

“在本机记住 WebDAV 密码” stores the WebDAV password with Windows DPAPI for the current Windows user. Reenter it on another computer. This password is separate from the backup encryption password.

Scheduled backups run only while the tool is open and require a confirmed backup password. If Joplin is running, the password is missing, or another operation is active, the backup is skipped and retried at most once every 15 minutes.

## Failed or interrupted restoration

Before restoration, the tool verifies every backup file's SHA-256 and creates a snapshot of the target environment in `VaultData/recovery`, or `recovery` under the fallback data directory. When restoring an encrypted backup, the recovery snapshot uses the same supplied password.

Normal failures trigger rollback. After power loss, process termination, or failed rollback, the profile may contain `plugin-vault-recovery.json`. Keep that record, any `.jpv-swap-*` directory, and the recovery snapshot. Do not launch Joplin yet. On the restore tab, enter the snapshot password and click “修复中断的恢复” to restore the environment from before the interrupted operation.

## Source and build

Build environment: Windows x64 with Python 3.14. Dependencies are pinned in `requirements.txt`.

```powershell
./build.ps1
```

The script creates `.venv`, installs dependencies, runs tests, and produces:

- `dist/JoplinPluginVault.exe` and both README files.
- Portable and source ZIPs plus SHA-256 checksums in `release/`. Packages exclude local `VaultData`.

Run from source and execute tests:

```powershell
./.venv/Scripts/python.exe main.py
./.venv/Scripts/python.exe -m unittest discover -s tests -v
```

Read-only inspection: `main.py --inspect PROFILE --output inventory.json`. Output includes plugin metadata and setting counts, without setting values.

`vault/` contains application code. `tests/` retains regression coverage for restoration, encryption, path discovery, and a simulated WebDAV service. `build/`, `dist/`, and `release/` are generated directories; preserve any `VaultData` user data before cleaning them.
