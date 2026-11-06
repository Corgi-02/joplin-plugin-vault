from __future__ import annotations

import queue
import subprocess
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from . import __version__
from .core import Engine, Layout, VaultError, inventory, list_local, validate_backup_password
from .paths import initial_paths
from .preferences import data_dir, load, save
from .security import cleanup_workspaces, legacy_workspaces, redact_log, stale_workspaces
from .webdav import WebDav


def size_text(value):
    value = float(value)
    for unit in ['B', 'KB', 'MB', 'GB']:
        if value < 1024 or unit == 'GB': return f'{value:.1f} {unit}'
        value /= 1024


class App:
    def __init__(self, root):
        self.root = root
        self.home = data_dir()
        self.engine = Engine()
        self.queue = queue.Queue()
        self.busy = False
        self.preview = None
        self.last_backup = time.time()
        self.last_schedule_attempt = 0
        self.buttons = []
        try: config, warning = load()
        except Exception: config, warning = {}, '配置文件无法读取，已使用默认值。'
        profile, exe, profiles = initial_paths(config)
        self.profile = tk.StringVar(value=profile)
        self.exe = tk.StringVar(value=exe)
        self.folder = tk.StringVar(value=config.get('folder', str(self.home / 'backups')))
        self.password = tk.StringVar()
        self.confirm_password = tk.StringVar()
        self.plain_backup = tk.BooleanVar(value=False)
        self.archive = tk.StringVar()
        self.restore_password = tk.StringVar()
        self.dav_url = tk.StringVar(value=config.get('dav_url', ''))
        self.dav_user = tk.StringVar(value=config.get('dav_user', ''))
        self.dav_password = tk.StringVar(value=config.get('dav_password', ''))
        self.remember = tk.BooleanVar(value=bool(config.get('dav_secret')))
        self.upload = tk.BooleanVar(value=config.get('upload', False))
        self.schedule = tk.BooleanVar(value=config.get('schedule', False))
        self.hours = tk.IntVar(value=config.get('hours', 24))
        self.status = tk.StringVar(value='就绪 · 可以先读取当前插件清单，无需退出 Joplin')

        root.title(f'Joplin 插件保险箱 · {__version__}')
        root.geometry('1120x820')
        root.minsize(920, 720)
        root.configure(background='#f3f6fa')
        style = ttk.Style()
        if 'vista' in style.theme_names(): style.theme_use('vista')
        style.configure('TFrame', background='#f3f6fa')
        style.configure('TLabel', background='#f3f6fa', font=('Microsoft YaHei UI', 10))
        style.configure('Title.TLabel', font=('Microsoft YaHei UI', 20, 'bold'), foreground='#122943')
        style.configure('Hint.TLabel', foreground='#536779', font=('Microsoft YaHei UI', 9))
        style.configure('TButton', font=('Microsoft YaHei UI', 10), padding=(12, 7))
        style.configure('TCheckbutton', background='#f3f6fa', font=('Microsoft YaHei UI', 10))
        style.configure('TNotebook.Tab', padding=(20, 8), font=('Microsoft YaHei UI', 10))
        style.configure('Treeview', rowheight=28, font=('Microsoft YaHei UI', 9))
        style.configure('Treeview.Heading', font=('Microsoft YaHei UI', 9, 'bold'))

        outer = ttk.Frame(root, padding=22)
        outer.pack(fill='both', expand=True)
        heading = ttk.Frame(outer)
        heading.pack(fill='x')
        ttk.Label(heading, text='Joplin 插件备份与恢复', style='Title.TLabel').pack(side='left')
        self.button(heading, '重新识别路径', self.detect_paths).pack(side='right')
        ttk.Label(outer, text='保存插件包、启停状态、设置与插件数据。支持本地和 WebDAV 历史备份。', style='Hint.TLabel').pack(anchor='w', pady=(5, 16))
        top = ttk.Frame(outer)
        top.pack(fill='x')
        top.columnconfigure(1, weight=1)
        ttk.Label(top, text='Joplin 配置目录').grid(row=0, column=0, sticky='w', padx=(0, 12))
        self.profile_box = ttk.Combobox(top, textvariable=self.profile, values=[p[1] for p in profiles], width=72)
        self.profile_box.grid(row=0, column=1, sticky='ew')
        self.button(top, '选择目录', self.choose_profile).grid(row=0, column=2, padx=(8, 0))
        self.button(top, '读取插件清单', self.inspect).grid(row=0, column=3, padx=(8, 0))
        ttk.Label(top, text=r'默认安装示例：%USERPROFILE%\.config\joplin-desktop', style='Hint.TLabel').grid(row=1, column=1, columnspan=3, sticky='w', pady=(3, 0))
        ttk.Label(top, text='Joplin 程序').grid(row=2, column=0, sticky='w', pady=(8, 0))
        ttk.Entry(top, textvariable=self.exe).grid(row=2, column=1, sticky='ew', pady=(8, 0))
        self.button(top, '选择程序', self.choose_exe).grid(row=2, column=2, padx=(8, 0), pady=(8, 0))
        self.button(top, '启动 Joplin', self.launch_joplin).grid(row=2, column=3, padx=(8, 0), pady=(8, 0))
        ttk.Label(top, text=r'程序示例：C:\Program Files\Joplin\Joplin.exe 或 %LOCALAPPDATA%\Programs\Joplin\Joplin.exe', style='Hint.TLabel').grid(row=3, column=1, columnspan=3, sticky='w', pady=(3, 0))
        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill='both', expand=True, pady=(18, 12))
        self.backup_tab, self.restore_tab, self.dav_tab, self.log_tab = [ttk.Frame(self.notebook, padding=18) for _ in range(4)]
        for frame, title in [(self.backup_tab, '本地备份'), (self.restore_tab, '预览与恢复'), (self.dav_tab, 'WebDAV'), (self.log_tab, '操作记录')]:
            self.notebook.add(frame, text=title)
        self.make_backup_tab()
        self.make_restore_tab()
        self.make_dav_tab()
        self.log_box = ScrolledText(self.log_tab, font=('Consolas', 10), state='disabled', relief='flat')
        self.button(self.log_tab, '检查并清理遗留临时文件', self.check_temp_files).pack(anchor='w', pady=(0, 8))
        self.log_box.pack(fill='both', expand=True)
        self.progress = ttk.Progressbar(outer, mode='indeterminate')
        # Reserve the footer before allocating the notebook's expanding area.
        # Otherwise Tk clips status feedback at common Windows display scales.
        footer_status = ttk.Label(outer, textvariable=self.status, style='Hint.TLabel')
        footer_status.pack(side='bottom', anchor='w', fill='x', pady=(7, 0), before=self.notebook)
        self.progress.pack(side='bottom', fill='x', before=self.notebook)
        self.profile.trace_add('write', lambda *_: self.invalidate_preview())
        self.archive.trace_add('write', lambda *_: self.invalidate_preview())
        self.restore_password.trace_add('write', lambda *_: self.invalidate_preview())
        root.protocol('WM_DELETE_WINDOW', self.close)
        root.after(100, self.poll_queue)
        root.after(60_000, self.scheduler)
        root.after(500, self.check_temp_files)
        self.refresh_local()
        if warning: self.log(warning)
        if not profile or not exe: self.log('未识别到有效的 Joplin 配置目录或程序路径，请参照示例手动选择。')
        if profile and (Path(profile) / 'plugin-vault-recovery.json').exists():
            self.log('检测到未完成的恢复记录。请保留配置目录，并按使用说明执行“恢复中断处理”。')

    def button(self, parent, text, command):
        item = ttk.Button(parent, text=text, command=command)
        self.buttons.append(item)
        return item

    def make_backup_tab(self):
        p = self.backup_tab
        p.columnconfigure(1, weight=1)
        ttk.Label(p, text='备份目录').grid(row=0, column=0, sticky='w', padx=(0, 12))
        ttk.Entry(p, textvariable=self.folder).grid(row=0, column=1, sticky='ew')
        self.button(p, '选择目录', self.choose_folder).grid(row=0, column=2, padx=(8, 0))
        passwords = ttk.Frame(p)
        passwords.grid(row=1, column=0, columnspan=3, sticky='ew', pady=12)
        ttk.Label(passwords, text='备份密码').pack(side='left')
        ttk.Entry(passwords, textvariable=self.password, show='●', width=24).pack(side='left', padx=(10, 18))
        ttk.Label(passwords, text='确认密码').pack(side='left')
        ttk.Entry(passwords, textvariable=self.confirm_password, show='●', width=24).pack(side='left', padx=10)
        options = ttk.Frame(p)
        options.grid(row=2, column=0, columnspan=3, sticky='ew')
        ttk.Checkbutton(options, text='允许明文备份（空密码，需确认）', variable=self.plain_backup).pack(side='left')
        ttk.Label(options, text='默认加密；密码至少 8 位，不会保存。', style='Hint.TLabel').pack(side='left', padx=12)
        actions = ttk.Frame(p)
        actions.grid(row=3, column=0, columnspan=3, sticky='ew', pady=12)
        self.button(actions, '创建完整插件备份', self.backup).pack(side='left')
        ttk.Checkbutton(actions, text='完成后上传 WebDAV', variable=self.upload).pack(side='left', padx=18)
        self.button(actions, '保存偏好设置', self.save_preferences).pack(side='right')
        timer = ttk.Frame(p)
        timer.grid(row=4, column=0, columnspan=3, sticky='ew', pady=(0, 10))
        ttk.Checkbutton(timer, text='定时备份', variable=self.schedule).pack(side='left')
        ttk.Label(timer, text='每').pack(side='left', padx=(18, 5))
        ttk.Spinbox(timer, from_=1, to=720, textvariable=self.hours, width=5).pack(side='left')
        ttk.Label(timer, text='小时；仅在本程序运行且 Joplin 已退出时执行，需填写备份密码。', style='Hint.TLabel').pack(side='left', padx=5)
        head = ttk.Frame(p)
        head.grid(row=5, column=0, columnspan=3, sticky='ew', pady=(10, 5))
        ttk.Label(head, text='本地历史备份').pack(side='left')
        self.button(head, '刷新列表', self.refresh_local).pack(side='right')
        self.local_tree = self.tree(p)
        self.local_tree.grid(row=6, column=0, columnspan=3, sticky='nsew')
        p.rowconfigure(6, weight=1)
        foot = ttk.Frame(p)
        foot.grid(row=7, column=0, columnspan=3, sticky='ew', pady=(10, 0))
        self.button(foot, '选择用于恢复', self.select_local).pack(side='left')
        self.button(foot, '上传所选备份', self.upload_selected).pack(side='left', padx=10)
        ttk.Label(foot, text='正式备份和恢复前，请从“文件 → 退出”完全关闭 Joplin。', style='Hint.TLabel').pack(side='right')

    def make_restore_tab(self):
        p = self.restore_tab
        p.columnconfigure(1, weight=1)
        ttk.Label(p, text='备份文件').grid(row=0, column=0, sticky='w', padx=(0, 12))
        ttk.Entry(p, textvariable=self.archive).grid(row=0, column=1, sticky='ew')
        self.button(p, '选择文件', self.choose_archive).grid(row=0, column=2, padx=(8, 0))
        fields = ttk.Frame(p)
        fields.grid(row=1, column=0, columnspan=3, sticky='ew', pady=12)
        fields.columnconfigure(1, weight=1)
        ttk.Label(fields, text='解密 / 快照密码').grid(row=0, column=0, sticky='w')
        ttk.Entry(fields, textvariable=self.restore_password, show='●', width=32).grid(row=0, column=1, sticky='ew', padx=12)
        self.button(fields, '校验备份并预览', self.preview_restore).grid(row=0, column=2)
        ttk.Label(fields, text='旧明文备份也需填写，用于加密恢复前快照。', style='Hint.TLabel').grid(row=1, column=0, columnspan=3, sticky='w', pady=(6, 0))
        self.preview_box = ScrolledText(p, font=('Microsoft YaHei UI', 10), state='disabled', wrap='word', relief='flat')
        self.preview_box.grid(row=2, column=0, columnspan=3, sticky='nsew')
        p.rowconfigure(2, weight=1)
        actions = ttk.Frame(p)
        actions.grid(row=3, column=0, columnspan=3, sticky='ew', pady=(12, 0))
        self.restore_button = self.button(actions, '恢复到上方配置目录', self.restore)
        self.restore_button.pack(side='left')
        self.restore_button.configure(state='disabled')
        ttk.Label(actions, text='自动留存恢复前快照；保留目标笔记、账号和笔记同步配置。', style='Hint.TLabel').pack(side='left', padx=16)
        self.button(p, '修复中断的恢复（还原恢复前快照）', self.recover_interrupted).grid(row=4, column=0, columnspan=3, sticky='w', pady=(10, 0))

    def make_dav_tab(self):
        p = self.dav_tab
        p.columnconfigure(1, weight=1)
        for row, title, variable, masked in [(0, '专用备份文件夹 URL', self.dav_url, False), (1, '用户名', self.dav_user, False), (2, '密码 / 应用密码', self.dav_password, True)]:
            ttk.Label(p, text=title).grid(row=row, column=0, sticky='w', padx=(0, 12), pady=5)
            ttk.Entry(p, textvariable=variable, show='●' if masked else '').grid(row=row, column=1, columnspan=2, sticky='ew', pady=5)
        ttk.Label(p, text='使用独立备份子目录，例如 https://nas.example/dav/joplin-plugin-backups/，与笔记同步目录分开。', style='Hint.TLabel').grid(row=3, column=0, columnspan=3, sticky='w', pady=5)
        options = ttk.Frame(p)
        options.grid(row=4, column=0, columnspan=3, sticky='ew', pady=10)
        ttk.Checkbutton(options, text='在本机记住 WebDAV 密码', variable=self.remember).pack(side='left')
        self.button(options, '保存连接设置', self.save_preferences).pack(side='left', padx=10)
        self.button(options, '测试读写连接', self.test_dav).pack(side='left')
        self.button(options, '刷新远程备份', self.refresh_remote).pack(side='right')
        self.remote_tree = self.tree(p)
        self.remote_tree.grid(row=5, column=0, columnspan=3, sticky='nsew')
        p.rowconfigure(5, weight=1)
        self.button(p, '下载所选备份并进入恢复', self.download_selected).grid(row=6, column=0, columnspan=3, sticky='w', pady=(12, 0))

    def tree(self, parent):
        tree = ttk.Treeview(parent, columns=('name', 'size', 'modified'), show='headings', selectmode='browse', height=7)
        for key, title, width in [('name', '备份文件', 530), ('size', '大小', 90), ('modified', '时间', 200)]:
            tree.heading(key, text=title); tree.column(key, width=width, minwidth=70)
        return tree

    def choose_profile(self):
        value = filedialog.askdirectory(title='选择 Joplin 配置目录', initialdir=self.profile.get())
        if value: self.profile.set(value)

    def detect_paths(self):
        profile, exe, profiles = initial_paths({})
        self.profile.set(profile); self.exe.set(exe)
        self.profile_box.configure(values=[p[1] for p in profiles])
        self.log('已重新识别当前电脑路径。' + ('未识别到的字段已留空，请手动选择。' if not profile or not exe else '可核对后选择其他配置。'))

    def choose_folder(self):
        value = filedialog.askdirectory(title='选择备份存储目录', initialdir=self.folder.get())
        if value: self.folder.set(value); self.refresh_local()

    def choose_exe(self):
        value = filedialog.askopenfilename(title='选择 Joplin.exe', filetypes=[('Joplin 程序', '*.exe')])
        if value: self.exe.set(value)

    def choose_archive(self):
        value = filedialog.askopenfilename(title='选择插件环境备份', filetypes=[('插件备份', '*.jpv.zip *.jpv.enc'), ('所有文件', '*.*')])
        if value: self.archive.set(value)

    def config(self):
        return {'profile': self.profile.get(), 'joplin_exe': self.exe.get(), 'folder': self.folder.get(),
                'dav_url': self.dav_url.get(), 'dav_user': self.dav_user.get(), 'upload': self.upload.get(),
                'schedule': self.schedule.get(), 'hours': max(1, self.hours.get())}

    def save_preferences(self, quiet=False):
        try:
            save(self.config(), self.dav_password.get(), self.remember.get())
            if not quiet: self.log('偏好设置已保存。备份密码未保存。')
        except Exception as exc: messagebox.showerror('保存失败', str(exc))

    def dav(self):
        return WebDav(self.dav_url.get(), self.dav_user.get(), self.dav_password.get())

    def log(self, text):
        text = redact_log(text)
        stamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        line = f'[{stamp}] {text}\n'
        self.log_box.configure(state='normal'); self.log_box.insert('end', line); self.log_box.see('end'); self.log_box.configure(state='disabled')
        self.status.set(text)
        try:
            with (self.home / 'operations.log').open('a', encoding='utf-8') as f: f.write(line)
        except OSError: pass

    def check_temp_files(self):
        if self.busy:
            return
        try:
            stale = stale_workspaces()
            if stale and messagebox.askyesno('遗留临时文件', f'发现 {len(stale)} 个未使用的临时目录，可能包含明文插件设置。\n\n清理这些临时文件？恢复记录及恢复前快照会保留。', icon='warning'):
                removed, skipped = cleanup_workspaces(stale)
                self.log(f'已清理 {removed} 个遗留临时目录；跳过 {skipped} 个正在使用或无法安全处理的目录。')
            legacy = legacy_workspaces(self.folder.get())
            if legacy:
                self.log(f'发现 {len(legacy)} 个旧版临时目录，请退出其他工具实例后手动检查。')
                messagebox.showwarning('旧版临时文件', '以下目录可能包含旧版遗留的明文数据。请先退出其他实例，再手动确认清理；程序不会自动删除。\n\n' + '\n'.join(map(str, legacy)))
        except OSError as exc:
            self.log('临时文件检查未完成：' + str(exc))

    def submit(self, label, action, done=None):
        if self.busy: return
        self.busy = True
        for button in self.buttons: button.configure(state='disabled')
        self.progress.start(12)
        self.log(label)
        def worker():
            try: self.queue.put(('ok', action(), done))
            except Exception as exc: self.queue.put(('error', str(exc) or type(exc).__name__, None))
        threading.Thread(target=worker, daemon=True).start()

    def poll_queue(self):
        try:
            while True:
                kind, result, done = self.queue.get_nowait()
                self.busy = False
                self.progress.stop()
                for button in self.buttons: button.configure(state='normal')
                self.restore_button.configure(state='normal' if self.preview else 'disabled')
                if kind == 'error':
                    self.log('操作失败：' + result)
                    messagebox.showerror('操作未完成', result)
                elif done:
                    done(result)
        except queue.Empty: pass
        self.root.after(100, self.poll_queue)

    def inspect(self):
        profile, exe = self.profile.get(), self.exe.get()
        def finished(result):
            manifest, _ = result
            text = self.describe_manifest(manifest)
            dialog = tk.Toplevel(self.root); dialog.title('当前插件清单（只读）'); dialog.geometry('820x600')
            box = ScrolledText(dialog, wrap='word', font=('Microsoft YaHei UI', 10)); box.pack(fill='both', expand=True, padx=16, pady=16)
            box.insert('1.0', text); box.configure(state='disabled')
            self.log(f'读取完成：{len(manifest["plugins"])} 个插件包，{len(manifest["settings_database"])} 项数据库插件设置。')
        self.submit('正在读取当前插件环境……', lambda: inventory(Layout.discover(profile), exe), finished)

    def describe_manifest(self, manifest):
        lines = [f'备份时间：{manifest["created_utc"]}', f'插件包：{len(manifest["plugins"])} 个；数据库设置：{len(manifest["settings_database"])} 项', '']
        for plugin in manifest['plugins']:
            state = '已删除标记' if plugin.get('deleted') else ('启用' if plugin['enabled'] else '停用')
            lines.append(f'{plugin["name"]}  {plugin["version"]}  [{state}]' + ('  内建包' if plugin.get('bundled') else ''))
            lines.append('  ' + plugin['id'])
        lines += ['', *manifest.get('warnings', [])]
        return '\n'.join(lines)

    def backup(self, scheduled=False):
        try:
            password = self.password.get()
            if password != self.confirm_password.get(): raise VaultError('两次备份密码不一致。')
            allow_unencrypted = self.plain_backup.get() and not scheduled
            validate_backup_password(password, allow_unencrypted)
            if scheduled: self.engine.guard()
            profile, folder, exe = self.profile.get(), self.folder.get(), self.exe.get()
            if not folder: raise VaultError('请选择本地备份目录。')
            dav = self.dav() if self.upload.get() else None
            if not password:
                destination = '本地目录并上传 WebDAV' if dav else '本地目录'
                if not messagebox.askyesno('确认明文备份', f'插件设置及插件数据可能含 API 密钥、登录信息等敏感内容。\n明文备份可被直接读取，请确认备份目录可信且访问权限受限。\n\n仍将明文备份保存到{destination}？', icon='warning'): return
            self.save_preferences(quiet=True)
        except Exception as exc:
            if scheduled: self.log('定时备份跳过：' + str(exc))
            else: messagebox.showerror('无法开始备份', str(exc))
            return
        def action():
            path = self.engine.backup(profile, folder, password, exe, allow_unencrypted=allow_unencrypted)
            if dav:
                try: dav.upload(path)
                except Exception as exc: return path, '本地备份已成功，WebDAV 上传失败：' + str(exc)
            return path, ''
        def finished(result):
            path, warning = result
            self.last_backup = time.time(); self.refresh_local()
            self.log(warning if warning else '备份成功：' + path.name + ('；WebDAV 上传完成。' if dav else ''))
            if warning: messagebox.showwarning('本地备份已保留', warning)
        self.submit('正在创建插件环境备份……', action, finished)

    def fill_tree(self, tree, entries):
        tree.delete(*tree.get_children())
        for entry in entries: tree.insert('', 'end', values=(entry['name'], size_text(entry['size']), entry['modified']))

    def refresh_local(self):
        try: self.fill_tree(self.local_tree, list_local(self.folder.get()))
        except Exception as exc: self.log('无法读取本地备份列表：' + str(exc))

    def selected(self, tree):
        values = tree.selection()
        if not values: raise VaultError('请先在列表中选择一份备份。')
        return tree.item(values[0], 'values')[0]

    def select_local(self):
        try:
            self.archive.set(str(Path(self.folder.get()) / self.selected(self.local_tree)))
            self.notebook.select(self.restore_tab)
        except Exception as exc: messagebox.showinfo('选择备份', str(exc))

    def invalidate_preview(self):
        self.preview = None
        if hasattr(self, 'restore_button'): self.restore_button.configure(state='disabled')

    def preview_restore(self):
        profile, archive, password = self.profile.get(), self.archive.get(), self.restore_password.get()
        if not archive: messagebox.showinfo('选择备份', '请先选择备份文件。'); return
        def finished(preview):
            # Do not attach a completed preview to inputs edited during work.
            if (profile, archive, password) != (self.profile.get(), self.archive.get(), self.restore_password.get()):
                self.log('输入已变化，请重新预览。'); return
            self.preview = preview
            text = f'恢复目标：{preview["target"]}\n\n' + self.describe_manifest(preview['manifest'])
            text += f'\n\n新增：{len(preview["install"])}；替换：{len(preview["replace"])}；移除目标额外插件：{len(preview["remove"])}。'
            if preview['remove']: text += '\n将移除：' + '、'.join(preview['remove'])
            if preview['shared_plugins']: text += '\n注意：此配置的插件安装包与同一根目录下的其他配置共享。'
            text += '\n\n恢复会整体替换插件安装目录和此配置的插件数据，插件设置按快照还原；笔记和笔记同步配置保留。'
            self.preview_box.configure(state='normal'); self.preview_box.delete('1.0', 'end'); self.preview_box.insert('1.0', text); self.preview_box.configure(state='disabled')
            self.restore_button.configure(state='normal')
            self.log('备份校验通过。请核对目标和变更清单，再执行恢复。')
        self.submit('正在解密、校验备份并生成恢复预览……', lambda: self.engine.preview(archive, profile, password), finished)

    def restore(self):
        if not self.preview: return
        try:
            validate_backup_password(self.restore_password.get())
        except VaultError:
            messagebox.showerror('需要快照密码', '请在“解密 / 快照密码”中填写至少 8 位密码。\n旧明文备份也需填写，用于加密恢复前快照，然后重新预览。')
            return
        preview = self.preview
        if not messagebox.askyesno('确认恢复插件环境', f'恢复目标：\n{preview["target"]}\n\n恢复 {len(preview["manifest"]["plugins"])} 个插件包及其设置和数据。\n移除目标额外插件 {len(preview["remove"])} 个。\n\n会先创建恢复前快照。请确认 Joplin 已完全退出。\n\n执行恢复？', icon='warning'): return
        archive, profile, password, exe = self.archive.get(), self.profile.get(), self.restore_password.get(), self.exe.get()
        recovery = self.home / 'recovery'
        def finished(result):
            self.invalidate_preview()
            self.log(f'恢复完成：{result["plugins"]} 个插件包，{result["settings"]} 项数据库设置。恢复前快照：{Path(result["recovery_backup"]).name}')
            messagebox.showinfo('恢复完成', '插件环境已恢复，可以启动 Joplin。\n\n需要重新登录或调整路径的项目请参见预览中的提示。')
        self.submit('正在留存恢复前快照并恢复插件环境……', lambda: self.engine.restore(archive, profile, recovery, password, exe, preview['archive_sha256']), finished)

    def test_dav(self):
        try: dav = self.dav()
        except Exception as exc: messagebox.showerror('WebDAV', str(exc)); return
        self.submit('正在测试 WebDAV 创建、读取和删除临时文件……', dav.test, lambda count: self.log(f'WebDAV 读写测试通过；找到 {count} 份备份。'))

    def recover_interrupted(self):
        profile, password, exe = self.profile.get(), self.restore_password.get(), self.exe.get()
        if not (Path(profile) / 'plugin-vault-recovery.json').exists():
            messagebox.showinfo('恢复记录', '此配置目录没有未完成的恢复记录。'); return
        if not messagebox.askyesno('修复中断的恢复', '将从恢复记录中的“恢复前快照”还原插件环境。请先退出 Joplin。\n\n如果快照已加密，请先在解密密码框填写密码。\n\n执行修复？', icon='warning'): return
        self.submit('正在还原恢复前插件环境……',
                    lambda: self.engine.recover_interrupted(profile, password, exe),
                    lambda result: self.log('中断恢复已修复，插件环境回到恢复前状态。'))

    def refresh_remote(self):
        try: dav = self.dav()
        except Exception as exc: messagebox.showerror('WebDAV', str(exc)); return
        def finished(entries):
            self.fill_tree(self.remote_tree, entries); self.log(f'远程列表已更新：{len(entries)} 份备份。')
        self.submit('正在获取 WebDAV 备份列表……', dav.list, finished)

    def upload_selected(self):
        try:
            path = Path(self.folder.get()) / self.selected(self.local_tree)
            dav = self.dav()
            if path.suffix == '.zip' and not messagebox.askyesno('未加密备份', '这份备份未加密，仍上传到 WebDAV？'): return
        except Exception as exc: messagebox.showinfo('上传备份', str(exc)); return
        self.submit('正在上传备份到 WebDAV……', lambda: dav.upload(path), lambda _: self.log('WebDAV 上传完成。'))

    def download_selected(self):
        try: name, dav = self.selected(self.remote_tree), self.dav()
        except Exception as exc: messagebox.showinfo('下载备份', str(exc)); return
        def finished(path):
            self.archive.set(str(path)); self.notebook.select(self.restore_tab)
            self.log('下载完成，请输入解密密码并预览：' + path.name)
        self.submit('正在下载所选 WebDAV 备份……', lambda: dav.download(name, self.home / 'downloads'), finished)

    def launch_joplin(self):
        path = Path(self.exe.get())
        if not path.is_file() or path.name.lower() != 'joplin.exe': messagebox.showerror('启动 Joplin', '请先选择有效的 Joplin.exe。'); return
        subprocess.Popen([str(path)])
        self.log('已启动 Joplin。')

    def scheduler(self):
        try:
            due = time.time() - self.last_backup >= max(1, self.hours.get()) * 3600
            if self.schedule.get() and due and not self.busy and time.time() - self.last_schedule_attempt >= 900:
                self.last_schedule_attempt = time.time(); self.backup(scheduled=True)
        finally: self.root.after(60_000, self.scheduler)

    def close(self):
        if self.busy: messagebox.showinfo('操作进行中', '请等待当前操作完成后再关闭程序。'); return
        self.root.destroy()


def run():
    root = tk.Tk()
    App(root)
    root.mainloop()
