from __future__ import annotations

import base64
import hashlib
import os
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

from .core import BACKUP_NAME, CHUNK, VaultError, digest


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class WebDav:
    def __init__(self, url, username='', password='', timeout=90):
        parts = urllib.parse.urlsplit(url.strip())
        if parts.scheme not in ['http', 'https'] or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
            raise VaultError('请填写不带账号、密码、查询参数的完整 WebDAV 文件夹 URL。')
        decoded = urllib.parse.unquote(parts.path)
        if any(x in ['.', '..'] for x in decoded.split('/')):
            raise VaultError('WebDAV 地址包含无效路径。')
        self.base = urllib.parse.urlunsplit((parts.scheme, parts.netloc, urllib.parse.quote(decoded.rstrip('/') + '/', safe='/'), '', ''))
        self.parts = urllib.parse.urlsplit(self.base)
        self.timeout = timeout
        self.opener = urllib.request.build_opener(NoRedirect())
        self.auth = 'Basic ' + base64.b64encode((username + ':' + password).encode()).decode() if username else ''

    def url(self, name=''):
        if name and ('/' in name or '\\' in name or name in ['.', '..']):
            raise VaultError('无效的远程备份文件名。')
        return self.base + urllib.parse.quote(name, safe='')

    def request(self, method, url=None, data=None, headers=None, allowed=()):
        request_headers = {'User-Agent': 'JoplinPluginVault/1.0', **(headers or {})}
        if self.auth:
            request_headers['Authorization'] = self.auth
        req = urllib.request.Request(url or self.base, data=data, headers=request_headers, method=method)
        try:
            return self.opener.open(req, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            if exc.code in allowed:
                return exc
            exc.close()
            messages = {401: 'WebDAV 认证失败，请检查账号或密码。', 403: 'WebDAV 拒绝访问，请检查目录权限。',
                        404: 'WebDAV 目录或备份不存在。', 405: '服务器不支持所需 WebDAV 方法。',
                        412: '远程已存在同名文件，未覆盖。', 507: 'WebDAV 存储空间不足。'}
            raise VaultError(messages.get(exc.code, f'WebDAV 请求失败（HTTP {exc.code}）。地址若发生重定向，请填写最终文件夹 URL。')) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise VaultError('无法连接 WebDAV，请检查地址、网络和 HTTPS 证书。') from None

    def ensure_collection(self):
        # A user-selected dedicated folder may not exist yet. Create its
        # ancestors using MKCOL, never write files in the note sync namespace.
        parts = [x for x in self.parts.path.split('/') if x]
        prefix = ''
        for part in parts:
            prefix += '/' + part
            url = urllib.parse.urlunsplit((self.parts.scheme, self.parts.netloc, prefix + '/', '', ''))
            with self.request('MKCOL', url, data=b'', allowed=(405,)):
                pass

    def properties(self, url=None, depth='1'):
        body = b'<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/><d:getcontentlength/><d:getlastmodified/></d:prop></d:propfind>'
        with self.request('PROPFIND', url, data=body, headers={'Depth': depth, 'Content-Type': 'application/xml'}) as response:
            raw = response.read(10 * CHUNK + 1)
        if len(raw) > 10 * CHUNK or b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
            raise VaultError('WebDAV 目录响应无效。')
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            raise VaultError('服务器未返回有效 WebDAV 目录，请检查是否填写了文件夹地址。') from None
        return root

    def list(self):
        root = self.properties()
        entries = []
        prefix = urllib.parse.unquote(self.parts.path)
        for item in root.findall('{DAV:}response'):
            href = item.findtext('{DAV:}href', '')
            resolved = urllib.parse.urlsplit(urllib.parse.urljoin(self.base, href))
            if (resolved.scheme, resolved.netloc) != (self.parts.scheme, self.parts.netloc): continue
            path = urllib.parse.unquote(resolved.path)
            if not path.startswith(prefix): continue
            name = path[len(prefix):]
            if not BACKUP_NAME.fullmatch(name): continue
            for propstat in item.findall('{DAV:}propstat'):
                if ' 200 ' not in propstat.findtext('{DAV:}status', ''): continue
                prop = propstat.find('{DAV:}prop')
                if prop is None: continue
                if prop.find('{DAV:}resourcetype/{DAV:}collection') is not None: continue
                try: size = int(prop.findtext('{DAV:}getcontentlength', '0'))
                except ValueError: size = 0
                entries.append({'name': name, 'size': size, 'modified': prop.findtext('{DAV:}getlastmodified', '')})
                break
        return sorted(entries, key=lambda x: x['name'], reverse=True)

    def verify_upload(self, path):
        path = Path(path)
        expected = path.stat().st_size
        url = self.url(path.name)
        with self.request('HEAD', url, allowed=(405, 501)) as response:
            length = response.headers.get('Content-Length', '')
            if response.status == 200 and length.isascii() and length.isdecimal() and int(length) == expected:
                return

        # HEAD may omit Content-Length or be unsupported. Ask for the exact
        # file's DAV property before paying for a full download.
        try:
            root = self.properties(url, depth='0')
            target = urllib.parse.urlsplit(url)
            for item in root.findall('{DAV:}response'):
                href = urllib.parse.urlsplit(urllib.parse.urljoin(url, item.findtext('{DAV:}href', '')))
                if (href.scheme, href.netloc, urllib.parse.unquote(href.path)) != (target.scheme, target.netloc, urllib.parse.unquote(target.path)):
                    continue
                for propstat in item.findall('{DAV:}propstat'):
                    if ' 200 ' not in propstat.findtext('{DAV:}status', ''): continue
                    length = propstat.findtext('{DAV:}prop/{DAV:}getcontentlength', '')
                    if length.isascii() and length.isdecimal() and int(length) == expected:
                        return
        except VaultError:
            pass  # A successful GET can still establish integrity.

        remote_hash, size = hashlib.sha256(), 0
        with self.request('GET', url, headers={'Accept-Encoding': 'identity'}) as response:
            while data := response.read(CHUNK):
                remote_hash.update(data); size += len(data)
                if size > expected:
                    raise VaultError('远程备份内容校验失败，本地备份及远程文件已保留。')
        if size != expected or remote_hash.hexdigest() != digest(path):
            raise VaultError('远程备份内容校验失败，本地备份及远程文件已保留。')

    def test(self):
        self.ensure_collection()
        entries = self.list()
        name = '.jpv-connection-test-' + uuid.uuid4().hex
        payload = os.urandom(32)
        try:
            with self.request('PUT', self.url(name), data=payload, headers={'Content-Type': 'application/octet-stream', 'If-None-Match': '*'}): pass
            with self.request('GET', self.url(name)) as response:
                if response.read(33) != payload: raise VaultError('WebDAV 读写校验失败。')
        finally:
            with self.request('DELETE', self.url(name), allowed=(404,)): pass
        return len(entries)

    def upload(self, path):
        path = Path(path)
        if not BACKUP_NAME.fullmatch(path.name): raise VaultError('不是程序生成的备份文件名。')
        self.ensure_collection()
        temp_name = path.name + '.' + uuid.uuid4().hex + '.partial'
        try:
            with path.open('rb') as data:
                with self.request('PUT', self.url(temp_name), data=data,
                                  headers={'Content-Length': str(path.stat().st_size), 'Content-Type': 'application/octet-stream', 'If-None-Match': '*'}): pass
            with self.request('MOVE', self.url(temp_name), headers={'Destination': self.url(path.name), 'Overwrite': 'F'}): pass
            self.verify_upload(path)
        finally:
            with self.request('DELETE', self.url(temp_name), allowed=(404,)): pass

    def download(self, name, destination):
        if not BACKUP_NAME.fullmatch(name): raise VaultError('无效的远程备份文件名。')
        destination = Path(destination)
        destination.mkdir(parents=True, exist_ok=True)
        path = destination / name
        if path.exists():
            # Always download a fresh copy. Never trust an old local cache as
            # the selected remote backup.
            path = destination / (uuid.uuid4().hex + '-' + name)
        temp = path.with_name(path.name + '.partial')
        try:
            with self.request('GET', self.url(name)) as response, temp.open('xb') as dst:
                expected = response.headers.get('Content-Length')
                size = 0
                while data := response.read(CHUNK):
                    dst.write(data); size += len(data)
                if expected and size != int(expected): raise VaultError('WebDAV 下载不完整。')
            os.replace(temp, path)
        finally:
            temp.unlink(missing_ok=True)
        return path
