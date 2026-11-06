import base64
import contextlib
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from xml.sax.saxutils import escape

from vault.core import VaultError
from vault.webdav import WebDav


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_): pass

    def reply(self, code, data=b'', **headers):
        self.send_response(code)
        self.send_header('Content-Length', str(len(data)))
        for key, value in headers.items(): self.send_header(key.replace('_', '-'), value)
        self.end_headers()
        if self.command != 'HEAD': self.wfile.write(data)

    def auth(self):
        if self.headers.get('Authorization') != 'Basic ' + base64.b64encode(b'user:secret').decode():
            self.reply(401); return False
        if self.path.startswith('/redirect/'):
            self.reply(302, Location='http://127.0.0.1:1/do-not-follow'); return False
        return True

    def do_MKCOL(self):
        if not self.auth(): return
        if self.path in self.server.collections: self.reply(405)
        else: self.server.collections.add(self.path); self.reply(201)

    def do_PUT(self):
        if not self.auth():
            self.close_connection = True; return
        data = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        self.server.files[self.path] = data
        self.reply(201)

    def do_MOVE(self):
        if not self.auth(): return
        if self.server.fail_move: self.reply(500); return
        destination = urllib.parse.urlsplit(self.headers['Destination']).path
        if destination in self.server.files and self.headers.get('Overwrite') == 'F': self.reply(412); return
        self.server.files[destination] = self.server.files.pop(self.path)
        self.reply(201)

    def do_DELETE(self):
        if not self.auth(): return
        if self.path not in self.server.files: self.reply(404); return
        del self.server.files[self.path]; self.reply(204)

    def do_GET(self):
        if not self.auth(): return
        if self.path not in self.server.files: self.reply(404); return
        if self.command == 'GET': self.server.get_requests.append(self.path)
        self.reply(200, self.server.files[self.path])

    def do_HEAD(self):
        if self.server.head_mode == 'normal': self.do_GET(); return
        if not self.auth(): return
        if self.server.head_mode in ['405', '501']:
            self.reply(int(self.server.head_mode)); return
        self.send_response(200)
        if self.server.head_mode == 'wrong': self.send_header('Content-Length', '0')
        if self.server.head_mode == 'invalid': self.send_header('Content-Length', 'unknown')
        self.end_headers()

    def do_PROPFIND(self):
        if not self.auth(): return
        self.rfile.read(int(self.headers.get('Content-Length', 0)))
        if self.server.prop_mode == 'unsupported': self.reply(405); return
        entries = [f'<d:response><d:href>{escape(path if self.server.prop_mode != "wrong_href" else path + ".other")}</d:href><d:propstat><d:prop><d:getcontentlength>{len(value) if self.server.prop_mode == "normal" or self.server.prop_mode == "wrong_href" else ""}</d:getcontentlength><d:getlastmodified>Fri, 06 Nov 2026 00:00:00 GMT</d:getlastmodified><d:resourcetype/></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>'
                   for path, value in self.server.files.items() if path.startswith(self.path)]
        # An absolute external href must never become a downloadable entry.
        entries.append('<d:response><d:href>https://attacker.invalid/backups/joplin-plugins-20261106T000000Z-ffffffff.jpv.zip</d:href></d:response>')
        data = ('<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">' + ''.join(entries) + '</d:multistatus>').encode()
        self.reply(207, data, Content_Type='application/xml')


class WebDavTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.server.daemon_threads = True
        cls.server.files = {}; cls.server.collections = set(); cls.server.fail_move = False
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True); cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()

    def setUp(self):
        self.server.files.clear(); self.server.collections.clear(); self.server.fail_move = False
        self.server.head_mode = 'normal'; self.server.prop_mode = 'normal'; self.server.get_requests = []
        self.temp = tempfile.TemporaryDirectory(prefix='jpv-dav-test-')
        self.root = Path(self.temp.name)
        self.base = f'http://127.0.0.1:{self.server.server_port}/测试/backups/'
        self.dav = WebDav(self.base, 'user', 'secret', timeout=5)

    def tearDown(self): self.temp.cleanup()

    def backup_file(self):
        path = self.root / 'joplin-plugins-20261106T000000Z-01234567.jpv.enc'
        path.write_bytes(bytes(range(256)) * 10000)
        return path

    def test_connection_probe_is_removed(self):
        self.assertEqual(self.dav.test(), 0)
        self.assertFalse(self.server.files)

    def test_streaming_upload_list_download_roundtrip(self):
        path = self.backup_file()
        self.dav.upload(path)
        entries = self.dav.list()
        self.assertEqual([x['name'] for x in entries], [path.name])
        self.assertEqual(entries[0]['size'], path.stat().st_size)
        downloaded = self.dav.download(path.name, self.root / 'downloads')
        self.assertEqual(path.read_bytes(), downloaded.read_bytes())
        self.assertFalse(any('.partial' in name for name in self.server.files))

    def test_atomic_publish_failure_has_no_completed_or_partial_remote_file(self):
        self.server.fail_move = True
        with self.assertRaises(VaultError): self.dav.upload(self.backup_file())
        self.assertFalse(self.server.files)

    def test_upload_without_head_length_uses_exact_file_dav_property(self):
        self.server.head_mode = 'missing'
        path = self.backup_file()
        self.dav.upload(path)
        self.assertEqual(self.server.files[urllib.parse.urlsplit(self.dav.url(path.name)).path], path.read_bytes())
        self.assertFalse(self.server.get_requests)

    def test_unsupported_head_uses_dav_property(self):
        path = self.backup_file(); self.dav.upload(path)
        for mode in ['405', '501']:
            with self.subTest(mode=mode):
                self.server.head_mode = mode
                self.dav.verify_upload(path)
        self.assertFalse(self.server.get_requests)

    def test_invalid_or_inaccurate_head_length_uses_dav_property(self):
        path = self.backup_file(); self.dav.upload(path)
        for mode in ['invalid', 'wrong']:
            with self.subTest(mode=mode):
                self.server.head_mode = mode
                self.dav.verify_upload(path)
        self.assertFalse(self.server.get_requests)

    def test_missing_or_unsupported_dav_length_falls_back_to_get_hash(self):
        path = self.backup_file(); self.dav.upload(path)
        self.server.head_mode = 'missing'
        for mode in ['missing', 'unsupported', 'wrong_href']:
            with self.subTest(mode=mode):
                self.server.prop_mode = mode
                self.server.get_requests.clear()
                self.dav.verify_upload(path)
                self.assertEqual(len(self.server.get_requests), 1)

    def test_get_fallback_rejects_same_length_corruption(self):
        path = self.backup_file(); self.dav.upload(path)
        remote = urllib.parse.urlsplit(self.dav.url(path.name)).path
        self.server.files[remote] = b'x' + self.server.files[remote][1:]
        self.server.head_mode = 'missing'; self.server.prop_mode = 'unsupported'
        with self.assertRaisesRegex(VaultError, '内容校验失败'):
            self.dav.verify_upload(path)
        self.assertTrue(path.exists())
        self.assertIn(remote, self.server.files)

    def test_get_fallback_rejects_truncated_file(self):
        path = self.backup_file(); self.dav.upload(path)
        remote = urllib.parse.urlsplit(self.dav.url(path.name)).path
        self.server.files[remote] = self.server.files[remote][:-1]
        self.server.head_mode = 'missing'; self.server.prop_mode = 'missing'
        with self.assertRaisesRegex(VaultError, '内容校验失败'):
            self.dav.verify_upload(path)

    def test_same_name_is_not_overwritten(self):
        path = self.backup_file(); self.dav.upload(path)
        before = dict(self.server.files)
        with self.assertRaises(VaultError): self.dav.upload(path)
        self.assertEqual(before, self.server.files)

    def test_authentication_failure_is_clear_and_does_not_expose_password(self):
        with self.assertRaises(VaultError) as error:
            WebDav(self.base, 'user', 'wrong-secret', timeout=5).list()
        self.assertNotIn('wrong-secret', str(error.exception))
        self.assertIn('认证', str(error.exception))

    def test_redirect_is_not_followed(self):
        with self.assertRaises(VaultError) as error:
            WebDav(f'http://127.0.0.1:{self.server.server_port}/redirect/', 'user', 'secret', timeout=5).list()
        self.assertIn('302', str(error.exception))

    def test_embedded_credentials_and_traversal_are_rejected(self):
        for url in ['https://user:secret@example.invalid/dav/', 'https://example.invalid/dav/../notes/', 'ftp://example.invalid/dav/']:
            with self.assertRaises(VaultError): WebDav(url)
        with self.assertRaises(VaultError): self.dav.download('../notes', self.root)


if __name__ == '__main__': unittest.main()
