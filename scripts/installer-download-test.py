#!/usr/bin/env python3
"""Exercise the actual bootstrap downloader against a local HTTPS fault server."""
import hashlib
import http.server
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = b'complete pinned download\n' * 100
PIN = hashlib.sha256(PAYLOAD).hexdigest()


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        count = self.server.hits.get(self.path, 0) + 1
        self.server.hits[self.path] = count
        if self.path == '/fail':
            self.send_error(503)
            return
        self.send_response(200)
        self.send_header('Content-Length', str(len(PAYLOAD)))
        self.end_headers()
        if self.path == '/stall' or (self.path == '/idle-once' and count == 1):
            self.wfile.flush()
            self.server.stop_fault.wait(35)
            return
        if self.path == '/partial-once' and count == 1:
            self.wfile.write(PAYLOAD[:7])
            self.wfile.flush()
            self.close_connection = True
            return
        self.wfile.write(PAYLOAD)


class DownloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='cmrm-download-test-')
        cls.base = Path(cls.directory.name)
        cls.cert = cls.base / 'server.crt'
        key = cls.base / 'server.key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-days', '1', '-subj', '/CN=127.0.0.1', '-addext',
                        'subjectAltName=IP:127.0.0.1', '-keyout', str(key),
                        '-out', str(cls.cert)], check=True, capture_output=True)
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.server.hits = {}
        cls.server.stop_fault = threading.Event()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.cert, key)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = 'https://127.0.0.1:' + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop_fault.set()
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.directory.cleanup()

    def setUp(self):
        self.out = self.base / self.id().rsplit('.', 1)[-1]
        self.out.write_bytes(b'previous-valid-file')

    def download(self, paths, *, pin=PIN, limit=10000, budget=8, trust=True):
        env = {k: v for k, v in os.environ.items()
               if k.lower() not in ('http_proxy', 'https_proxy', 'all_proxy')}
        env['CMRM_IP_VERSION'] = 'auto'
        if trust:
            env['CURL_CA_BUNDLE'] = str(self.cert)
        else:
            for name in ('CURL_CA_BUNDLE', 'SSL_CERT_FILE', 'SSL_CERT_DIR'):
                env.pop(name, None)
        command = 'source "$1"; shift; cmrm_download fixture "$@"'
        return subprocess.run(['bash', '-c', command, 'fixture', str(ROOT / 'install.sh'),
                               str(self.out), str(limit), pin, str(budget),
                               *(self.origin + p for p in paths)],
                              env=env, text=True, capture_output=True, timeout=budget + 5)

    def assert_preserved(self):
        self.assertEqual(self.out.read_bytes(), b'previous-valid-file')
        self.assertEqual(list(self.base.glob(self.out.name + '.part.*')), [])

    def test_verified_success(self):
        result = self.download(['/success'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.out.read_bytes(), PAYLOAD)

    def test_partial_transfer_retries_without_appending(self):
        result = self.download(['/partial-once'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.out.read_bytes(), PAYLOAD)
        self.assertEqual(self.server.hits['/partial-once'], 2)
        self.assertIn('ipv4-http1', result.stdout)

    def test_alternate_source_after_http_failure(self):
        result = self.download(['/fail', '/success'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.out.read_bytes(), PAYLOAD)

    def test_global_deadline_preserves_existing_file(self):
        start = time.monotonic()
        result = self.download(['/stall', '/success'], budget=2)
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(time.monotonic() - start, 5)
        self.assert_preserved()

    def test_twenty_second_idle_transfer_recovers(self):
        start = time.monotonic()
        result = self.download(['/idle-once'], budget=26)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreaterEqual(time.monotonic() - start, 19)
        self.assertLess(time.monotonic() - start, 26)
        self.assertEqual(self.out.read_bytes(), PAYLOAD)

    def test_checksum_failure_preserves_existing_file(self):
        result = self.download(['/success'], pin='0' * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Checksum mismatch', result.stderr)
        self.assert_preserved()

    def test_size_limit_preserves_existing_file(self):
        result = self.download(['/success'], limit=5)
        self.assertNotEqual(result.returncode, 0)
        self.assert_preserved()

    def test_tls_failure_preserves_existing_file(self):
        result = self.download(['/success'], trust=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('curl: (60)', result.stderr)
        self.assert_preserved()

    def test_dependency_download_entrypoint(self):
        env = dict(os.environ, CURL_CA_BUNDLE=str(self.cert), CMRM_IP_VERSION='4')
        result = subprocess.run(['bash', str(ROOT / 'install.sh'), '--download',
                                 self.origin + '/success', str(self.out), '10000', PIN],
                                env=env, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.out.read_bytes(), PAYLOAD)


if __name__ == '__main__':
    unittest.main()
