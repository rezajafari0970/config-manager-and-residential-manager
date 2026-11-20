"""Closed SOCKS/TLS fixtures for TestSideCapacity. This server has no forwarding path."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
from urllib.parse import urlsplit

scripts = Path(__file__).resolve().parents[3] / 'scripts'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, scripts / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def serve(directory):
    fixture = load('contracts', 'side-checks-test.py')
    driver = fixture.side
    urls = [x[0] for x in driver.SERVICES.values()] + [driver.WARP, driver.DOWN, driver.UP, driver.PING]
    hosts = {urlsplit(url).hostname for url in urls}
    cert, key = Path(directory) / 'cert.pem', Path(directory) / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                    'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1', '-subj',
                    '/CN=Closed fixture', '-addext', 'subjectAltName=' + ','.join(
                        'DNS:' + h for h in sorted(hosts)), '-keyout', key, '-out', cert],
                   check=True, capture_output=True)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)

    async def handle(reader, writer, mode):
        try:
            version, count = await reader.readexactly(2)
            if version != 5 or 0 not in await reader.readexactly(count):
                return
            writer.write(b'\x05\x00')
            if await reader.readexactly(4) != b'\x05\x01\x00\x03':
                return
            length = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(length)).decode()
            if host not in hosts or await reader.readexactly(2) != b'\x01\xbb':
                return
            writer.write(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x01\xbb')
            await writer.drain()
            await writer.start_tls(tls, ssl_handshake_timeout=8)
            header = (await reader.readuntil(b'\r\n\r\n')).decode().split('\r\n')
            method, path, _ = header[0].split()
            fields = {k.lower(): v.strip() for k, v in (line.split(':', 1) for line in header[1:] if line)}
            if fields.get('host') != host:
                return
            length = int(fields.get('content-length', '0'))
            if length < 0 or length > driver.UPLOAD_BYTES:
                return
            payload = await reader.readexactly(length)
            url = 'https://' + host + path
            if method != ('POST' if url == driver.UP else 'GET'):
                return
            body = fixture.fixture(url, 5, payload=payload)
            if url.startswith(driver.WARP + '?'):
                body = ('h=www.cloudflare.com\nwarp=' + mode + '\n').encode()
            status = 204 if url.startswith(driver.PING + '?') else 200
            mime = 'text/plain'
            if url.startswith(driver.DOWN + '?'):
                mime = 'application/octet-stream'
            for service, (target, types, _) in driver.SERVICES.items():
                if url == target:
                    mime = sorted(types)[0]
            writer.write(f'HTTP/1.1 {status} OK\r\nContent-Type: {mime}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode() + body)
            await writer.drain()
        except (OSError, ValueError, asyncio.IncompleteReadError, TimeoutError):
            pass
        finally:
            writer.close()

    servers = []
    for mode in ['on', 'off']:
        server = await asyncio.start_server(lambda r, w, mode=mode: handle(r, w, mode),
                                            '127.0.0.1', 0, backlog=512)
        servers.append(server)
    print(json.dumps([s.sockets[0].getsockname()[1] for s in servers]), flush=True)
    await asyncio.gather(*(s.serve_forever() for s in servers))


def run(port, directory):
    driver = load('checks', 'side-checks.py')
    adapter = load('adapter', 'side-one.py')
    driver.SOCKS_PORT = int(port)
    ca = os.path.join(directory, 'cert.pem')
    run_process = subprocess.run

    def trust_local_fixture(args, *a, **kw):
        if args[0] == '/usr/bin/curl':
            # curl --next resets per-transfer TLS options. Keep the real
            # curl/trailer checks and independent host verification enabled.
            updated = []
            for arg in args:
                if arg.startswith('https://'):
                    updated.extend(['--cacert', ca])
                updated.append(arg)
            args = updated
        return run_process(args, *a, **kw)

    subprocess.run = trust_local_fixture
    plan = json.load(sys.stdin)
    candidate = plan['candidates'][0]

    def measure(_):
        e = driver.measure(8)
        return {'code': driver.verdict(e), 'evidence': e}

    result = measure(candidate)
    if result['code'] == 'passed':
        result = adapter.qualify_raw(result, candidate, plan, measure)
        result['evidence']['candidate_sha256'] = candidate['sha256']
    print(json.dumps(result))


if __name__ == '__main__':
    if sys.argv[1] == 'serve':
        asyncio.run(serve(sys.argv[2]))
    else:
        run(sys.argv[2], sys.argv[3])
