#!/usr/bin/env python3
"""Fixed, read-only public service contracts measured through the candidate's SOCKS listener."""
import concurrent.futures
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path

GOOGLE = 'https://accounts.google.com/.well-known/openid-configuration'
FACEBOOK = 'https://www.facebook.com/.well-known/oauth/openid/jwks/'
INSTAGRAM = 'https://www.instagram.com/data/manifest.json'
TWITTER = 'https://x.com/manifest.json'
TELEGRAM = 'https://web.telegram.org/k/'
CLOUDFLARE = 'https://cloudflare-dns.com/dns-query?name=example.com&type=A'
WARP = 'https://www.cloudflare.com/cdn-cgi/trace'
PING = 'https://www.gstatic.com/generate_204'
DOWN = 'https://speed.cloudflare.com/__down'
UP = 'https://speed.cloudflare.com/__up'
DOWNLOAD_BYTES = 262144
UPLOAD_BYTES = 131072
SOCKS_PORT = 10808
WORK_DIR = None
CHECKS = ('google', 'facebook', 'instagram', 'twitter', 'telegram', 'cloudflare',
          'warp', 'upload', 'download', 'stability')
MEDIA_JSON = {'application/json'}
MEDIA_MANIFEST = MEDIA_JSON | {'application/manifest+json'}
MEDIA_TEXT = {'text/plain'}
MAX_PARALLEL_TRANSFERS = 9


class ObservationError(Exception):
    """A bounded diagnostic safe for the ledger."""


@dataclass(frozen=True)
class Transfer:
    url: str
    status: int = 200
    types: set | None = None
    payload: bytes | None = None
    limit: int = 65536
    accept: str = '*/*'


def response(transfer, metadata, body_file):
    # In curl parallel mode the process exit code describes a single transfer.
    # Use the per-URL code and validated receipt for every individual service.
    rc = metadata.get('exitcode')
    if type(rc) is not int:
        raise ObservationError('side_driver_unavailable')
    if rc:
        reason = {18: 'incomplete_response', 28: 'timeout', 60: 'unverified_connection',
                  63: 'response_too_large'}.get(rc, 'transport_failed')
        raise ObservationError(reason)
    if (metadata.get('remote_ip') != '127.0.0.1' or metadata.get('ssl_verify_result') != 0
            or metadata.get('url_effective') != transfer.url or metadata.get('num_redirects') != 0):
        raise ObservationError('unverified_connection')
    code = metadata.get('http_code', 0)
    if code in (408, 425, 429) or 500 <= code <= 599:
        raise ObservationError('provider_unavailable')
    if code != transfer.status:
        raise ObservationError('unexpected_http_status')
    mime = (metadata.get('content_type') or '').partition(';')[0].strip().lower()
    if transfer.types and mime not in transfer.types:
        raise ObservationError('unexpected_content')
    if transfer.payload is not None and metadata.get('size_upload') != len(transfer.payload):
        raise ObservationError('incomplete_upload')
    with body_file.open('rb') as stream:
        body = stream.read(transfer.limit + 1)
    if len(body) > transfer.limit or metadata.get('size_download') != len(body):
        raise ObservationError('incomplete_response')
    return body


def request_group(transfers, timeout):
    """One curl process with independent TLS, deadlines, receipts and bounded fan-out."""
    results = {}
    # Each runtime owns its private directory. Child arguments contain only
    # fixed URLs, a loopback listener and ephemeral, locally generated paths.
    with tempfile.TemporaryDirectory(prefix='side-http-', dir=WORK_DIR) as tmp:
        files = Path(tmp)
        args = ['/usr/bin/curl', '-q', '--parallel', '--parallel-max', str(MAX_PARALLEL_TRANSFERS), '--parallel-immediate']
        for index, (name, transfer) in enumerate(transfers.items()):
            if index:
                args.append('--next')
            args += ['--proto', '=https', '--noproxy', '',
                     '--proxy', 'socks5h://127.0.0.1:' + str(SOCKS_PORT),
                     '--max-time', str(timeout), '--connect-timeout', str(min(4, timeout)),
                     '--max-filesize', str(transfer.limit), '--silent',
                     '--user-agent', 'ConfigManager-Health/1', '--header', 'Accept: ' + transfer.accept,
                     '--header', 'Cache-Control: no-cache', '-o', str(files / name),
                     '--write-out', str(index) + ' %{json}\n']
            if transfer.payload is not None:
                payload_file = files / (name + '-upload')
                payload_file.write_bytes(transfer.payload)
                args += ['--header', 'Content-Type: application/octet-stream',
                         '--data-binary', '@' + str(payload_file)]
            args.append(transfer.url)

        names = list(transfers)
        waves = (len(names) + MAX_PARALLEL_TRANSFERS - 1) // MAX_PARALLEL_TRANSFERS
        try:
            run = subprocess.run(args, capture_output=True, timeout=waves * (timeout + 1) + 3,
                                 env={'PATH': '/usr/bin:/usr/sbin'})
            receipts = run.stdout
        except subprocess.TimeoutExpired as e:
            receipts = e.stdout or b''
        except OSError:
            receipts = b''
        for line in receipts.splitlines():
            index, sep, payload = line.partition(b' ')
            if not sep or not index.isdigit() or int(index) >= len(names):
                continue
            name = names[int(index)]
            if name in results:
                results[name] = ObservationError('side_driver_unavailable')
                continue
            try:
                metadata = json.loads(payload)
                if not isinstance(metadata, dict):
                    raise ValueError('invalid receipt')
                results[name] = response(transfers[name], metadata, files / name)
            except ObservationError as e:
                results[name] = e
            except (OSError, ValueError, TypeError):
                results[name] = ObservationError('side_driver_unavailable')
    for name in transfers:
        results.setdefault(name, ObservationError('side_driver_unavailable'))
    return results


def unique_json(body):
    def fields(pairs):
        obj = dict(pairs)
        if len(obj) != len(pairs):
            raise ValueError('duplicate key')
        return obj
    return json.loads(body, object_pairs_hook=fields)


def google(body):
    d = unique_json(body)
    return (d.get('issuer') == 'https://accounts.google.com'
            and d.get('authorization_endpoint', '').startswith('https://accounts.google.com/')
            and d.get('jwks_uri', '').startswith('https://www.googleapis.com/'))


def facebook(body):
    d = unique_json(body)
    return any(isinstance(k, dict) and k.get('kty') == 'RSA' and k.get('kid')
               and isinstance(k.get('n'), str) and len(k['n']) >= 256 and k.get('e')
               for k in d.get('keys', []))


def manifest(body, names, package):
    d = unique_json(body)
    packages = {a.get('id') for a in d.get('related_applications', [])
                if isinstance(a, dict) and a.get('platform') == 'play'}
    return (d.get('name') in names and package in packages and bool(d.get('icons'))
            and d.get('display') in ('standalone', 'fullscreen'))


class TelegramShell(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title = self.script = False

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == 'meta' and d.get('name') == 'application-name':
            self.title |= d.get('content') == 'Telegram Web'
        if tag == 'script' and re.fullmatch(r'(\./|/k/)[\w./-]+\.js', d.get('src') or ''):
            self.script = True


def telegram(body):
    shell = TelegramShell()
    shell.feed(body.decode('utf-8'))
    return shell.title and shell.script


def cloudflare(body):
    d = unique_json(body)
    def target(a):
        return a.get('name', '').rstrip('.').lower() == 'example.com' and a.get('type') == 1
    return (d.get('Status') == 0 and any(target(a) for a in d.get('Question', []))
            and any(target(a) and ipaddress.IPv4Address(a['data']).is_global
                    for a in d.get('Answer', [])))


SERVICES = {
    'google': (GOOGLE, MEDIA_JSON, google),
    'facebook': (FACEBOOK, MEDIA_JSON, facebook),
    'instagram': (INSTAGRAM, MEDIA_MANIFEST, lambda body: manifest(body, {'Instagram'}, 'com.instagram.android')),
    'twitter': (TWITTER, MEDIA_MANIFEST, lambda body: manifest(body, {'X', 'Twitter'}, 'com.twitter.android')),
    'telegram': (TELEGRAM, {'text/html'}, telegram),
    'cloudflare': (CLOUDFLARE, {'application/dns-json'}, cloudflare),
}


def warp_mode(body):
    fields = {}
    for line in body.decode('ascii').splitlines():
        key, sep, value = line.partition('=')
        if not sep or key in fields:
            raise ValueError('invalid trace')
        fields[key] = value
    if fields.get('h') != 'www.cloudflare.com' or fields.get('warp') not in ('off', 'on', 'plus'):
        raise ValueError('invalid trace')
    return fields['warp']


def observed(action):
    try:
        return 'passed' if action() else 'unexpected_content'
    except ObservationError as e:
        return str(e)
    except (TypeError, KeyError, AttributeError, ValueError):
        return 'unexpected_content'


def measure(timeout):
    timeout = min(12, max(2, int(timeout)))
    result = {'side_version': 'side_v2', 'warp_mode': 'unknown'}
    transfers = {}
    for name, (url, types, _) in SERVICES.items():
        transfers[name] = Transfer(url, types=types,
                                   accept='application/dns-json' if name == 'cloudflare' else '*/*')
    transfers['warp'] = Transfer(WARP + '?side=' + uuid.uuid4().hex, types=MEDIA_TEXT)
    transfers['upload'] = Transfer(UP, types=MEDIA_TEXT, payload=os.urandom(UPLOAD_BYTES), limit=4096)
    transfers['download'] = Transfer(DOWN + '?bytes=' + str(DOWNLOAD_BYTES) + '&side=' + uuid.uuid4().hex,
                                     types={'application/octet-stream'}, limit=DOWNLOAD_BYTES)

    def stable_sample():
        transfer = Transfer(PING + '?side=' + uuid.uuid4().hex, status=204)
        body = request_group({'stability': transfer}, timeout)['stability']
        return str(body) if isinstance(body, ObservationError) else observed(lambda: body == b'')

    # Each sample uses a fresh curl process, so it cannot pass on an already
    # open TLS connection. A slow first response cannot postpone later starts.
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        batch = pool.submit(request_group, transfers, timeout)
        samples = [pool.submit(stable_sample)]
        for _ in range(2):
            time.sleep(1)
            samples.append(pool.submit(stable_sample))
        measurements = batch.result()
        samples = [s.result() for s in samples]

    def warp(body):
        mode = warp_mode(body)
        result['warp_mode'] = mode
        if mode == 'off':
            raise ObservationError('warp_not_active')
        return True

    checks = {k: spec[2] for k, spec in SERVICES.items()}
    checks.update(warp=warp, upload=lambda body: body == b'', download=lambda body: len(body) == DOWNLOAD_BYTES)
    for name, validate in checks.items():
        body = measurements[name]
        result[name] = str(body) if isinstance(body, ObservationError) else observed(lambda: validate(body))
    result['stability_samples'] = str(samples.count('passed'))
    if 'side_driver_unavailable' in samples:
        result['stability'] = 'side_driver_unavailable'
    else:
        result['stability'] = next((s for s in samples if s != 'passed'), 'passed')
    if result['upload'] == 'passed':
        result['upload_bytes'] = str(UPLOAD_BYTES)
    if result['download'] == 'passed':
        result['download_bytes'] = str(DOWNLOAD_BYTES)
    return result


def verdict(e):
    checks = [e.get(k, 'not_run') for k in CHECKS]
    if any(c in ('not_run', 'side_driver_unavailable') for c in checks):
        return 'side_driver_unavailable'
    missed = [c for c in checks if c != 'passed']
    if not missed and e.get('warp_mode') in ('on', 'plus'):
        return 'passed'
    if missed and all(c == 'provider_unavailable' for c in missed):
        return 'side_provider_unavailable'
    return 'side_checks_failed'


def session(box, timeout):
    # Executed by the trusted supervisor. Only the fixed session program is run
    # in the already isolated, endpoint-only candidate network namespace.
    script = os.path.realpath(__file__)
    r = box.net(['/usr/bin/python3', script, str(timeout), str(box.side_port), str(box.work)],
                timeout=2 * min(12, max(2, timeout)) + 12)
    evidence = json.loads(r.stdout)
    code = verdict(evidence)
    return {'connection': 'passed' if code == 'passed' else 'failed',
            'code': code, 'evidence': evidence,
            'endpoints_passed': sum(evidence[k] == 'passed' for k in CHECKS)}


if __name__ == '__main__':
    SOCKS_PORT = int(sys.argv[2])
    WORK_DIR = sys.argv[3] if len(sys.argv) > 3 else None
    if not 1 <= SOCKS_PORT <= 65535:
        raise SystemExit('invalid local listener')
    print(json.dumps(measure(int(sys.argv[1]))))
