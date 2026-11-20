#!/usr/bin/env python3
"""Fixed, read-only public service contracts measured through the candidate's SOCKS listener."""
import concurrent.futures
import ipaddress
import json
import os
import re
import secrets
import subprocess
import sys
import time
import uuid
from html.parser import HTMLParser

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
CHECKS = ('google', 'facebook', 'instagram', 'twitter', 'telegram', 'cloudflare',
          'warp', 'upload', 'download', 'stability')
MEDIA_JSON = {'application/json'}
MEDIA_MANIFEST = MEDIA_JSON | {'application/manifest+json'}
MEDIA_TEXT = {'text/plain'}


class ObservationError(Exception):
    """A bounded diagnostic safe for the ledger."""


def request(url, timeout, *, status=200, types=None, payload=None, limit=65536,
            accept='*/*'):
    args = ['/usr/bin/curl', '-q', '--proto', '=https', '--noproxy', '',
            '--proxy', 'socks5h://127.0.0.1:' + str(SOCKS_PORT), '--max-time', str(timeout),
            '--connect-timeout', str(min(4, timeout)), '--max-filesize', str(limit),
            '--silent', '--user-agent', 'ConfigManager-Health/1',
            '--header', 'Accept: ' + accept, '--header', 'Cache-Control: no-cache',
            '--write-out', '\n%{json}']
    if payload is not None:
        args += ['--header', 'Content-Type: application/octet-stream', '--data-binary', '@-']
    try:
        r = subprocess.run(args + [url], input=payload, capture_output=True, timeout=timeout + 2,
                           env={'PATH': '/usr/bin:/usr/sbin'})
    except OSError as e:
        raise ObservationError('side_driver_unavailable') from e
    except subprocess.TimeoutExpired as e:
        raise ObservationError('timeout') from e
    body, sep, trailer = r.stdout.rpartition(b'\n')
    try:
        m = json.loads(trailer) if sep else {}
    except ValueError:
        m = {}
    if r.returncode or not isinstance(m, dict):
        reason = {18: 'incomplete_response', 28: 'timeout', 60: 'unverified_connection',
                  63: 'response_too_large'}.get(r.returncode, 'transport_failed')
        raise ObservationError(reason)
    if (m.get('remote_ip') != '127.0.0.1' or m.get('ssl_verify_result') != 0
            or m.get('url_effective') != url or m.get('num_redirects') != 0):
        raise ObservationError('unverified_connection')
    code = m.get('http_code', 0)
    if code in (408, 425, 429) or 500 <= code <= 599:
        raise ObservationError('provider_unavailable')
    if code != status:
        raise ObservationError('unexpected_http_status')
    mime = (m.get('content_type') or '').partition(';')[0].strip().lower()
    if types and mime not in types:
        raise ObservationError('unexpected_content')
    if len(body) > limit or m.get('size_download') != len(body):
        raise ObservationError('incomplete_response')
    if payload is not None and m.get('size_upload') != len(payload):
        raise ObservationError('incomplete_upload')
    return body


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


def sample_off_controls():
    # Preserve occasional independent observations for worker recovery when
    # every live candidate exits outside WARP.
    return secrets.randbelow(16) == 0


def measure(timeout, sample_off=sample_off_controls):
    timeout = min(12, max(2, int(timeout)))
    result = dict.fromkeys(CHECKS, 'not_run')
    result.update(side_version='side_v1', warp_mode='unknown')

    def service(name):
        url, types, validate = SERVICES[name]
        return validate(request(url, timeout, types=types,
                                accept='application/dns-json' if name == 'cloudflare' else '*/*'))

    def warp():
        mode = warp_mode(request(WARP + '?side=' + uuid.uuid4().hex, timeout, types=MEDIA_TEXT))
        result['warp_mode'] = mode
        if mode == 'off':
            raise ObservationError('warp_not_active')
        return True

    # An authenticated off disproves a required gate. Roughly one in sixteen
    # also measures the six light controls. No off session runs payload tests.
    result['warp'] = observed(warp)
    if result['warp'] == 'warp_not_active' and result['warp_mode'] == 'off' and not sample_off():
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        jobs = {name: pool.submit(observed, lambda name=name: service(name)) for name in SERVICES}
        result.update({name: future.result() for name, future in jobs.items()})
    if any(result[name] != 'passed' for name in (*SERVICES, 'warp')):
        return result

    def stable_sample():
        return request(PING + '?side=' + uuid.uuid4().hex, timeout, status=204) == b''

    def download():
        url = DOWN + '?bytes=' + str(DOWNLOAD_BYTES) + '&side=' + uuid.uuid4().hex
        return len(request(url, timeout, types={'application/octet-stream'}, limit=DOWNLOAD_BYTES)) == DOWNLOAD_BYTES

    def upload():
        # The speed service acknowledges a complete POST with an empty HTTP 200.
        return request(UP, timeout, types=MEDIA_TEXT, payload=os.urandom(UPLOAD_BYTES), limit=4096) == b''

    started = time.monotonic()
    samples = [observed(stable_sample)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        up = pool.submit(observed, upload)
        down = pool.submit(observed, download)
        time.sleep(max(0, started + 1 - time.monotonic()))
        samples.append(observed(stable_sample))
        result['upload'], result['download'] = up.result(), down.result()
    time.sleep(max(0, started + 2 - time.monotonic()))
    samples.append(observed(stable_sample))
    result['stability_samples'] = str(samples.count('passed'))
    result['stability'] = next((s for s in samples if s != 'passed'), 'passed')
    if result['upload'] == 'passed':
        result['upload_bytes'] = str(UPLOAD_BYTES)
    if result['download'] == 'passed':
        result['download_bytes'] = str(DOWNLOAD_BYTES)
    return result


def verdict(e):
    missed = [e[k] for k in CHECKS if e[k] not in ('passed', 'not_run')]
    if not missed and all(e[k] == 'passed' for k in CHECKS) and e.get('warp_mode') in ('on', 'plus'):
        return 'passed'
    if missed and all(c in ('provider_unavailable', 'side_driver_unavailable') for c in missed):
        return 'side_provider_unavailable' if 'provider_unavailable' in missed else 'side_driver_unavailable'
    return 'side_checks_failed'


def session(box, timeout):
    # Executed by the trusted supervisor. Only the fixed session program is run
    # in the already isolated, endpoint-only candidate network namespace.
    script = os.path.realpath(__file__)
    r = box.net(['/usr/bin/python3', script, str(timeout), str(box.side_port)], timeout=6 * min(12, max(2, timeout)) + 18)
    evidence = json.loads(r.stdout)
    code = verdict(evidence)
    return {'connection': 'passed' if code == 'passed' else 'failed',
            'code': code, 'evidence': evidence,
            'endpoints_passed': sum(evidence[k] == 'passed' for k in CHECKS)}


if __name__ == '__main__':
    SOCKS_PORT = int(sys.argv[2])
    if not 1 <= SOCKS_PORT <= 65535:
        raise SystemExit('invalid local listener')
    print(json.dumps(measure(int(sys.argv[1]))))
