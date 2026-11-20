#!/usr/bin/env python3
"""Offline checks of the Side service driver. No external endpoint or user config is used."""
import importlib.util
import base64
import hashlib
import json
import pathlib
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('side', pathlib.Path(__file__).with_name('side-checks.py'))
side = importlib.util.module_from_spec(spec)
spec.loader.exec_module(side)

fixtures = {
    side.GOOGLE: {'issuer': 'https://accounts.google.com',
                  'authorization_endpoint': 'https://accounts.google.com/o/oauth2/v2/auth',
                  'jwks_uri': 'https://www.googleapis.com/oauth2/v3/certs'},
    side.FACEBOOK: {'keys': [{'kty': 'RSA', 'kid': 'test', 'n': 'a' * 300, 'e': 'AQAB'}]},
    side.CLOUDFLARE: {'Status': 0, 'Question': [{'name': 'example.com', 'type': 1}],
                      'Answer': [{'name': 'example.com.', 'type': 1, 'data': '1.1.1.1'}]},
}
for url, name, package in [(side.INSTAGRAM, 'Instagram', 'com.instagram.android'),
                           (side.TWITTER, 'X', 'com.twitter.android')]:
    fixtures[url] = {'name': name, 'display': 'standalone', 'icons': [{'src': '/app.png'}],
                     'related_applications': [{'platform': 'play', 'id': package}]}


def fixture(url, timeout, **kw):
    if url in fixtures:
        return json.dumps(fixtures[url]).encode()
    if url == side.TELEGRAM:
        return b'<meta name="application-name" content="Telegram Web"><script src="./index-v1.js"></script>'
    if url.startswith(side.WARP + '?'):
        return b'h=www.cloudflare.com\nwarp=on\n'
    if url.startswith(side.PING + '?'):
        return b''
    if url.startswith(side.DOWN + '?'):
        return b'x' * side.DOWNLOAD_BYTES
    if url == side.UP and len(kw.get('payload', b'')) == side.UPLOAD_BYTES:
        return b''
    raise AssertionError('unexpected probe')


class SideContracts(unittest.TestCase):
    def measure(self, driver):
        with patch.object(side, 'request', side_effect=driver), patch.object(side.time, 'sleep'):
            return side.measure(5)

    def test_all_independent_gates(self):
        r = self.measure(fixture)
        self.assertTrue(all(r[k] == 'passed' for k in side.CHECKS))
        self.assertEqual((r['stability_samples'], r['upload_bytes'], r['download_bytes']),
                         ('3', str(side.UPLOAD_BYTES), str(side.DOWNLOAD_BYTES)))
        self.assertEqual(side.verdict(r), 'passed')
        for key in side.CHECKS:
            self.assertNotEqual(side.verdict(dict(r, **{key: 'not_run'})), 'passed')

    def test_service_failure_cannot_be_masked_by_http_200(self):
        for name, (url, _, _) in side.SERVICES.items():
            r = self.measure(lambda u, t, **kw: b'<html>please sign in or verify</html>' if u == url
                             else fixture(u, t, **kw))
            self.assertEqual(r[name], 'unexpected_content', name)
            self.assertEqual(r['upload'], 'not_run')
            self.assertEqual(side.verdict(r), 'side_checks_failed')

    def test_warp_requires_exact_authenticated_trace(self):
        for wire, reason, mode in [(b'h=www.cloudflare.com\nwarp=off\n', 'warp_not_active', 'off'),
                                   (b'warp=on\n', 'unexpected_content', 'unknown'),
                                   (b'h=other\nwarp=on\n', 'unexpected_content', 'unknown'),
                                   (b'h=www.cloudflare.com\nwarp=off\nwarp=on\n', 'unexpected_content', 'unknown'),
                                   (b'h=www.cloudflare.com\nwarp=plus\n', 'passed', 'plus')]:
            r = self.measure(lambda u, t, **kw: wire if u.startswith(side.WARP) else fixture(u, t, **kw))
            self.assertEqual((r['warp'], r['warp_mode']), (reason, mode))
            self.assertEqual(side.verdict(r) == 'passed', reason == 'passed')

    def test_partial_load_or_stability_is_not_accepted(self):
        for target in ('upload', 'download', 'stability'):
            def broken(url, timeout, **kw):
                missing = {'upload': side.UP, 'download': side.DOWN, 'stability': side.PING}[target]
                if url.startswith(missing):
                    return b'partial'
                return fixture(url, timeout, **kw)
            r = self.measure(broken)
            self.assertNotEqual(r[target], 'passed')
            self.assertEqual(side.verdict(r), 'side_checks_failed')

    def test_vendor_failures_do_not_record_a_negative_qualification(self):
        def limited(url, timeout, **kw):
            if url == side.TWITTER:
                raise side.ObservationError('provider_unavailable')
            return fixture(url, timeout, **kw)
        self.assertEqual(side.verdict(self.measure(limited)), 'side_provider_unavailable')


    def test_nondefault_listener_and_dns_only_bypass_preserve_exact_bytes(self):
        runner = importlib.util.spec_from_file_location('side_one', pathlib.Path(__file__).with_name('side-one.py'))
        one = importlib.util.module_from_spec(runner)
        runner.loader.exec_module(one)
        lab = one.load('side_lab', 'live-probe.py')
        actual = {'inbounds': [{'tag':'socks','protocol':'socks','listen':'127.0.0.1','port':19000}],
                  'outbounds':[{'tag':'p','protocol':'trojan','settings':{'servers':[{'address':'1.1.1.1','port':443}]}},
                               {'tag':'d','protocol':'freedom'}],
                  'routing':{'rules':[{'type':'field','port':'53','outboundTag':'d'}]}}
        encoded = json.dumps(actual)
        box = SimpleNamespace(driver='xray')
        with patch.object(lab, 'resolve_endpoints', return_value={}):
            one.inspect_runtime(box, actual, lab)
            self.assertEqual(box.side_port,19000)
            self.assertEqual(json.dumps(actual),encoded)
            actual['routing']['rules'][0]['port']='443'
            with self.assertRaisesRegex(ValueError,'direct_route_not_qualified'):
                one.inspect_runtime(box, actual, lab)
            actual['inbounds'][0]['listen']='0.0.0.0'
            with self.assertRaisesRegex(ValueError,'nonloopback_listener_not_qualified'):
                one.inspect_runtime(box, actual, lab)

    def test_raw_and_template_must_both_pass(self):
        runner = importlib.util.spec_from_file_location('side_one', pathlib.Path(__file__).with_name('side-one.py'))
        one = importlib.util.module_from_spec(runner)
        runner.loader.exec_module(one)
        def candidate(payload):
            return {'config': base64.b64encode(payload).decode(),
                    'sha256': hashlib.sha256(payload).hexdigest()}
        template, raw = candidate(b'template'), candidate(b'original')
        plan = {'raw_candidate': raw, 'original_sha256': 'f' * 64}
        def result():
            return {'code': 'passed', 'evidence': self.measure(fixture)}
        r = one.qualify_raw(result(), template, plan,
                            lambda _: {'code': 'side_checks_failed', 'evidence': {'warp': 'warp_not_active'}})
        self.assertEqual(r['code'], 'side_checks_failed')
        self.assertEqual((r['evidence']['raw_checks'], r['evidence']['raw_warp']), ('failed', 'warp_not_active'))
        r = one.qualify_raw(result(), template, plan, lambda _: result())
        self.assertEqual(r['evidence']['raw_runtime_sha256'], raw['sha256'])
        self.assertEqual(r['evidence']['raw_input_sha256'], plan['original_sha256'])
        self.assertEqual(r['evidence']['raw_checks'], 'passed')
        r = one.qualify_raw(result(), template, {}, lambda _: self.fail('missing original'))
        self.assertEqual(r['code'], 'side_raw_unverified')
        r = one.qualify_raw(result(), template, dict(plan, raw_candidate=template),
                            lambda _: self.fail('identical bytes measured twice'))
        self.assertEqual(r['evidence']['raw_checks'], 'passed')

    def test_request_requires_actual_proxy_tls_status_mime_and_bytes(self):
        url = side.FACEBOOK
        baseline = dict(remote_ip='127.0.0.1', ssl_verify_result=0, url_effective=url, num_redirects=0,
                        http_code=200, content_type='application/json; charset=utf-8', size_download=2,
                        size_upload=4)
        def send(changes, rc=0):
            metadata = json.dumps(dict(baseline, **changes)).encode()
            response = subprocess.CompletedProcess([], rc, b'{}\n' + metadata)
            with patch.object(side.subprocess, 'run', return_value=response) as run:
                body = side.request(url, 5, types=side.MEDIA_JSON, payload=b'data')
                args = run.call_args.args[0]
                self.assertIn('socks5h://127.0.0.1:10808', args)
                self.assertEqual(args[args.index('--noproxy') + 1], '')
                self.assertNotIn('--location', args)
                self.assertNotIn('--insecure', args)
                return body
        self.assertEqual(send({}), b'{}')
        for changes in [dict(remote_ip='192.0.2.1'), dict(ssl_verify_result=20), dict(num_redirects=1),
                        dict(http_code=302), dict(size_upload=3), dict(size_download=1),
                        dict(content_type='text/html'), dict(url_effective='https://example.org/')]:
            with self.assertRaises(side.ObservationError):
                send(changes)
        with self.assertRaisesRegex(side.ObservationError, 'provider_unavailable'):
            send(dict(http_code=429))
        with self.assertRaisesRegex(side.ObservationError, 'timeout'):
            send({}, 28)


if __name__ == '__main__':
    unittest.main()
