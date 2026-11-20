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
        def group(transfers, timeout):
            results = {}
            for name, transfer in transfers.items():
                try:
                    results[name] = driver(transfer.url, timeout, payload=transfer.payload)
                except side.ObservationError as err:
                    results[name] = err
            return results
        with patch.object(side, 'request_group', side_effect=group), patch.object(side.time, 'sleep'):
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
            self.assertEqual(r['upload'], 'passed')
            self.assertNotIn('not_run', r.values())
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

    def test_warp_off_still_measures_every_service_and_payload_once(self):
        requests = []
        def off(url, timeout, **kw):
            requests.append(url)
            if url.startswith(side.WARP + '?'):
                return b'h=www.cloudflare.com\nwarp=off\n'
            return fixture(url, timeout, **kw)
        r = self.measure(off)
        self.assertEqual(len(requests), 12)
        self.assertEqual(len(set(requests)), 12)
        self.assertEqual(r['warp'], 'warp_not_active')
        self.assertEqual(r['warp_mode'], 'off')
        self.assertTrue(all(r[k] == 'passed' for k in side.CHECKS if k != 'warp'))
        self.assertEqual(r['stability_samples'], '3')
        self.assertEqual(side.verdict(r), 'side_checks_failed')

    def test_missing_driver_receipt_cannot_be_made_final_by_unrelated_warp_failure(self):
        def off_and_unavailable(url, timeout, **kw):
            if url.startswith(side.WARP):
                return b'h=www.cloudflare.com\nwarp=off\n'
            if url == side.TWITTER:
                raise side.ObservationError('side_driver_unavailable')
            return fixture(url, timeout, **kw)
        r = self.measure(off_and_unavailable)
        self.assertEqual(r['warp'], 'warp_not_active')
        self.assertEqual(r['twitter'], 'side_driver_unavailable')
        self.assertEqual(side.verdict(r), 'side_driver_unavailable')

    def test_unavailable_warp_still_measures_the_other_service_contracts(self):
        def unavailable(url, timeout, **kw):
            if url.startswith(side.WARP):
                raise side.ObservationError('provider_unavailable')
            return fixture(url, timeout, **kw)
        r = self.measure(unavailable)
        self.assertEqual(r['warp_mode'], 'unknown')
        self.assertTrue(all(r[k] == 'passed' for k in side.SERVICES))
        self.assertEqual(side.verdict(r), 'side_provider_unavailable')

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
                            lambda _: {'code': 'side_checks_failed', 'evidence': dict(self.measure(fixture), warp='warp_not_active')})
        self.assertEqual(r['code'], 'side_checks_failed')
        self.assertEqual((r['evidence']['raw_checks'], r['evidence']['raw_warp']), ('failed', 'warp_not_active'))
        self.assertTrue(all(r['evidence']['raw_' + k] == 'passed' for k in side.CHECKS if k != 'warp'))
        r = one.qualify_raw(result(), template, plan, lambda _: result())
        self.assertEqual(r['evidence']['raw_runtime_sha256'], raw['sha256'])
        self.assertEqual(r['evidence']['raw_input_sha256'], plan['original_sha256'])
        self.assertEqual(r['evidence']['raw_checks'], 'passed')
        r = one.qualify_raw(result(), template, {}, lambda _: self.fail('missing original'))
        self.assertEqual(r['code'], 'side_raw_unverified')
        r = one.qualify_raw(result(), template, dict(plan, raw_candidate=template),
                            lambda _: self.fail('identical bytes measured twice'))
        self.assertEqual(r['evidence']['raw_checks'], 'passed')

    def test_multiple_templates_begin_with_one_complete_original_observation(self):
        spec = importlib.util.spec_from_file_location('side_original', pathlib.Path(__file__).with_name('side-one.py'))
        one = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(one)
        def candidate(body):
            return {'config': base64.b64encode(body).decode(), 'sha256': hashlib.sha256(body).hexdigest()}
        raw, first, second = (candidate(v) for v in [b'raw', b'first', b'second'])
        plan = {'original_sha256':'f' * 64, 'raw_candidate':raw, 'candidates':[first, second]}
        for code in ('side_checks_failed', 'passed', 'probe_socks_contract_missing'):
            calls = []
            def run(c):
                calls.append(c['sha256'])
                measured = code != 'probe_socks_contract_missing' or c != raw
                evidence = self.measure(fixture) if measured else {}
                if code == 'side_checks_failed' and c == raw:
                    evidence.update(warp='warp_not_active', warp_mode='off')
                return dict(core='passed', runtime_sha256=c['sha256'] if measured else '', evidence=evidence,
                            code=code if c == raw else 'passed', connection='passed' if c != raw or code=='passed' else 'failed')
            terminal, reuse = one.first_profile(plan, run)
            if code == 'side_checks_failed':
                self.assertEqual(calls, [raw['sha256']])
                self.assertEqual(terminal['evidence']['measured_form'], 'raw')
                self.assertNotIn('candidate_sha256', terminal['evidence'])
                self.assertEqual(terminal['evidence']['warp'], 'warp_not_active')
                continue
            self.assertIsNone(terminal)
            result = one.qualify_raw(reuse(first), first, plan, reuse)
            self.assertEqual(calls, [raw['sha256'], first['sha256']])
            self.assertEqual(result['code'], code)
            if code == 'passed':
                self.assertEqual(result['evidence']['raw_checks'], 'passed')
            else:
                self.assertEqual(result['evidence']['measured_form'], 'template')
                self.assertEqual(result['evidence']['google'], 'passed')
        for single in (dict(plan, candidates=[first]), dict(plan, raw_candidate=None)):
            no_call = lambda _: self.fail('unnecessary original measurement')
            self.assertEqual(one.first_profile(single, no_call), (None, no_call))

    def test_request_requires_actual_proxy_tls_status_mime_and_bytes(self):
        url = side.FACEBOOK
        transfer = side.Transfer(url, types=side.MEDIA_JSON, payload=b'data')
        baseline = dict(remote_ip='127.0.0.1', ssl_verify_result=0, url_effective=url, num_redirects=0,
                        http_code=200, content_type='application/json; charset=utf-8', size_download=2,
                        size_upload=4)
        def send(changes, rc=0):
            def curl(args, **kw):
                self.assertIn('socks5h://127.0.0.1:10808', args)
                self.assertEqual(args[args.index('--noproxy') + 1], '')
                self.assertNotIn('--location', args)
                self.assertNotIn('--insecure', args)
                self.assertEqual(pathlib.Path(args[args.index('--data-binary') + 1][1:]).read_bytes(), b'data')
                pathlib.Path(args[args.index('-o') + 1]).write_bytes(b'{}')
                metadata = json.dumps(dict(baseline, exitcode=rc) | changes).encode()
                return subprocess.CompletedProcess(args, rc, b'0 ' + metadata + b'\n')
            with patch.object(side.subprocess, 'run', side_effect=curl):
                result = side.request_group({'facebook': transfer}, 5)['facebook']
            if isinstance(result, side.ObservationError):
                raise result
            return result
        self.assertEqual(send({}), b'{}')
        for changes in [dict(remote_ip='192.0.2.1'), dict(ssl_verify_result=20), dict(num_redirects=1),
                        dict(http_code=302), dict(size_upload=3), dict(size_download=1),
                        dict(content_type='text/html'), dict(url_effective='https://example.org/')]:
            with self.assertRaises(side.ObservationError):
                send(changes)
        with self.assertRaisesRegex(side.ObservationError, 'provider_unavailable'):
            send(dict(http_code=429))
        for rc, reason in [(18, 'incomplete_response'), (28, 'timeout'),
                           (60, 'unverified_connection'), (63, 'response_too_large')]:
            with self.assertRaisesRegex(side.ObservationError, reason):
                send({}, rc)

    def test_parallel_transfers_keep_independent_receipts(self):
        transfers = {'google': side.Transfer(side.GOOGLE), 'warp': side.Transfer(side.WARP),
                     'instagram': side.Transfer(side.INSTAGRAM)}
        good = dict(exitcode=0, remote_ip='127.0.0.1', ssl_verify_result=0, url_effective=side.GOOGLE,
                    num_redirects=0, http_code=200, size_download=2)
        def curl(args, **kw):
            self.assertEqual(args[0:3], ['/usr/bin/curl', '-q', '--parallel'])
            self.assertEqual(args.count('--next'), 2)
            self.assertEqual(args.count('--noproxy'), 3)
            self.assertEqual(args.count('--proxy'), 3)
            pathlib.Path(args[args.index('-o') + 1]).write_bytes(b'{}')
            # Arrival order differs from submission; third transfer has no valid receipt.
            return subprocess.CompletedProcess(args, 28, b'1 {"exitcode":28}\n0 ' +
                                               json.dumps(good).encode() + b'\n')
        with patch.object(side.subprocess, 'run', side_effect=curl) as process:
            results = side.request_group(transfers, 5)
        self.assertEqual(process.call_count, 1)
        self.assertEqual(results['google'], b'{}')
        self.assertEqual(str(results['warp']), 'timeout')
        self.assertEqual(str(results['instagram']), 'side_driver_unavailable')


if __name__ == '__main__':
    unittest.main()
