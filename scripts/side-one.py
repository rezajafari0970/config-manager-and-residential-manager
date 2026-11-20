#!/usr/bin/env python3
"""Run an independent Side qualification using the existing pinned core sandbox."""
import importlib.util
import base64
import copy
import hashlib
import re
import pathlib


def load(name, filename):
    path = pathlib.Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inspect_runtime(box, config, lab):
    """Choose the existing local SOCKS listener without rewriting the running configuration."""
    native = getattr(box, 'driver', 'xray') == 'sing-box'
    port_key = 'listen_port' if native else 'port'
    protocol_key = 'type' if native else 'protocol'
    obj = copy.deepcopy(config)
    listeners = obj.get('inbounds', [])
    if not isinstance(listeners, list) or any(not isinstance(x, dict) or
            x.get('listen') != '127.0.0.1' for x in listeners):
        raise ValueError('nonloopback_listener_not_qualified')
    ports = [x.get(port_key) for x in listeners]
    if any(type(p) is not int or not 1 <= p <= 65535 for p in ports) or len(set(ports)) != len(ports):
        raise ValueError('listener_port_conflict')
    socks = [x for x in listeners if x.get(protocol_key) == 'socks'
             and (not x.get('users') if native else x.get('settings', {}).get('auth', 'noauth') == 'noauth')]
    chosen = next((x for x in socks if x[port_key] == 10808), None)
    if chosen is None:
        if len(socks) != 1:
            raise ValueError('probe_socks_contract_missing')
        chosen = socks[0]
    box.side_port = chosen[port_key]
    if native:
        # Under native imports an administrator can specify arbitrary route
        # actions. Only explicit single proxy/WireGuard paths are representable.
        route = obj.get('route', {})
        if route.get('rules') or route.get('rule_set'):
            raise ValueError('native_route_unqualified')
        return lab.native_endpoints(config)
    # A rule explicitly limited to DNS port 53 cannot route the fixed HTTPS
    # destinations in this measurement. The executed config remains unchanged.
    direct = {x.get('tag') for x in obj.get('outbounds', []) if x.get('protocol') == 'freedom'}
    route = obj.get('routing', {})
    if 'rules' in route:
        route['rules'] = [r for r in route['rules'] if not (
            r.get('type', 'field') == 'field' and r.get('port') == '53' and r.get('outboundTag') in direct)]
    resolved = lab.endpoints(obj)
    lab.preflight.runtime_config(obj, resolved, socks_port=box.side_port)
    return resolved


def qualify_raw(result, candidate, plan, measure):
    """Bind the normalized and original delivery forms to the same Side grant."""
    evidence = result['evidence']
    raw = plan.get('raw_candidate')
    input_hash = plan.get('original_sha256', '')
    if not raw or not re.fullmatch('[a-f0-9]{64}', input_hash):
        evidence['raw_checks'] = 'failed'
        return dict(result, code='side_raw_unverified', connection='failed')
    raw_hash = hashlib.sha256(base64.b64decode(raw['config'], validate=True)).hexdigest()
    if raw_hash != raw['sha256'] or raw.get('engine', 'xray') != candidate.get('engine', 'xray'):
        evidence['raw_checks'] = 'failed'
        return dict(result, code='side_raw_unverified', connection='failed')
    evidence.update(raw_input_sha256=input_hash, raw_runtime_sha256=raw_hash)
    if raw_hash != candidate['sha256']:
        raw_result = measure(raw)
        if raw_result['code'] != 'passed':
            # The same raw is shared by all template alternatives. Retrying a
            # different template cannot change its qualified or deferred state.
            evidence['raw_checks'] = 'failed'
            evidence['raw_failure'] = raw_result['code']
            for key in ('google','facebook','instagram','twitter','telegram','cloudflare',
                        'warp','upload','download','stability'):
                value = raw_result.get('evidence', {}).get(key, 'not_run')
                if value not in ('passed','not_run'):
                    evidence['raw_' + key] = value
            return dict(result, connection='failed', code=raw_result['code'])
    evidence['raw_checks'] = 'passed'
    return result


if __name__ == '__main__':
    adapter = load('side_adapter', 'probe-one.py')
    adapter.PREFIX = 'csi'
    adapter.main(session_check=load('side_checks', 'side-checks.py').session,
                 verify_raw=qualify_raw, inspect_session=inspect_runtime)
