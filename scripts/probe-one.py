#!/usr/bin/env python3
"""Trusted one-job adapter. Payload only on stdin; receipts never contain secrets."""
import hashlib, fcntl, argparse, threading, time, signal, base64, contextlib, importlib.util, json, os, pathlib, re, shutil, stat, subprocess, sys, tempfile, uuid

HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('probe_sandbox',HERE/'live-probe.py')
lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)
spec=importlib.util.spec_from_file_location("app_contract",HERE/"app-import-contract.py")
app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)
CORE_SHA='e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d'
# Client exports must also build on the current official core. Older-core
# connectivity (including legacy VLESS vnext) is not current-client acceptance.
CLIENT_CORE_SHA='cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1'
CLIENT_CORE='/opt/config-repair/core-26.10.31/xray'
PREFIX='crw'
OWN=re.compile(r'^'+PREFIX+r'[0-9a-f]{6}20(?:0[0-8])$')

def pinned_core(path, expected, cache_dir=pathlib.Path('/run/config-repair-side-core')):
    """Share successful checks of the same installed inode across Side workers."""
    with open(path, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if PREFIX != 'csi' or not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022:
            return hashlib.file_digest(stream, 'sha256').hexdigest() == expected
        stamp = f'{before.st_dev}:{before.st_ino}:{before.st_size}:{before.st_ctime_ns}:{before.st_mtime_ns}'
        # Root owns /run. Only use receipts inside our private, non-symlink directory.
        trusted = False
        try:
            cache_dir.mkdir(mode=0o700, exist_ok=True)
            folder = cache_dir.lstat()
            trusted = stat.S_ISDIR(folder.st_mode) and folder.st_uid == 0 and not folder.st_mode & 0o077
            receipt = cache_dir / expected
            if trusted and receipt.read_text() == stamp:
                return True
        except OSError:
            pass
        if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
            return False
        after = os.fstat(stream.fileno())
        if (after.st_size, after.st_ctime_ns, after.st_mtime_ns) != (before.st_size, before.st_ctime_ns, before.st_mtime_ns):
            return False
        if trusted:
            try:
                with tempfile.NamedTemporaryFile(mode='w', dir=cache_dir, delete=False) as tmp:
                    tmp.write(stamp)
                os.replace(tmp.name, receipt)
            except OSError:
                pass
        return True

def validate_client(box, data, core):
    """Build the exact exported bytes in the existing sandbox, before networking.

    Return a bounded diagnostic, never raw logs/endpoints. A successful build
    proves syntax/core compatibility only. Never rewrite security or credentials.
    """
    previous = box.core
    result = {'core':'blocked','connection':'not_run','code':'client_core_infrastructure_error',
              'runtime_sha256':'','endpoints_passed':0}
    try:
        box.stop()
        box.core = pathlib.Path(core).resolve()
        box.policy({})
        process = box.launch(data, True)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            result['code'] = 'client_core_validation_timeout'
            return result
        log = box.logs()
        if process.returncode == 0:
            return None
        if process.returncode < 0 or not log.startswith(b'Xray '):
            return result
        code = lab.classify(log, 'client_core_incompatible')
        if code == 'missing_runtime_asset':
            result['code'] = 'client_core_asset_missing'
            return result
        result['core'] = 'failed'
        if b'vless without TLS or other encryption is prohibited' in log:
            result['code'] = 'client_vless_encryption_required'
        elif b'trojan without TLS is prohibited' in log:
            result['code'] = 'client_trojan_tls_required'
        else:
            result['code'] = 'client_core_incompatible'
        return result
    finally:
        box.stop()
        box.core = previous

def run_target(box,candidate,timeout,core,session_check=None):
    previous=box.core
    try:
        box.core=pathlib.Path(core).resolve()
        options={'session_check':session_check} if session_check is not None else {}
        result=lab.test_candidate(box,candidate,timeout,validated_sha256=candidate['sha256'],**options)
        if session_check is None and result.get('code') in {'peer_closed_connection','peer_reset_connection','proxy_request_failed'} and result.get('core')=='passed':
            # A new exact-config session and fresh endpoint resolution, once.
            # Never invent credentials or relax TLS after an upstream close.
            first=result['code'];box.stop()
            result=lab.test_candidate(box,candidate,timeout,validated_sha256=candidate['sha256'])
            result.setdefault('evidence',{}).update(session_attempts='2',first_failure=first)
        result.setdefault('evidence',{})['runtime_core']='xray_26_10_31'
        return result
    finally:
        box.stop();box.core=previous

def side_xray_candidate(box, candidate, data, timeout, args, session_check):
    # A subscriber's core must run these exact bytes. Only an otherwise
    # qualifying session also needs the offline checks for every import form.
    evidence = {'bundled_core': 'not_run', 'target_core': 'not_run',
                'app_import_contract': 'not_run', 'android': 'not_run'}
    failure = validate_client(box, data, args.client_core)
    if failure is not None:
        evidence['bundled_core'] = failure['core']
        failure['evidence'] = evidence
        return failure
    evidence['bundled_core'] = 'passed'
    result = run_target(box, candidate, timeout, args.client_core, session_check)
    result.setdefault('evidence', {}).update(evidence)
    if result['code'] != 'passed':
        return result
    receipt = result['evidence']
    seen = {candidate['sha256']}
    try:
        for variant in app.variants(data):
            variant_hash = lab.digest(variant)
            if variant_hash in seen:
                continue
            seen.add(variant_hash)
            failure = validate_client(box, variant, args.client_core)
            if failure is not None:
                receipt['app_import_contract'] = failure['core']
                if failure['core'] == 'failed':
                    failure['code'] = 'app_transform_core_rejected'
                return dict(result, code=failure['code'], core=failure['core'])
    except (ValueError, TypeError, KeyError):
        receipt['app_import_contract'] = 'failed'
        return dict(result, code='custom_import_shape_invalid', core='failed')
    receipt['app_import_contract'] = 'passed'
    failure = validate_client(box, data, args.core)
    if failure is not None:
        receipt['target_core'] = failure['core']
        return dict(result, code=failure['code'], core=failure['core'])
    receipt['target_core'] = 'passed'
    return result

def attempt_score(result,candidate):
    eligible=result['core']=='passed' and (not candidate.get('requires_connection') or result['connection']=='passed')
    payload=result['connection']=='passed' and result.get('code')=='https_payload_verified'
    return (eligible,payload,{'not_run':0,'failed':1,'partial':2,'passed':3}[result['connection']],result['core']=='passed')

SIDE_GROUP = pathlib.Path('/sys/fs/cgroup/csi-sandboxes')

def cleanup(slot=None,runid=None):
    names=set()
    folders=['/run/netns','/sys/fs/cgroup','/dev/shm']
    if PREFIX == 'csi':
        folders.append(SIDE_GROUP)
    for folder in folders:
        for p in pathlib.Path(folder).glob(PREFIX+'*'):
            name=p.name.split('-')[0]
            if OWN.fullmatch(name) and (slot is None or name.endswith(format(8192+slot,'x'))) and (runid is None or name.startswith(PREFIX+runid)):names.add(name)
    # Covers crashes between NAT-table creation and namespace registration.
    r=subprocess.run([lab.NFT,'-j','list','tables'],capture_output=True)
    if r.returncode==0:
        for item in json.loads(r.stdout).get('nftables',[]):
            t=item.get('table',{});name=t.get('name','')
            if t.get('family') in ('ip','inet') and OWN.fullmatch(name) and (slot is None or name.endswith(format(8192+slot,'x'))) and (runid is None or name.startswith(PREFIX+runid)):names.add(name)
    for name in names:
        groups = [pathlib.Path('/sys/fs/cgroup')/name]
        if PREFIX == 'csi':
            groups.append(SIDE_GROUP/name)
        for cg in groups:
            with contextlib.suppress(OSError):(cg/'cgroup.kill').write_text('1')
        for args in [[lab.NFT,'delete','table','inet',name],[lab.NFT,'delete','table','ip',name],[lab.IP,'link','del',name+'h'],[lab.IP,'netns','del',name]]:subprocess.run(args,capture_output=True,timeout=5)
        for cg in groups:
            with contextlib.suppress(OSError):cg.rmdir()
        for p in pathlib.Path('/dev/shm').glob(name+'-*'):
            if p.is_dir() and not p.is_symlink():shutil.rmtree(p)

NATIVE_CORE='/opt/config-repair/sing-box-1.14.4/sing-box'
NATIVE_SHA='1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a'
class NativeBox(lab.Sandbox):
    driver='sing-box'
    def core_mounts(self):
        out=['--ro-bind','/lib64/ld-linux-x86-64.so.2','/lib64/ld-linux-x86-64.so.2']
        for name in ('libdl.so.2','libpthread.so.0','libc.so.6'):out+=['--ro-bind','/usr/lib/x86_64-linux-gnu/'+name,'/lib/x86_64-linux-gnu/'+name]
        return out
    def core_command(self,test):return ['/xray','check' if test else 'run','-c','/config.json']
    def inspect(self,config):
        return lab.native_endpoints(config)

class SideSandbox(lab.Sandbox):
    # Each identity gets its own freshly created namespace and leaf cgroup.
    # Aggregate anonymous memory/CPU have their own host-level guard as well.
    def __init__(self, core, runid, index, prefix='csi'):
        super().__init__(core, runid, index, prefix)
        with open('/run/config-repair-side-cgroup.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            SIDE_GROUP.mkdir(exist_ok=True)
            meminfo = pathlib.Path('/proc/meminfo').read_text()
            total = int(re.search(r'^MemTotal:\s+(\d+) kB$', meminfo, re.M)[1]) * 1024
            limit = str(max(256 << 20, min(4 << 30, total // 4)))
            for name, desired in [('memory.max', limit), ('pids.max', '4096'), ('cpu.weight', '75')]:
                path = SIDE_GROUP / name
                if path.read_text().strip() != desired:
                    path.write_text(desired)
            if not {'cpu','pids','memory'} <= set((SIDE_GROUP/'cgroup.subtree_control').read_text().split()):
                (SIDE_GROUP/'cgroup.subtree_control').write_text('+memory +pids +cpu')
        self.cg = SIDE_GROUP / self.name
        self.policy_key = None
        self.policy_relay = False

    def network_command(self):
        return ['/usr/bin/nsenter', '--net=/run/netns/' + self.name, '--']

    def launch_command(self):
        return ['/usr/bin/python3', str(HERE/'egress-launch.py'), str(self.cg)]

    def policy(self, resolved):
        # A syntax check often repeats the already-installed deny-all rules.
        # Never reuse a relay mapping after the process supporting it died.
        key = json.dumps(resolved, sort_keys=True, separators=(',', ':'))
        if key == self.policy_key and (not self.policy_relay or self.relay and self.relay.poll() is None):
            return
        self.policy_key = None
        super().policy(resolved)
        self.policy_key = key
        self.policy_relay = self.relay is not None

    def oom_kills(self):
        # A cgroup memory kill is local infrastructure failure. It cannot
        # supply a negative service observation for a candidate.
        events = dict(line.split() for line in (self.cg/'memory.events').read_text().splitlines())
        return int(events['oom_kill'])

class SideNativeBox(NativeBox, SideSandbox):
    pass

def measure_candidate(box,candidate,timeout,args,native,session_check):
    client_failure={'code':'not_run'}
    try:
        data=base64.b64decode(candidate['config'],validate=True)
        if len(data)>2*1024*1024 or lab.digest(data)!=candidate['sha256']:raise ValueError('invalid candidate')
        if native:
            r=lab.test_candidate(box,candidate,timeout,session_check=session_check)
        elif session_check is not None:
            return side_xray_candidate(box, candidate, data, timeout, args, session_check)
        else:
            client_failure=validate_client(box,data,args.client_core)
            if client_failure is None:
                seen_variants={lab.digest(data)}
                for variant in app.variants(data):
                    if lab.digest(variant) in seen_variants:continue
                    seen_variants.add(lab.digest(variant))
                    client_failure=validate_client(box,variant,args.client_core)
                    if client_failure is not None:
                        client_failure["code"]="app_transform_core_rejected"
                        break
            if client_failure is not None:
                r=client_failure
            else:
                # Both official cores must build the exact output. Real traffic
                # runs on the core actually bundled with the target Android app.
                latest_failure=validate_client(box,data,args.core)
                if latest_failure is not None:
                    r=latest_failure
                else:
                    r=run_target(box,candidate,timeout,args.client_core,session_check)
    except Exception as error:
        code = 'protocol_disabled' if isinstance(error,ValueError) and str(error)=='protocol_disabled' else 'probe_infrastructure_error'
        r={'core':'blocked','connection':'not_run','code':code,'runtime_sha256':'','endpoints_passed':0}
    if native:
        r['engine']='sing-box'
        r.setdefault('evidence',{})['native_core']=r['core']
        r['evidence']['runtime_core']='sing_box_1_14_4'
        r['evidence']['android']='not_run'
    else:
        r.setdefault('evidence',{})['bundled_core']='passed' if client_failure is None else 'failed'
        r['evidence']['target_core']=r['core']
        r['evidence']['app_import_contract']='passed' if client_failure is None else 'failed'
        r['evidence']['android']='not_run'
    return r

def main(session_check=None,verify_raw=None,inspect_session=None,first_profile=None):
    global OWN
    if PREFIX not in ('crw','ctw','crr','crt','csi') or (PREFIX=='csi')!=(session_check is not None):raise SystemExit('invalid resource prefix')
    max_slot = 31 if PREFIX == 'csi' else 8
    suffix = r'20[01][0-9a-f]' if PREFIX == 'csi' else r'200[0-8]'
    OWN = re.compile(r'^' + PREFIX + r'[0-9a-f]{6}' + suffix + r'$')
    a=argparse.ArgumentParser();a.add_argument('--core');a.add_argument('--client-core',default=CLIENT_CORE);a.add_argument('--slot',type=int);a.add_argument('--cleanup',action='store_true');a.add_argument('--cleanup-slot',type=int);a.add_argument('--self-test',action='store_true');a.add_argument('--run-id');a.add_argument('--cleanup-run');args=a.parse_args()
    if os.geteuid()!=0:raise SystemExit('root supervisor required')
    for value in [args.run_id,args.cleanup_run]:
        if value is not None and not re.fullmatch('[0-9a-f]{6}',value):raise SystemExit('invalid run id')
    # Prevent orphan supervisors after their Go parent is killed.
    parent=os.getppid()
    signal.signal(signal.SIGTERM,lambda *_:sys.exit(143))
    if parent==1:raise SystemExit('parent unavailable')
    def watch_parent():
        while True:
            time.sleep(.25)
            if os.getppid()!=parent:os.kill(os.getpid(),signal.SIGTERM);return
    threading.Thread(target=watch_parent,daemon=True).start()
    if args.cleanup_slot is not None and not 1<=args.cleanup_slot<=max_slot:raise SystemExit('invalid slot')
    if args.cleanup or args.cleanup_slot is not None:cleanup(args.cleanup_slot,args.cleanup_run);return
    if not args.core or not pinned_core(args.core,CORE_SHA):raise SystemExit('pinned core mismatch')
    if not pinned_core(args.client_core,CLIENT_CORE_SHA):raise SystemExit('pinned client core mismatch')
    if args.self_test:
        runid=uuid.uuid4().hex[:6]
        try:
            with (SideSandbox if PREFIX=='csi' else lab.Sandbox)(args.core,runid,8192,prefix=PREFIX) as box:
                for host in ['127.0.0.1','169.254.169.254',box.gateway,'1.1.1.1']:
                    r=box.net(['/usr/bin/python3','-c','import socket,sys;s=socket.socket();s.settimeout(.3);print(s.connect_ex((sys.argv[1],443)))',host],timeout=3)
                    if r.stdout.strip()==b'0':raise RuntimeError('egress_control_failed')
                box.policy({'public':{'ips':['1.1.1.1','1.0.0.1'],'port':443}})
                good=False
                for host in ['1.1.1.1','1.0.0.1']:
                    try:
                        r=box.net(['/usr/bin/curl','--noproxy','*','--max-time','10','--silent','--output','/dev/null','--write-out','%{http_code}','https://'+host+'/cdn-cgi/trace'],timeout=12)
                        if r.stdout.strip()==b'200':good=True;break
                    except subprocess.SubprocessError:pass
                if not good:raise RuntimeError('positive_control_failed')
                box.policy({});p=box.launch(lab.SANDBOX_CHECK_CONFIG,True);p.wait(timeout=10)
                if p.returncode!=0:raise RuntimeError('core_launch_failed')
                if validate_client(box,lab.SANDBOX_CHECK_CONFIG,args.client_core) is not None:raise RuntimeError('client_core_launch_failed')
                box.stop();marker=box.work/'host-only.pem';marker.write_text('synthetic host canary')
                denied={'inbounds':[],'outbounds':[{'protocol':'trojan','settings':{'address':'1.1.1.1','port':443,'password':'synthetic'},'streamSettings':{'security':'tls','tlsSettings':{'certificates':[{'certificateFile':str(marker),'usage':'verify'}]}}}],'routing':{}}
                p=box.launch(json.dumps(denied).encode(),True);p.wait(timeout=10)
                if p.returncode==0 or b'no such file' not in box.logs():raise RuntimeError('filesystem_control_failed')
                box.stop()
        finally:cleanup(0,runid)
        return
    if args.slot is None or not 1<=args.slot<=max_slot:raise SystemExit('invalid slot')
    request=json.load(sys.stdin);plan=request['plan'];timeout=request['timeout']
    if not isinstance(timeout,int) or not 1<=timeout<=120 or not 1<=len(plan['candidates'])<=12:raise SystemExit('invalid request')
    runid=args.run_id or uuid.uuid4().hex[:6]
    rows=[];best=None
    native=all(c.get('engine')=='sing-box' for c in plan['candidates'])
    if any(c.get('engine')=='sing-box' for c in plan['candidates']) and not native:raise SystemExit('mixed core plan')
    if native and not pinned_core(NATIVE_CORE,NATIVE_SHA):raise SystemExit('native core mismatch')
    box_type=NativeBox if native else lab.Sandbox
    if PREFIX == 'csi':
        box_type = SideNativeBox if native else SideSandbox
    try:
        with box_type(NATIVE_CORE if native else args.core,runid,8192+args.slot,prefix=PREFIX) as box:
            if inspect_session is not None:
                box.inspect=lambda cfg: inspect_session(box,cfg,lab)
            def measure(c):
                before = box.oom_kills() if PREFIX == 'csi' else 0
                result = measure_candidate(box,c,timeout,args,native,session_check)
                if PREFIX == 'csi' and box.oom_kills() > before:
                    return dict(core='blocked', connection='not_run', code='probe_resource_or_signal_failure',
                                runtime_sha256='', endpoints_passed=0, evidence={})
                return result
            candidates = plan['candidates']
            if first_profile is not None:
                best, measure = first_profile(plan, measure)
                if best is not None:
                    rows.append(best)
                    candidates = ()
            for candidate in candidates:
                r=measure(candidate)
                if verify_raw is not None and r['code']=='passed':
                    r=verify_raw(r,candidate,plan,measure)
                if session_check is not None:
                    evidence=r.setdefault('evidence',{})
                    evidence.update(engine='sing-box' if native else 'xray',candidate_sha256=candidate['sha256'])
                r.update(sha256=candidate['sha256'],rule=candidate['rule']);rows.append(r)
                score=attempt_score(r,candidate)
                if session_check is not None:
                    # A plausible candidate with an unavailable test service
                    # cannot become a permanent rejection from a different one.
                    transient=r['core']=='blocked' or r['code'] in ('side_driver_unavailable','side_provider_unavailable','endpoint_dns_failed')
                    score=(r['code']=='passed',r.get('evidence',{}).get('raw_checks')=='failed',transient,r.get('endpoints_passed',0))

                if best is None or score>best_score:best=r;best_score=score
                if r['connection']=='passed' and r.get('code') in ('https_payload_verified','passed'):break
                if session_check is not None and r.get('evidence',{}).get('raw_checks')=='failed':break
        print(json.dumps(best|{'attempts':rows}))
    finally:cleanup(args.slot,runid)

if __name__=='__main__':main()
