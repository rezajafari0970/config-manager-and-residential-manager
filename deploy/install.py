#!/usr/bin/env python3
"""Root-only, bounded installer. Private state is never part of the source tree."""
import base64, contextlib, fcntl, hashlib, importlib.util, ipaddress, json, os, pathlib, pwd, re, secrets, shutil, socket, subprocess, sys, tarfile, tempfile, time, urllib.request, zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
OPT=pathlib.Path('/opt/config-repair'); ETC=pathlib.Path('/etc/config-repair'); DATA=pathlib.Path('/var/lib/config-repair')
SERVICES=['config-repair','config-repair-prober','config-repair-egress']
DATA_UPDATERS=['config-repair-country-update','config-repair-network-update']
MARKER=OPT/'installer.json'

def run(*args,**kw):
    return subprocess.run([str(x) for x in args],check=True,**kw)
def sha(path):
    with pathlib.Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def write(path,text,mode=0o600):
    path=pathlib.Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(path.name+'.install-new');tmp.write_text(text);tmp.chmod(mode);os.replace(tmp,path)
def download(url,path,pin=None):
    run('bash',ROOT/'install.sh','--download',url,path,'268435456',pin or '')
def valid_host(value):
    try:ip=ipaddress.ip_address(value);return str(ip)
    except ValueError:
        if len(value)>253 or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?',value):raise ValueError('CMRM_HOST must be an IP or DNS name')
        return value.lower()
def socket_free(port):
    with socket.socket() as s:s.bind(('0.0.0.0',port))
def health(origin,timeout=45):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        try:
            with urllib.request.urlopen('http://127.0.0.1:18191/healthz',timeout=2) as r:
                if r.status==200:return
        except Exception:pass
        time.sleep(1)
    raise RuntimeError('Panel health failed; inspect journalctl -u config-repair')
def sandbox_check(source,core):
    spec=importlib.util.spec_from_file_location('install_sandbox',source/'scripts/live-probe.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    # ctf is the dedicated fixture scope; no other application's resources touched.
    controllers=pathlib.Path('/sys/fs/cgroup/cgroup.subtree_control')
    current=set(controllers.read_text().split())
    required={'cpu','memory','pids'}
    if required-current:controllers.write_text(' '.join('+'+v for v in sorted(required-current)))
    with mod.Sandbox(core,secrets.token_hex(3),8192,prefix='ctf') as box:
        p=box.launch(mod.SANDBOX_CHECK_CONFIG, True)
        p.wait(timeout=20)
        if p.returncode:raise RuntimeError('Kernel sandbox test failed: namespaces/cgroups/nftables/bubblewrap are required')
def main():
    if os.geteuid()!=0 or sys.version_info<(3,11):raise RuntimeError('Root and Python 3.11+ required')
    os.umask(0o077)
    lock=open('/var/lock/config-repair-deploy.lock','a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    owned=MARKER.exists()
    existing=owned and (ETC/'panel.json').exists() and (ETC/'access.txt').exists()
    if not owned and any(p.exists() for p in (ETC,DATA,OPT)):
        raise RuntimeError('Existing unmanaged installation found. Preserve its key/data and use the documented migration procedure.')
    old=json.loads(MARKER.read_text()) if owned else {}
    if old.get('product','cmrm')!='cmrm':raise RuntimeError('Installation ownership mismatch')
    if not pathlib.Path('/sys/fs/cgroup/cgroup.controllers').is_file():raise RuntimeError('cgroup v2 required')
    if shutil.disk_usage('/').free<2*1024**3:raise RuntimeError('At least 2 GiB free disk is required for build and backup')
    memory=int(next(x.split()[1] for x in pathlib.Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemTotal:')))*1024
    if memory<1024**3:raise RuntimeError('At least 1 GiB RAM required; 2 GiB or more recommended')
    port=int(os.environ.get('CMRM_PORT',old.get('port',18443)))
    if not 1024<=port<=65535 or port==18191:raise ValueError('CMRM_PORT must be 1024..65535, excluding 18191')
    if existing and port!=old['port']:raise ValueError('Port changes require an explicit reverse proxy/configuration update')
    host=os.environ.get('CMRM_HOST',old.get('host',''))
    if not host:
        routes=json.loads(subprocess.check_output(['ip','-j','route','get','1.1.1.1']))
        host=routes[0].get('prefsrc','')
    host=valid_host(host)
    if existing and host!=old['host']:raise ValueError('Host changes require an explicit origin/certificate update')
    authority=('['+host+']' if ':' in host else host)+':'+str(port);origin='https://'+authority
    if not existing:socket_free(port);socket_free(18191)
    print('Preparing Config manager and residential manager...',flush=True)
    deps=json.loads((ROOT/'deploy/dependencies.json').read_text())
    source_hash=hashlib.sha256()
    for p in sorted(ROOT.rglob('*')):
        rel=p.relative_to(ROOT)
        if p.is_file() and not any(x.startswith('.') or x in ('bin','__pycache__') for x in rel.parts):
            source_hash.update(str(rel).encode());source_hash.update(bytes.fromhex(sha(p)))
    release_id='cmrm-'+source_hash.hexdigest()[:16]
    OPT.mkdir(parents=True,exist_ok=True,mode=0o755);OPT.chmod(0o755)
    write(MARKER,json.dumps(dict(product='cmrm',release=old.get('release','pending'),port=port,host=host))+'\n')
    with tempfile.TemporaryDirectory(prefix='cmrm-build-',dir='/var/tmp') as work:
        work=pathlib.Path(work)
        # Download and verify runtime binaries before changing any running service.
        for item in deps['xray']:
            dest=OPT/('core-'+item['version']);binary=dest/'xray'
            if binary.exists() and sha(binary)==item['sha256']:continue
            archive=work/'xray.zip';download('https://github.com/XTLS/Xray-core/releases/download/v'+item['version']+'/Xray-linux-64.zip',archive,item['archive_sha256'])
            dest.mkdir(exist_ok=True)
            with zipfile.ZipFile(archive) as z:
                for name in ('xray','geoip.dat','geosite.dat'):
                    if name not in z.namelist():continue
                    if z.getinfo(name).file_size>150*1024**2:raise RuntimeError('Core asset exceeds size limit')
                    p=work/name;p.write_bytes(z.read(name))
                    if name=='xray' and sha(p)!=item['sha256']:raise RuntimeError('Xray binary checksum mismatch')
                    p.chmod(0o755 if name=='xray' else 0o644);os.replace(p,dest/name)
        item=deps['sing_box'];dest=OPT/('sing-box-'+item['version']);binary=dest/'sing-box'
        if not binary.exists() or sha(binary)!=item['sha256']:
            archive=work/'sing.tar.gz';download(item['url'],archive,item['archive_sha256'])
            with tarfile.open(archive) as t:
                members=[m for m in t if m.isfile() and pathlib.PurePosixPath(m.name).name=='sing-box']
                if len(members)!=1 or members[0].size>150*1024**2:raise RuntimeError('Invalid sing-box archive')
                p=work/'sing-box';p.write_bytes(t.extractfile(members[0]).read())
            if sha(p)!=item['sha256']:raise RuntimeError('sing-box binary checksum mismatch')
            dest.mkdir(exist_ok=True);p.chmod(0o755);os.replace(p,binary)
        venv=OPT/'http3-venv'
        if not (venv/'bin/python').exists():run(sys.executable,'-m','venv',venv)
        print('[install] Installing HTTP/3 Python dependencies...',flush=True)
        run(venv/'bin/python','-m','pip','install','--disable-pip-version-check','--timeout','20','--retries','2','aioquic=='+deps['aioquic'])
        print('[install] Checking kernel sandbox support...',flush=True)
        sandbox_check(ROOT,OPT/'core-26.11.9/xray')
        release=OPT/'releases'/release_id
        if not (release/'build-complete').exists():
            archive=work/'go.tar.gz';download(deps['go']['url'],archive,deps['go']['sha256'])
            with tarfile.open(archive) as t:t.extractall(work,filter='data')
            stage=work/'release';stage.mkdir()
            env=dict(os.environ,GOMAXPROCS='2',GOFLAGS='-p=1',GOTOOLCHAIN='local',GOCACHE=str(work/'go-cache'),GOMODCACHE=str(work/'go-mod'),CGO_ENABLED='0')
            for name in ('config-panel','config-probe-worker','config-egress-worker','config-compat','config-repair','config-probe-plan','config-route-audit'):
                print('[build] '+name+' (compilation may take several minutes)...',flush=True)
                run(work/'go/bin/go','build','-mod=readonly','-trimpath','-buildvcs=false','-o',stage/name,'./cmd/'+name,cwd=ROOT,env=env)
            shutil.copytree(ROOT/'scripts',stage/'scripts',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
            shutil.copytree(ROOT/'deploy',stage/'deploy')
            shutil.copytree(ROOT/'docs',stage/'docs')
            for name in ('README.md','THIRD_PARTY.md'):shutil.copy2(ROOT/name,stage/name)
            (stage/'build-complete').write_text(release_id+'\n');release.parent.mkdir(exist_ok=True,mode=0o755);release.parent.chmod(0o755)
            if release.exists():shutil.rmtree(release)
            shutil.copytree(stage,release)
            for p in release.rglob('*'):p.chmod(0o755 if p.is_dir() or (p.parent==release and p.name.startswith('config-')) else 0o644)
            release.chmod(0o755)
    # Validate TLS and nginx before stopping the live installation.
    run('nginx','-t')
    if not existing and bool(os.environ.get('CMRM_TLS_CERT'))!=bool(os.environ.get('CMRM_TLS_KEY')):raise ValueError('Set both CMRM_TLS_CERT and CMRM_TLS_KEY')
    ETC.mkdir(exist_ok=True,mode=0o750);DATA.mkdir(exist_ok=True,mode=0o700)
    try:user=pwd.getpwnam('config-repair')
    except KeyError:
        run('useradd','--system','--home-dir',DATA,'--shell','/usr/sbin/nologin','config-repair');user=pwd.getpwnam('config-repair')
    os.chown(DATA,user.pw_uid,user.pw_gid);os.chown(ETC,0,user.pw_gid)
    budget=DATA/'resource-budget';budget.mkdir(exist_ok=True);os.chown(budget,user.pw_uid,user.pw_gid);budget.chmod(0o2770)
    backup=None
    if existing and old.get('release')!=release_id:
        backup=DATA.parent/('config-repair-backup-'+str(int(time.time())))
        backup.mkdir(mode=0o700)
        if pathlib.Path('/etc/systemd/system/config-repair-network-update.timer').exists():
            run('systemctl','stop','config-repair-network-update.timer','config-repair-network-update.service')
        run('systemctl','stop',*SERVICES)
        # A stopped SQLite file, WAL, blobs, key and configuration form one snapshot.
        shutil.copytree(ETC,backup/'etc');shutil.copytree(DATA,backup/'data',copy_function=shutil.copy2,ignore=shutil.ignore_patterns('probe.sock'))
        (backup/'release').write_text(str((OPT/'current').resolve()))
    if not existing:
        if (DATA/'panel.db').exists():raise RuntimeError('Database present without complete credentials; manual recovery required')
        config=dict(listen='127.0.0.1:18191',public_origin=origin,database=str(DATA/'panel.db'),master_key=base64.b64encode(secrets.token_bytes(32)).decode())
        write(ETC/'panel.json',json.dumps(config,indent=2)+'\n',0o640);os.chown(ETC/'panel.json',0,user.pw_gid)
        password=secrets.token_urlsafe(24)
        digest=subprocess.check_output(['openssl','passwd','-6','-stdin'],input=(password+'\n').encode()).decode().strip()
        write(ETC/'htpasswd','admin:'+digest+'\n',0o640)
        os.chown(ETC/'htpasswd',0,pwd.getpwnam('www-data').pw_gid)
        # nginx master reads certificates; worker needs only htpasswd access.
        ETC.chmod(0o751)
        cert=os.environ.get('CMRM_TLS_CERT');key=os.environ.get('CMRM_TLS_KEY')
        if bool(cert)!=bool(key):raise ValueError('Set both CMRM_TLS_CERT and CMRM_TLS_KEY')
        if cert:shutil.copyfile(cert,ETC/'tls.crt');shutil.copyfile(key,ETC/'tls.key')
        else:
            try:ipaddress.ip_address(host);san='IP:'+host
            except ValueError:san='DNS:'+host
            run('openssl','req','-x509','-newkey','rsa:3072','-sha256','-nodes','-days','365','-subj','/CN='+host,'-addext','subjectAltName='+san,'-keyout',ETC/'tls.key','-out',ETC/'tls.crt',stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        (ETC/'tls.key').chmod(0o600);(ETC/'tls.crt').chmod(0o644)
        write(ETC/'access.txt',f'URL: {origin}\nUser: admin\nPassword: {password}\nTLS: '+('operator certificate' if cert else 'self-signed; install a trusted certificate for subscriptions')+'\n')
    proxy='''proxy_pass http://127.0.0.1:18191; proxy_set_header Host $http_host; proxy_set_header X-Forwarded-Proto https; proxy_set_header X-Real-IP $remote_addr; proxy_read_timeout 130s; proxy_request_buffering off; proxy_buffering off;'''
    nginx=f'''# Managed by Config manager and residential manager\nserver {{\n listen {port} ssl;\n server_name {host};\n ssl_certificate /etc/config-repair/tls.crt;\n ssl_certificate_key /etc/config-repair/tls.key;\n ssl_protocols TLSv1.2 TLSv1.3;\n access_log off; server_tokens off; client_max_body_size 0;\n auth_basic "Config manager and residential manager"; auth_basic_user_file /etc/config-repair/htpasswd;\n location = /healthz {{ return 404; }}\n location /subscription/ {{ auth_basic off; {proxy} }}\n location /egress-subscription/ {{ auth_basic off; {proxy} }}\n location / {{ {proxy} }}\n}}\n'''
    conf=pathlib.Path('/etc/nginx/conf.d/config-manager-residential.conf')
    if conf.exists() and not owned:raise RuntimeError('Reverse proxy config already exists')
    write(conf,nginx,0o644);run('nginx','-t')
    write('/etc/sysctl.d/90-config-manager-residential.conf','net.ipv4.ip_forward=1\n',0o644)
    run('sysctl','-w','net.ipv4.ip_forward=1')
    for name in SERVICES+DATA_UPDATERS:
        shutil.copy2(ROOT/'deploy'/(name+'.service'),pathlib.Path('/etc/systemd/system')/(name+'.service'))
    timers=[name+'.timer' for name in DATA_UPDATERS]
    for timer in timers:
        shutil.copy2(ROOT/'deploy'/timer,pathlib.Path('/etc/systemd/system')/timer)
    (DATA/'country').mkdir(exist_ok=True,mode=0o700)
    network=DATA/'network'
    network.mkdir(exist_ok=True,mode=0o700)
    os.chown(network,user.pw_uid,user.pw_gid)
    link=OPT/'current.install-new';link.unlink(missing_ok=True);link.symlink_to(release);os.replace(link,OPT/'current')
    write(MARKER,json.dumps(dict(product='cmrm',release=release_id,port=port,host=host),indent=2)+'\n')
    print('[install] Starting application services...',flush=True)
    run('systemctl','daemon-reload')
    run('systemctl','enable',*SERVICES,*timers,'nginx')
    run('systemctl','restart',*SERVICES)
    run('systemctl','start',*timers,'nginx')
    run('systemctl','start','--no-block','config-repair-network-update.service')
    run('systemctl','reload','nginx')
    health(origin)
    run('systemctl','is-active',*SERVICES)
    # Country refresh is bounded; readiness is reported, never silently assumed.
    print('[install] Updating country data...',flush=True)
    run('systemctl','start','config-repair-country-update.service')
    geo=ETC/'egress-country.json'
    ready=geo.exists() and len(json.loads(geo.read_text()).get('providers',[]))>=2
    print('\nInstallation running. '+('Both country providers ready.' if ready else 'Country data incomplete; automatic retries are enabled. Residential checks fail closed.'))
    print((ETC/'access.txt').read_text())
    print('Allow TCP '+str(port)+' in your provider firewall. Existing firewall rules were not changed.')
    if backup:print('Preserved stopped backup: '+str(backup)+'. Never restore it over resumed writes without reconciling subsequent changes.')
if __name__=='__main__':
    try:main()
    except Exception as e:print('INSTALLATION FAILED: '+str(e),file=sys.stderr);sys.exit(1)
