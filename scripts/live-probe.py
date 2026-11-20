#!/usr/bin/env python3
"""Isolated Linux validation driver for the transient JSON conversion pipeline.

Root is needed only by the trusted supervisor for netns/nft/cgroups. Untrusted
configs execute as nobody in a read-only, capability-free mount/PID namespace.
Only pre-resolved public proxy endpoint IP:port pairs and DNS:53 can leave it.
Receipts contain hashes and bounded diagnosis codes, never credentials/logs.
"""
import argparse, base64, concurrent.futures, contextlib, copy, fcntl, hashlib, ipaddress
import json, os, pathlib, resource, signal, subprocess, importlib.util, select
import tempfile, threading, time, urllib.request, uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
IP = '/usr/sbin/ip' if pathlib.Path('/usr/sbin/ip').exists() else '/usr/bin/ip'
NFT = '/usr/sbin/nft'
TARGET = 'v2rayng-2.3.15-lib40-xray-26.10.31-and-26.11.9'
TESTS = [('https://www.gstatic.com/generate_204', 204), ('https://www.cloudflare.com/cdn-cgi/trace', 200)]
# The installer and supervisor both run this fixture in core configuration-check mode.
SANDBOX_CHECK_CONFIG = json.dumps({"outbounds": [{"protocol": "shadowsocks", "settings": {
    "servers": [{"address": "127.0.0.1", "port": 9, "method": "aes-128-gcm", "password": "sandbox-check"}]
}}]}).encode()
lock = threading.Lock()
STOP = threading.Event()
spec=importlib.util.spec_from_file_location("config_preflight",pathlib.Path(__file__).with_name("config-preflight.py"))
preflight=importlib.util.module_from_spec(spec);spec.loader.exec_module(preflight)

def digest(b): return hashlib.sha256(b).hexdigest()
def cmd(args, **kw): return subprocess.run(args, check=True, capture_output=True, **kw)
def classify(log, fallback):
    text = log.decode(errors='replace').lower() if isinstance(log, bytes) else log.lower()
    rules = [('feature "allowinsecure" has been removed','removed_allow_insecure'), ('without tls is prohibited','public_endpoint_requires_tls'), ('without tls or other encryption is prohibited','public_endpoint_requires_tls'), ('invalid uuid','invalid_uuid'),
        ('unknown config id','unsupported_protocol_or_transport'), ('unknown transport protocol','unsupported_transport'),
        ('flow has been removed','removed_trojan_flow'), ('reality: received real certificate','reality_authentication_rejected'), ('certificate signed by unknown authority','tls_untrusted_certificate'), ('certificate has expired','tls_expired_certificate'), ('certificate is valid for','tls_name_mismatch'), ('cannot validate certificate for','tls_name_mismatch'), ('failed to verify certificate','tls_certificate_failure'),
        ('reality:','reality_handshake_or_settings'), ('failed to parse','core_parse_failure'),
        ('cannot unmarshal','core_schema_mismatch'), ('no such file','missing_runtime_asset'),
        ('connection refused','endpoint_refused'), ('connection reset by peer','peer_reset_connection'), ('i/o timeout','connection_timeout'), ('operation timed out','connection_timeout'),
        ('network is unreachable','network_unreachable'), ('no such host','dns_failure'),
        ('authentication','authentication_failure'), ('eof','peer_closed_connection')]
    for needle, code in rules:
        if needle in text: return code
    return fallback

def download_endpoints(stream, depth=0):
    """Follow only native XHTTP download transports, with the core's extra precedence."""
    if depth > 16: raise ValueError('transport_dependency_depth')
    x=stream.get('xhttpSettings',stream.get('splithttpSettings',{}))
    holder=x.get('extra',x) if isinstance(x,dict) else {}
    if not isinstance(holder,dict): raise ValueError('invalid_download_settings')
    download=holder.get('downloadSettings')
    if download is None: return []
    if not isinstance(download,dict): raise ValueError('invalid_download_settings')
    # The pinned core dereferences an explicit download destination; no SNI/Host guessing.
    host=download.get('address');port=download.get('port',0)
    if not isinstance(host,str) or not host or not isinstance(port,int) or not 1<=port<=65535:
        raise ValueError('invalid_download_endpoint')
    return [(host,port)]+download_endpoints(download,depth+1)

def endpoints(config):
    """Never infer dial targets by recursively trusting arbitrary address keys."""
    preflight.require_enabled_config(config)
    config=preflight.logical_for_inspection(config)
    result=[];hopping={}
    for ob in config.get('outbounds',[]):
        protocol=ob.get('protocol');s=ob.get('settings',{})
        if protocol in {'freedom','blackhole','dns','loopback'}: continue
        if protocol not in preflight.PROXY_PROTOCOLS: raise ValueError('outbound_driver_pending')
        result.extend(download_endpoints(ob.get('streamSettings',{})))
        if protocol=='wireguard':
            for peer in s.get('peers',[]):
                host,sep,p=peer.get('endpoint','').rpartition(':')
                if not sep: raise ValueError('wireguard_endpoint_invalid')
                result.append((host.strip('[]'),int(p)))
        elif s.get('address'):
            result.append((s['address'],int(s.get('port',0))))
            hop=ob.get('streamSettings',{}).get('finalmask',{}).get('quicParams',{}).get('udpHop',{}).get('ports','')
            if hop:
                for entry in hop.split(','):
                    bounds=entry.strip().split('-')
                    if len(bounds)>2 or any(not x.strip().isdigit() or not 1<=int(x)<=65535 for x in bounds) or len(bounds)==2 and int(bounds[0])>int(bounds[1]):raise ValueError('port_hopping_invalid')
                    hopping.setdefault(s['address'],set()).add('-'.join(str(int(x)) for x in bounds))
        else:
            servers=s.get('vnext',s.get('servers',[]))
            for server in servers: result.append((server['address'],int(server['port'])))
    relays=preflight.relay_endpoints(config)
    result=[relays.get((host,port),(host,port)) for host,port in result]
    return resolve_endpoints(result, hopping)

def native_endpoints(config):
    preflight.require_enabled_config(config)
    pairs = []
    for ob in config.get('outbounds', []):
        typ = ob.get('type')
        if typ not in {'vless', 'vmess', 'trojan', 'shadowsocks'} or ob.get('detour') or ob.get('domain_resolver'):
            raise ValueError('native_path_unsupported')
        pairs.append((ob.get('server'), ob.get('server_port')))
    for endpoint in config.get('endpoints', []):
        if endpoint.get('type') != 'wireguard' or endpoint.get('system'):
            raise ValueError('native_path_unsupported')
        for peer in endpoint.get('peers', []):
            pairs.append((peer.get('address'), peer.get('port')))
    return resolve_endpoints(pairs, {})

def resolve_endpoints(result, hopping):
    if not result: raise ValueError('no_proxy_endpoint')
    resolved={};answers={}
    for host,port in result:
        if not isinstance(host,str) or not isinstance(port,int) or not 1<=port<=65535: raise ValueError('invalid_proxy_endpoint')
        # Resolver in a killable subprocess: a broken DNS lookup cannot stall the pool.
        helper='import socket,json,sys;print(json.dumps(sorted({x[4][0] for x in socket.getaddrinfo(sys.argv[1],None,socket.AF_UNSPEC,socket.SOCK_STREAM)})))'
        if host not in answers:
            try:
                answers[host] = [str(ipaddress.ip_address(host))]
            except ValueError:
                try: answers[host]=json.loads(cmd(['/usr/bin/python3','-c',helper,host],timeout=8).stdout)
                except (subprocess.SubprocessError,json.JSONDecodeError): raise ValueError('endpoint_dns_failed')
        ips=answers[host]
        if not ips or any(not ipaddress.ip_address(ip).is_global or ipaddress.ip_address(ip).is_multicast or ipaddress.ip_address(ip).is_reserved for ip in ips): raise ValueError('nonpublic_endpoint_blocked')
        previous=resolved.get(host,{})
        ports=set(previous.get('ports',[]))|{str(port)}|hopping.get(host,set())
        resolved[host]={'ips':ips,'port':port,'ports':sorted(ports)}
    return resolved

def runtime_config(config,resolved):
    return preflight.runtime_config(config,resolved)

# Disjoint /30 blocks for simultaneous worker scopes and trusted test adapters.
# Keep crw's existing block stable. Resource names/cleanup ownership do not change.
SANDBOX_ADDRESS_BASES={'crw':8192,'ctw':8288,'ctf':8384,'crr':8448,'crt':8480,'cge':8704,'cgt':8736,'csi':8768}

class Sandbox:
    def __init__(self, core, runid, index, prefix="crp"):
        self.core=pathlib.Path(core).resolve();self.name=prefix+runid[:6]+format(index,'x')
        self.table=self.name;self.hostif=self.name+'h';self.peer=self.name+'p'
        # /30 from the dedicated benchmark range; none of it is allowed as egress.
        if not 0<=index<32760: raise ValueError('namespace_address_capacity')
        address_index=index
        if prefix in SANDBOX_ADDRESS_BASES:
            slot=index-8192
            if not 0<=slot<32:raise ValueError('namespace_slot_capacity')
            address_index=SANDBOX_ADDRESS_BASES[prefix]+slot
        base=int(ipaddress.IPv4Address('198.18.0.0'))+4*(address_index+1)
        self.gateway=str(ipaddress.IPv4Address(base+1));self.addr=str(ipaddress.IPv4Address(base+2))
        v6base=int(ipaddress.IPv6Address('fd7c:636d:7200::'))+4*(address_index+1)
        self.gateway6=str(ipaddress.IPv6Address(v6base+1));self.addr6=str(ipaddress.IPv6Address(v6base+2));self.v6_ready=False;self.relay=None
        self.cg=pathlib.Path('/sys/fs/cgroup')/self.name;self.temp=None;self.process=None
    def __enter__(self):
        try:
            self.temp=tempfile.TemporaryDirectory(prefix=self.name+'-',dir='/dev/shm')
            self.work=pathlib.Path(self.temp.name);os.chmod(self.work,0o700)
            self.cg.mkdir();(self.cg/'memory.max').write_text(str(256*1024*1024));(self.cg/'pids.max').write_text('128');(self.cg/'cpu.max').write_text('100000 100000')
            cmd([IP,'netns','add',self.name]);cmd([IP,'link','add',self.hostif,'type','veth','peer','name',self.peer])
            cmd([IP,'link','set',self.peer,'netns',self.name]);cmd([IP,'addr','add',self.gateway+'/30','dev',self.hostif]);cmd([IP,'link','set',self.hostif,'up'])
            self.net([IP,'addr','add',self.addr+'/30','dev',self.peer]);self.net([IP,'link','set',self.peer,'up']);self.net([IP,'link','set','lo','up'])
            self.net([IP,'route','add','default','via',self.gateway])
            # Unique scoped NAT table. Never flush or modify pre-existing tables.
            cmd([NFT,'-f','-'],input=(f'table ip {self.table} {{ chain nat {{ type nat hook postrouting priority srcnat; policy accept; ip saddr {self.addr} oifname != "{self.hostif}" masquerade; }}; chain ingress {{ type filter hook input priority 0; policy accept; iifname "{self.hostif}" drop; }}; }}\n').encode())
            self.policy({})
            return self
        except BaseException:
            self.__exit__(None,None,None);raise
    def network_command(self): return [IP,'netns','exec',self.name]
    def launch_command(self): return ['/usr/bin/python3',str(pathlib.Path(__file__).resolve()),'--sandbox-launch',str(self.cg)]
    def net(self,args,**kw): return cmd(self.network_command()+args,**kw)
    def stop_relay(self):
        if self.relay:
            self.relay.terminate()
            try:self.relay.wait(timeout=2)
            except subprocess.TimeoutExpired:self.relay.kill();self.relay.wait()
            if self.relay.stdout:self.relay.stdout.close()
            self.relay=None
    def ipv6_relays(self,pairs):
        self.stop_relay()
        if not pairs:return []
        expanded=[]
        for ip,ports in pairs:
            if ipaddress.ip_address(ip).version!=6:continue
            bounds=ports.split('-');first=int(bounds[0]);last=int(bounds[-1])
            if last-first>127 or len(expanded)+last-first+1>128:raise ValueError('ipv6_endpoint_capacity')
            expanded.extend((ip,port) for port in range(first,last+1))
        if not expanded:return []
        # Never bridge to an address belonging to this host (the IPv4 sandbox
        # likewise drops its host input). Numeric targets prevent DNS rebinding.
        own={v.get('local') for link in json.loads(cmd([IP,'-j','-6','addr','show']).stdout) for v in link.get('addr_info',[])}
        if any(ip in own for ip,_ in expanded):raise ValueError('nonpublic_endpoint_blocked')
        if not self.v6_ready:
            cmd([IP,'-6','addr','add',self.gateway6+'/126','dev',self.hostif,'nodad'])
            self.net([IP,'-6','addr','add',self.addr6+'/126','dev',self.peer,'nodad'])
            self.net([IP,'-6','route','add','default','via',self.gateway6])
            hostmac=json.loads(cmd([IP,'-j','link','show',self.hostif]).stdout)[0]['address']
            peermac=json.loads(self.net([IP,'-j','link','show',self.peer]).stdout)[0]['address']
            cmd([IP,'-6','neigh','replace',self.addr6,'lladdr',peermac,'nud','permanent','dev',self.hostif])
            self.net([IP,'-6','neigh','replace',self.gateway6,'lladdr',hostmac,'nud','permanent','dev',self.peer])
            self.v6_ready=True
        self.relay=subprocess.Popen(['/usr/bin/python3',str(pathlib.Path(__file__).with_name('ipv6-endpoint-relay.py'))],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        (self.cg/'cgroup.procs').write_text(str(self.relay.pid))
        self.relay.stdin.write(json.dumps({'gateway':self.gateway6,'peer':self.addr6,'pairs':sorted(set(expanded))}).encode()+b'\n');self.relay.stdin.close()
        if not select.select([self.relay.stdout],[],[],5)[0]:raise ValueError('ipv6_relay_unavailable')
        mappings=json.loads(self.relay.stdout.readline(32768))
        ports=','.join(str(row[2]) for row in mappings)
        # This table is confined to this task's veth; no host forwarding,
        # default route or pre-existing firewall table is changed.
        subprocess.run([NFT,'delete','table','inet',self.table],capture_output=True)
        hostrules=f'table inet {self.table} {{ chain input {{ type filter hook input priority 0; policy accept; iifname "{self.hostif}" ip6 saddr {self.addr6} tcp dport {{ {ports} }} accept; iifname "{self.hostif}" ip6 saddr {self.addr6} udp dport {{ {ports} }} accept; iifname "{self.hostif}" meta nfproto ipv6 drop; }}; }}\n'
        cmd([NFT,'-f','-'],input=hostrules.encode())
        return mappings
    def policy(self,resolved):
        pairs=sorted({(ip,str(p)) for v in resolved.values() for ip in v['ips'] for p in v.get('ports',[v['port']])})
        mappings=self.ipv6_relays(pairs)
        allow='\n'.join(f'ip daddr {ip} tcp dport {p} accept\nip daddr {ip} udp dport {p} accept' for ip,p in pairs if ipaddress.ip_address(ip).version==4)
        allow+='\n'+'\n'.join(f'ip6 daddr {self.gateway6} tcp dport {local} accept\nip6 daddr {self.gateway6} udp dport {local} accept' for _,_,local in mappings)
        nat=''
        if mappings:
            rules='\n'.join(f'ip6 daddr {ip} tcp dport {port} dnat ip6 to [{self.gateway6}]:{local}\nip6 daddr {ip} udp dport {port} dnat ip6 to [{self.gateway6}]:{local}' for ip,port,local in mappings)
            nat='table inet endpoint_nat { chain out { type nat hook output priority dstnat; policy accept; '+rules+'\n}; }\n'
        # Only namespace-local rules are replaced. Both families remain closed
        # except pre-resolved endpoint tuples; the exact config stays unchanged.
        rules='flush ruleset\n'+nat+'table inet guard { chain out { type filter hook output priority 0; policy drop; oifname "lo" accept; '+allow+'\n}; chain in { type filter hook input priority 0; policy drop; iifname "lo" accept; ct state established,related accept; }; }\n'
        self.net([NFT,'-f','-'],input=rules.encode())
    def inspect(self,config):
        resolved=endpoints(config);runtime_config(config,resolved);return resolved
    def core_mounts(self):
        return []
    def core_command(self,test):
        return ['/xray','run']+(['-test'] if test else [])+['-c','/config.json']
    def launch(self,b,test=False):
        preflight.require_enabled_config(preflight.parse_runtime_config(b))
        (self.work/'config.json').write_bytes(b);os.chmod(self.work/'config.json',0o444)
        (self.work/'hosts').write_text('127.0.0.1 localhost\n'+''.join(ip+' '+host+'\n' for host,entry in getattr(self,'resolved',{}).items() for ip in entry['ips']))
        (self.work/'resolv.conf').write_text('nameserver 1.1.1.1\noptions timeout:2 attempts:1\n')
        args=self.network_command()+['/usr/bin/bwrap','--unshare-user','--unshare-pid','--unshare-ipc','--unshare-uts','--unshare-cgroup','--die-with-parent','--new-session','--cap-drop','ALL','--uid','65534','--gid','65534','--clearenv','--setenv','SSL_CERT_FILE','/etc/ssl/certs/ca-certificates.crt','--setenv','GOMAXPROCS','1','--setenv','GOMEMLIMIT','128MiB','--setenv','XRAY_LOCATION_ASSET','/assets','--ro-bind','/etc/ssl/certs/ca-certificates.crt','/etc/ssl/certs/ca-certificates.crt','--ro-bind',str(self.core),'/xray','--ro-bind',str(self.work/'config.json'),'/config.json','--ro-bind',str(self.work/'resolv.conf'),'/etc/resolv.conf','--ro-bind',str(self.work/'hosts'),'/etc/hosts','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--dir','/assets']
        for name in ['geoip.dat','geosite.dat']:
            asset=self.core.parent/name
            if asset.exists():args+=['--ro-bind',str(asset),'/assets/'+name]
        args+=self.core_mounts()+['--']+self.core_command(test)
        self.log=tempfile.TemporaryFile(dir='/dev/shm')
        self.process=subprocess.Popen(self.launch_command()+args,stdout=self.log,stderr=subprocess.STDOUT,start_new_session=True)
        return self.process
    def logs(self):
        self.log.seek(0);return self.log.read(128*1024)
    def stop(self):
        self.stop_relay()
        if self.process:
            with contextlib.suppress(ProcessLookupError):os.killpg(self.process.pid,signal.SIGKILL)
            with contextlib.suppress(subprocess.TimeoutExpired):self.process.wait(timeout=3)
            if (self.cg/'cgroup.kill').exists(): (self.cg/'cgroup.kill').write_text('1')
            self.process=None
        if hasattr(self,'log'):self.log.close()
    def __exit__(self,*exc):
        self.stop()
        for args in [[NFT,'delete','table','inet',self.table],[NFT,'delete','table','ip',self.table],[IP,'link','del',self.hostif],[IP,'netns','del',self.name]]:
            subprocess.run(args,capture_output=True)
        for _ in range(20):
            try:self.cg.rmdir();break
            except FileNotFoundError:break
            except OSError:time.sleep(.05)
        if self.temp:self.temp.cleanup()

def application_site_check(box, timeout):
    # An HTTPing success elsewhere does not prove the application's TLS path.
    # Bound response size/time and require HTTPS success without disabling TLS.
    args=[IP,'netns','exec',box.name,'/usr/bin/curl','--noproxy','','--proxy','socks5h://127.0.0.1:10808','--max-time',str(timeout),'--connect-timeout',str(timeout),'--range','0-65535','--max-filesize','2097152','--silent','--output','/dev/null','--write-out','%{http_code}','https://www.instagram.com/']
    try:
        r=subprocess.run(args,capture_output=True,timeout=timeout+2,env={'PATH':'/usr/bin:/usr/sbin'})
        return r.returncode==0 and r.stdout.strip() in (b'200',b'206')
    except (OSError,subprocess.SubprocessError):
        return False

def test_candidate(box,candidate,timeout,validated_sha256=None,session_check=None):
    b=base64.b64decode(candidate['config'],validate=True)
    if digest(b)!=candidate['sha256']: raise ValueError('candidate_hash_mismatch')
    result={'core':'not_run','connection':'not_run','code':'not_run','runtime_sha256':'','endpoints_passed':0}
    box.policy({})
    # Only the trusted one-job caller can reuse its immediately preceding
    # exact-byte, same-core syntax check. This is never connection evidence.
    if validated_sha256 != candidate['sha256']:
        p=box.launch(b,True)
        try:p.wait(timeout=10)
        except subprocess.TimeoutExpired:result['code']='core_validation_timeout';box.stop();return result
        log=box.logs();rc=p.returncode;box.stop()
        if rc!=0:
            code=classify(log,'core_rejected')
            if getattr(box,'driver','xray')=='xray' and not log.startswith(b'Xray '):code='probe_infrastructure_error'
            if rc<0:code='probe_resource_or_signal_failure'
            blocked=code in {'missing_runtime_asset','probe_infrastructure_error','probe_resource_or_signal_failure'}
            result.update(core='blocked' if blocked else 'failed',code=code);return result
    result['core']='passed'
    try:
        config=preflight.parse_runtime_config(b);resolved=box.inspect(config)
    except (ValueError,TypeError,KeyError) as e:
        if session_check is not None and str(e) in {'nonloopback_listener_not_qualified','listener_port_conflict','probe_socks_contract_missing','direct_route_not_qualified','direct_default_not_qualified','native_path_unsupported','native_route_unqualified'}:
            result['code']=str(e)
            return result
        code=str(e);result['code']=code if code in {'protocol_disabled','outbound_driver_pending','wireguard_endpoint_invalid','no_proxy_endpoint','invalid_proxy_endpoint','endpoint_dns_failed','nonpublic_endpoint_blocked','ipv6_only_probe_pending','ipv6_relay_unavailable','ipv6_endpoint_capacity','custom_dns_mapping_requires_review','invalid_download_settings','invalid_download_endpoint','transport_dependency_depth','port_hopping_invalid'} else 'probe_preparation_failed';return result
    box.resolved=resolved
    # Explicit bootstrap DoH may reach its fixed resolver; app DNS stays routed.
    for server in config.get('dns',{}).get('servers',[]):
        address=server.get('address','') if isinstance(server,dict) else server
        if address in ('https+local://1.1.1.1/dns-query','https+local://8.8.8.8/dns-query'):
            ip=address.split('/')[2];resolved['bootstrap-'+ip]={'ips':[ip],'port':443}
    box.policy(resolved);runtime_bytes=b;result['runtime_sha256']=digest(runtime_bytes)
    p=box.launch(runtime_bytes);codes=[];curl_errors=[]
    # Readiness waits are local and do not reject slow remote proxies with TCP ping.
    ready=False
    for _ in range(30):
        if p.poll() is not None:break
        port=getattr(box,'side_port',10808) if session_check is not None else 10808
        check=box.net(['/usr/bin/python3','-c','import socket,sys; s=socket.socket();s.settimeout(.1); print(s.connect_ex(("127.0.0.1",int(sys.argv[1]))))',str(port)])
        if check.stdout.strip()==b'0':ready=True;break
        time.sleep(.1)
    if session_check is not None:
        try:
            if ready:
                result.update(session_check(box,timeout))
            else:
                result.update(connection='failed',code=classify(box.logs(),'runtime_start_failed'))
        finally:
            box.stop()
        return result
    def https_check(test):
        url,expected=test;error=b""
        args=[IP,'netns','exec',box.name,'/usr/bin/curl','--noproxy','','--proxy','socks5h://127.0.0.1:10808','--max-time',str(timeout),'--connect-timeout',str(timeout),'--max-filesize','65536','--retry','1','--retry-all-errors','--retry-delay','0','--retry-max-time',str(timeout),'--silent','--show-error','--output','/dev/null','--write-out','%{http_code}',url]
        if config.get('burstObservatory'):
            # Cold leastLoad has no successful observation yet. Retry the
            # SAME final runtime through SOCKS; never substitute a member.
            args[args.index('--max-time')+1]=str(min(timeout,4))
            args[args.index('--connect-timeout')+1]=str(min(timeout,4))
            args+=['--retry','4','--retry-all-errors','--retry-delay','1','--retry-max-time',str(min(15,timeout+5))]
        try:
            r=subprocess.run(args,capture_output=True,timeout=timeout+20,env={'PATH':'/usr/bin:/usr/sbin'})
            passed=r.returncode==0 and r.stdout.strip()==str(expected).encode()
            if not passed: error=r.stderr[-4096:]
        except subprocess.TimeoutExpired:
            passed=False;error=b'operation timed out'
        return passed,error
    if ready:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            outcomes=list(pool.map(https_check,TESTS))
        codes=[passed for passed,_ in outcomes];curl_errors=[error for passed,error in outcomes if not passed]
    site_ok=False
    evidence={'https':'passed' if len(codes)==2 and all(codes) else 'failed','http3':'not_run','android':'not_run'}
    def transport_checks():
        checks_out={}
        try:
            tcp_only={o.get('protocol') for o in config.get('outbounds',[]) if o.get('protocol') not in ('freedom','blackhole','dns','loopback')}=={'http'}
            checks=box.net(['/usr/bin/python3',str(pathlib.Path(__file__).with_name('transport-checks.py')),'--timeout',str(min(timeout,6))]+(['--tcp-only'] if tcp_only else []),timeout=min(timeout,6)*4+5)
            report=json.loads(checks.stdout)
            checks_out.update({x['name']:x['status'] for x in report['checks']})
            checks_out['http3']=report['http3']
            h3python=pathlib.Path('/opt/config-repair/http3-venv/bin/python')
            if not tcp_only and h3python.exists():
                response=box.net([str(h3python),str(pathlib.Path(__file__).with_name('http3-check.py')),str(min(timeout,8))],timeout=min(timeout,8)+3)
                checks_out['http3']=json.loads(response.stdout)['status']
        except (OSError,ValueError,subprocess.SubprocessError):checks_out['transport']='infrastructure_error'
        return checks_out
    def payload_checks():
        checks_out={}
        try:
            q=box.net(['/usr/bin/python3',str(pathlib.Path(__file__).with_name('payload-quality.py')),str(timeout)],timeout=2*max(20,min(45,timeout))+110)
            quality=json.loads(q.stdout)
            if not isinstance(quality,dict):raise ValueError('invalid payload receipt')
            checks_out.update(quality)
        except (OSError,ValueError,subprocess.SubprocessError):
            checks_out['payload_version']='payload_v1'
            checks_out['payload_download']='infrastructure_error'
        return checks_out
    # Independent checks share the same exact core session. The pool is bounded;
    # all children finish before teardown and every original evidence gate remains.
    if ready and len(codes)==2 and all(codes):
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            site=pool.submit(application_site_check,box,timeout)
            transports=pool.submit(transport_checks)
            payloads=pool.submit(payload_checks)
            site_ok=site.result();evidence.update(transports.result());evidence.update(payloads.result())
    payload_ok=evidence.get('payload_version')=='payload_v1' and all(evidence.get('payload_'+k)=='passed' for k in ('download','upload','recheck')) and evidence.get('payload_download_bytes')=='2097152' and evidence.get('payload_upload_bytes')=='1048576'
    result['evidence']=evidence
    log=box.logs();box.stop();result['endpoints_passed']=sum(codes)
    if codes and all(codes):result.update(connection='passed',code=('https_payload_verified' if payload_ok else 'https_payload_incomplete') if site_ok else 'https_proxy_verified_site_unavailable')
    elif any(codes):result.update(connection='partial',code='test_destination_partial')
    else:result.update(connection='failed',code=classify(log,classify(b'\n'.join(curl_errors),'proxy_request_failed' if ready else 'runtime_start_failed')))
    if result['connection']=='passed' and (any(evidence.get(k)!='passed' for k in ('dns_tcp','doh_cloudflare','doh_google')) or evidence.get('dns_udp') not in ('passed','unsupported') or (evidence.get('quic_vn') not in ('passed','unsupported') and evidence.get('http3')!='passed')):
        result.update(connection='partial',code='transport_verification_incomplete')
    if result['connection']=='passed' and not payload_ok:
        result.update(connection='partial',code='https_payload_incomplete')
    return result

if __name__=='__main__':
    import sys
    if len(sys.argv)>2 and sys.argv[1]=='--sandbox-launch':
        cg=pathlib.Path(sys.argv[2]);(cg/'cgroup.procs').write_text(str(os.getpid()))
        resource.setrlimit(resource.RLIMIT_NOFILE,(256,256));resource.setrlimit(resource.RLIMIT_FSIZE,(1024*1024,1024*1024));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        os.execv(sys.argv[3],sys.argv[3:])
    raise SystemExit("use probe-one.py")
