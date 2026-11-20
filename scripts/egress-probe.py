#!/usr/bin/env python3
"""Trusted driver orchestrator. Configs enter exclusively through stdin.
Each job owns one isolated netns/cgroup. Core fallback never weakens TLS.
"""
import concurrent.futures
import argparse,base64,hashlib,hmac,secrets,fcntl,ipaddress,contextlib,importlib.util,json,os,pathlib,re,signal,subprocess,sys,threading,time
HERE=pathlib.Path(__file__).resolve().parent
def module(name,file):
 spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
lab=module('egress_lab','live-probe.py');scope=module('egress_scope','egress-preflight.py');country=module('egress_country','egress-country.py');sessions=module('egress_sessions','egress-session.py');scheduling=module('egress_scheduling','egress-scheduling.py')
exit_network=module('egress_network','egress-network.py')
CORES=[('xray-26.11.9','/opt/config-repair/core-26.11.9/xray','e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d'),('xray-26.10.31','/opt/config-repair/core-26.10.31/xray','cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1'),('xray-26.7.28','/opt/config-repair/core-26.7.28/xray','64d46afb80adea1bf97a0d467e83f4a9ac1ebd0995891e84bca3f1a1d1affb1d'),('xray-26.5.9','/opt/config-repair/core-26.5.9/xray','b2c525e082cf2fef460499c88838d355f0b9bfb5a00bdb3eaa99b6af63825006')]
NATIVE=('sing-box-1.14.4','/opt/config-repair/sing-box-1.14.4/sing-box','1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a')
def cleanup(prefix,slot=None,run=None):
 # Reuse only the shared sandbox's resource deletion mechanics, with a new
 # disjoint ownership regex. Never delete another pipeline's namespaces.
 parent=pathlib.Path('/sys/fs/cgroup')/(prefix+'-sandboxes')
 owned=re.compile('^'+prefix+r'[0-9a-f]{6}20[01][0-9a-f]$')
 children=[p for p in parent.glob(prefix+'*') if owned.fullmatch(p.name) and (slot is None or p.name.endswith(format(8192+slot,'x'))) and (run is None or p.name.startswith(prefix+run))]
 for p in children:
  with contextlib.suppress(OSError):(p/'cgroup.kill').write_text('1')
 adapter=module('egress_cleanup','probe-one.py');adapter.PREFIX=prefix;adapter.OWN=re.compile('^'+prefix+r'[0-9a-f]{6}20[01][0-9a-f]$');adapter.cleanup(slot,run)
 for p in children:
  with contextlib.suppress(OSError):p.rmdir()
class EgressBox(lab.Sandbox):
 def __init__(self,core,runid,index,prefix='cge'):
  super().__init__(core,runid,index,prefix)
  parent=pathlib.Path('/sys/fs/cgroup')/(prefix+'-sandboxes')
  with open('/run/'+prefix+'-sandbox-budget.lock','a') as lock:
   fcntl.flock(lock,fcntl.LOCK_EX);parent.mkdir(exist_ok=True)
   (parent/'memory.max').write_text(str(1024*1024*1024));(parent/'pids.max').write_text('4096');(parent/'cpu.max').write_text('200000 100000')
   (parent/'cgroup.subtree_control').write_text('+memory +pids +cpu')
  self.cg=parent/self.name;self.policy_key=None
 def network_command(self):return ['/usr/bin/nsenter','--net=/run/netns/'+self.name,'--']
 def launch_command(self):return ['/usr/bin/python3',str(HERE/'egress-launch.py'),str(self.cg)]
 def policy(self,resolved):
  key=json.dumps(resolved,sort_keys=True,separators=(',',':'))
  if key==getattr(self,'policy_key',None):return
  self.policy_key=None
  super().policy(resolved);self.policy_key=key
class NativeBox(EgressBox):
 def core_mounts(self):
  out=['--ro-bind','/lib64/ld-linux-x86-64.so.2','/lib64/ld-linux-x86-64.so.2']
  for name in ('libdl.so.2','libpthread.so.0','libc.so.6'):out+=['--ro-bind','/usr/lib/x86_64-linux-gnu/'+name,'/lib/x86_64-linux-gnu/'+name]
  return out
 def core_command(self,test):return ['/xray','check' if test else 'run','-c','/config.json']
class SessionBox(EgressBox):
 driver='xray'
 def core_mounts(self):return NativeBox.core_mounts(self) if self.driver!='xray' else []
 def core_command(self,test):return NativeBox.core_command(self,test) if self.driver!='xray' else lab.Sandbox.core_command(self,test)
class ResourcePool:
 def __init__(self,args):
  self.args=args;self.box=None;self.pins={};self.geo=country.Registry()
  self.network=exit_network.NetworkRegistry()
 def __enter__(self):return self
 def __exit__(self,*exc):self.close();self.geo.close();self.network.close()
 def close(self):
  if self.box is not None:
   box=self.box;self.box=None;box.__exit__(None,None,None)
 def verify(self,path,pin):
  p=pathlib.Path(path);st=p.stat();key=(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,pin)
  if self.pins.get(path)!=key:
   with p.open('rb') as f:actual=hashlib.file_digest(f,'sha256').hexdigest()
   if actual!=pin:raise ValueError('core_pin_mismatch')
   self.pins[path]=key
 @contextlib.contextmanager
 def lease(self,path,driver):
  try:
   if self.box is None:
    box=SessionBox(path,self.args.run_id,8192+self.args.slot,prefix=self.args.prefix)
    box.__enter__();self.box=box
   box=self.box
   box.stop();box.policy({});box.core=pathlib.Path(path).resolve();box.driver=driver
   try:
    yield box
   finally:
    box.stop();box.policy({})
    for _ in range(20):
     if (box.cg/'pids.current').read_text().strip()=='0':break
     time.sleep(.05)
    else:raise OSError('sandbox_not_empty')
    for name in ('config.json','hosts','resolv.conf'):(box.work/name).unlink(missing_ok=True)
  except (OSError,subprocess.SubprocessError):
   # The namespace/cgroup may have disappeared or only partially reset.
   # A subsequent attempt must acquire new resources before running a core.
   try:self.close()
   finally:cleanup(self.args.prefix,self.args.slot,self.args.run_id)
   raise
def runtime(config,driver):
 if driver=='xray':
  return scope.runtime(config,lab)
 listeners=config.get('inbounds',[])
 if not all(isinstance(x,dict) for x in listeners):raise ValueError('native_probe_listener_missing')
 if not any(x.get('type')=='socks' and x.get('listen')=='127.0.0.1' and x.get('listen_port')==10808 for x in listeners):
  raise ValueError('native_probe_listener_missing')
 if any(x.get('listen')!='127.0.0.1' for x in listeners):
  raise ValueError('nonloopback_listener_not_qualified')
 return lab.native_endpoints(config),config

def core_order(plan):
 # Known capability dispatch, not a network-failure guess or a TLS downgrade.
 # These exact public plaintext VLESS inputs are prohibited on the newer cores.
 try:
  cfg=json.loads(base64.b64decode(plan['variants'][0]['config'],validate=True))
  for ob in cfg.get('outbounds',[]):
   if ob.get('protocol')!='vless' or ob.get('streamSettings',{}).get('security','none') not in ('','none'):continue
   settings=ob.get('settings',{})
   servers=settings.get('vnext',[])
   if settings.get('address'):servers=[dict(address=settings['address'],users=[settings])]
   for server in servers:
    try:public=ipaddress.ip_address(server.get('address','')).is_global
    except ValueError:public=bool(server.get('address')) and server['address'].lower() not in ('localhost',) and not server['address'].lower().endswith(('.localhost','.local'))
    if public and all(u.get('encryption','none') in ('','none') for u in server.get('users',[])):
     return [CORES[-1]]+CORES[:-1]
 except (ValueError,KeyError,TypeError):pass
 return CORES

def private_sources(samples,key):
 for row in samples:
  value=row.pop('ip','')
  try:value=ipaddress.ip_address(value).compressed
  except ValueError:value=''
  row['source']=hmac.new(key,value.encode(),hashlib.sha256).hexdigest() if value and row.get('echo') else ''
  if 'network' in row:
   row['network']={**row['network'],'source':row['source']}
 return samples

def error_code(error):
 return 'driver_subprocess_timeout' if isinstance(error,subprocess.TimeoutExpired) else 'driver_subprocess_failed' if isinstance(error,subprocess.CalledProcessError) else str(error) if isinstance(error,ValueError) and re.fullmatch('[a-z0-9_]{1,60}',str(error)) else 'driver_infrastructure_error'
def core_independent_failure(code):
 # These listener and route checks inspect the exact variant before any
 # core launches. Repeating them cannot produce a network observation.
 return code in ('protocol_disabled','endpoint_dns_failed','ipv6_only_probe_pending',
                 'direct_route_not_qualified','direct_default_not_qualified',
                 'probe_socks_contract_missing','native_probe_listener_missing',
                 'listener_port_conflict','nonloopback_listener_not_qualified')
def resource_failures(box):
 try:
  with (box.cg/'memory.events').open() as events:
   st=os.fstat(events.fileno())
   fields=dict(line.split() for line in events)
  return (st.st_dev,st.st_ino),(int(fields['oom']),int(fields['oom_kill']))
 except (ValueError,KeyError) as error:raise OSError('sandbox_counters_unavailable') from error

@contextlib.contextmanager
def observe_slot_pressure(box,attempt):
 # memory.events on the shared parent includes every sibling slot. Read
 # this core's counters while its exact cgroup still exists under the lease.
 before_group,before=resource_failures(box)
 try:yield
 finally:
  after_group,after=resource_failures(box)
  if after_group!=before_group or any(end<start for start,end in zip(before,after)):raise OSError('sandbox_counters_reset')
  attempt.update(monitored=True,resource_pressure=after!=before)

def diagnostic_delivery(box,variant,targets,timeout):
 try:
  q=box.net(['/usr/bin/python3',str(HERE/'egress-delivery.py')],input=json.dumps(dict(variant=variant,targets=targets,timeout=timeout)).encode(),timeout=timeout+3)
  result=json.loads(q.stdout)
  if not isinstance(result,dict):raise ValueError('delivery_contract')
  return result
 except Exception:return dict(version='ads-delivery.v1',variant=variant,at=int(time.time()*1000),assets=[])
def scheduled_health_sample(box,variant):
 try:
  q=box.net(['/usr/bin/python3',str(HERE/'egress-health.py')],timeout=11)
  sample=json.loads(q.stdout)
  if sample.get('version')!='ads-health.v1' or sample.get('host_control') is not False:raise ValueError('health_contract')
  return {**sample,'variant':variant}
 except Exception:
  return dict(version='ads-health.v1',variant=variant,at=int(time.time()*1000),host_control=False,providers=[])
def asset_available(a):return a.get('curl_exit')==0 and a.get('http_status')==200 and a.get('tls_verified') and a.get('complete') and a.get('content_match')
def cached_delivery_control(prefix,targets):
 # Shared outage calibration is reusable for at most 30s, never VPN proof.
 key=hashlib.sha256(json.dumps(targets,sort_keys=True).encode()).hexdigest()
 with open('/run/'+prefix+'-ads-control.lock','a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  path=pathlib.Path('/run/'+prefix+'-ads-control.json')
  try:
   old=json.loads(path.read_text());age=int(time.time()*1000)-old['value']['at']
   ttl=20000 if all(asset_available(a) for a in old['value']['assets']) else 5000
   if old['key']==key and 0<=age<ttl:return old['value']
  except Exception:pass
  try:
   q=subprocess.run(['/usr/bin/python3',str(HERE/'egress-delivery.py')],input=json.dumps(dict(targets=targets,host_control=True,timeout=3)).encode(),capture_output=True,timeout=6)
   value=json.loads(q.stdout);tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps(dict(key=key,value=value)));tmp.chmod(0o600);tmp.replace(path);return value
  except Exception:return None
def overlap_assessment(observe,health):
 # Two independent bounded processes in the SAME runtime. Join before core
 # shutdown, even on failure; no thread may leak into the next variant/job.
 with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
  pending=executor.submit(health)
  rows=observe()
  return rows,pending.result()
def observation_budget(req):
 # The first discovery pass can settle a slow valid route in waves 2 and 3.
 # Return wave count, first-wave timeout and later-wave timeout (seconds).
 return (3,8,8) if req.get('discovery') or req.get('deep') else (3,3,8)
def investigate(req,args,pool=None):
 if pool is None:
  with ResourcePool(args) as own:return investigate(req,args,own)
 discovery=req.get('discovery') is True
 probe_waves,first_timeout,probe_timeout=observation_budget(req)
 targets=sessions.target_registry(req.get('targets'));targets=targets if discovery else [t for t in targets if t.get('driver')!='https-reachability'];plan=req['plan'];r=dict(version='ads-egress.v9',hash=req['hash'],started=req['started'],finished=0,core='',core_sha='',infrastructure=False,code='driver_unavailable',checks=[],samples=[],health=[],delivery=[],attempts=[],evidence=[],wall_ms=0,waves=probe_waves)
 conditional_controls=sum(bool(t.get('when_ads_family')) for t in targets)
 base_targets=len(targets)-conditional_controls
 begin=time.monotonic();best=-1
 if len(plan.get('variants',[]))!=2:return r
 for core,path,pin in (core_order(plan) if plan['driver']=='xray' else [NATIVE]):
  at=time.monotonic();attempt_started=int(time.time()*1000);attempt={'resource_pressure':False,'monitored':False};completed=False;checks=[];samples=[];health=[];delivery=[];code='core_unavailable';stages={};checkpoint=at
  def mark(name):
   nonlocal checkpoint
   current=time.monotonic();stages[name]=(current-checkpoint)*1000;checkpoint=current
  try:
   pool.verify(path,pin);mark('pin')
   with pool.lease(path,plan['driver']) as box, observe_slot_pressure(box,attempt):
    mark('namespace')
    for v in plan['variants']:
     data=base64.b64decode(v['config'],validate=True)
     if len(data)>8*1024*1024 or lab.digest(data)!=v['hash']:raise ValueError('variant_hash_mismatch')
     config=lab.preflight.parse_runtime_config(data);box.policy({})
     # Successful isolated runtime startup validates the exact bytes too. Avoid
     # spawning an identical -test core before every actual launch.
     check=dict(name=v['name'],hash=v['hash'],runtime_hash='',core=False,code='runtime_pending');checks.append(check)
     resolved,_=runtime(config,plan['driver']);body=data;box.resolved=resolved;box.policy(resolved);check['runtime_hash']=lab.digest(body);mark(v['name']+'_resolve')
     p=box.launch(body);ready=False
     for _ in range(30):
      if p.poll() is not None:break
      ok=box.net(['/usr/bin/python3','-c','import socket;s=socket.socket();s.settimeout(.1);print(s.connect_ex(("127.0.0.1",10808)))'],timeout=2)
      if ok.stdout.strip()==b'0':ready=True;break
      time.sleep(.1)
     mark(v['name']+'_ready')
     if not ready:
      code=lab.classify(box.logs(),'runtime_start_failed');check.update(core=False,code=code);break
     check.update(core=True,code='exact_runtime_started')
     def observe(start,waves,timeout):
      result=box.net(['/usr/bin/python3',str(HERE/'egress-session.py')],input=json.dumps({'targets':targets,'variant':v['name'],'timeout':timeout,'first_timeout':first_timeout,'start_wave':start,'waves':waves,'sequential':sequential,'adaptive':not discovery}).encode(),timeout=scheduling.session_deadline(base_targets,waves,timeout,sequential,conditional_controls))
      if len(result.stdout)>131072:raise ValueError('session_output_limit')
      rows=json.loads(result.stdout)
      if not isinstance(rows,list) or not min(waves,2)*base_targets<=len(rows)<=waves*len(targets):raise ValueError('session_contract')
      return rows
     # Deep paired waves remain serial to avoid upstream connection saturation;
     # initial checks retain transport-specific overlap and the shared cap.
     sequential=scheduling.sequential(req,config)
     observe_current=lambda:observe(1,r['waves'],probe_timeout)
     if discovery:rows=observe_current()
     else:
      rows,assets=overlap_assessment(observe_current,lambda:diagnostic_delivery(box,v['name'],req.get('delivery_targets'),8 if req.get('deep') else 6))
      delivery.append(assets)
      if req.get('accepted') is True and req.get('health_due') is True:
       health.append(scheduled_health_sample(box,v['name']))
     samples+=rows
     box.stop();code='measured';mark(v['name']+'_probes')
   completed=True;mark('reset')
  except Exception as error:
   code=error_code(error)
  pressure=attempt['resource_pressure']
  if pressure:code='local_resource_pressure'
  if samples and attempt['monitored']:r['evidence'].append(dict(version=r['version'],hash=r['hash'],started=attempt_started,finished=int(time.time()*1000),core=core,core_sha=pin,checks=checks,samples=samples,waves=max(row.get('wave',0) for row in samples),resource_pressure=pressure))
  r['attempts'].append(dict(core=core,code=code,ms=(time.monotonic()-at)*1000,stages=stages))
  # Only attempts that returned from the sandbox with an intact reset may
  # provide the selected variant bindings. Other observations stay scoped
  # to their own attempt for independently verified safety checks.
  if completed:
   score=sum(bool(x.get('echo')) for x in samples)
   if len(checks)==2 and all(x['core'] for x in checks):score+=100
   if not pressure and score>best:
    r.update(core=core,core_sha=pin,checks=checks,samples=samples,health=health,delivery=delivery,code=code);best=score
  if best<0 or (pressure and not r['samples']):r.update(code=code,resource_pressure=pressure)
  if pressure or core_independent_failure(code):break
  if completed and len(checks)==2 and all(x.get('core') for x in checks):break
 # An independent host asset check is outage calibration only. Cache avoids
 # repeating two unrelated public probes for every disconnected input.
 if r['delivery'] and not any(asset_available(a) for part in r['delivery'] for a in part.get('assets',[])):
  control=cached_delivery_control(args.prefix,req.get('delivery_targets'))
  if control:
   r['infrastructure']=any(asset_available(a) for a in control.get('assets',[]))
   r['delivery'].append(control)
 r['waves']=max((x.get('wave',0) for x in r['samples']),default=2)
 # Reference selected samples once while preserving their attempt-local safety
 # metadata; unrelated attempts under resource pressure cannot erase valid IR.
 r['evidence']=[dict(part,samples=[],selected_samples=True) if part['samples'] is r['samples'] else part for part in r['evidence']]
 unique={id(s):s for part in [r]+r['evidence'] for s in part.get('samples',[])}
 observations=list(unique.values())
 pool.geo.attach(observations)
 pool.network.attach(observations)
 private_sources(observations,secrets.token_bytes(32))
 r['finished']=int(time.time()*1000);r['wall_ms']=(time.monotonic()-begin)*1000
 for part in r['evidence']:part['finished']=r['finished']
 return r
def main():
 a=argparse.ArgumentParser();a.add_argument('--prefix',default='cge',choices=['cge','cgt']);a.add_argument('--slot',type=int,default=1);a.add_argument('--run-id');a.add_argument('--cleanup',action='store_true');a.add_argument('--serve',action='store_true');args=a.parse_args()
 if os.geteuid()!=0 or not 0<=args.slot<=31 or args.run_id and not re.fullmatch('[0-9a-f]{6}',args.run_id):raise SystemExit('invalid supervisor request')
 if args.cleanup:cleanup(args.prefix,args.slot if args.slot else None,args.run_id);return
 if not args.run_id:raise SystemExit('run id required')
 parent=os.getppid();signal.signal(signal.SIGTERM,lambda *_:sys.exit(143))
 def watch():
  while True:
   time.sleep(.25)
   if os.getppid()!=parent or parent==1:os.kill(os.getpid(),signal.SIGTERM);return
 threading.Thread(target=watch,daemon=True).start()
 try:
  with ResourcePool(args) as pool:
   if args.serve:
    while True:
     line=sys.stdin.buffer.readline(24*1024*1024)
     if not line:break
     if not line.endswith(b'\n'):raise ValueError('request_limit')
     print(json.dumps(investigate(json.loads(line),args,pool),separators=(',',':')),flush=True)
   else:print(json.dumps(investigate(json.load(sys.stdin),args,pool)))
 finally:cleanup(args.prefix,args.slot,args.run_id)
if __name__=='__main__':main()
