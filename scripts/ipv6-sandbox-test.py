#!/usr/bin/env python3
"""Real scoped IPv6/IPv4 sandbox acceptance; requires an IPv6-capable host."""
import importlib.util, json, pathlib, socket, struct, subprocess, uuid
root=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('lab',root/'live-probe.py');lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)
before=pathlib.Path('/proc/sys/net/ipv6/conf/all/forwarding').read_text()
run=uuid.uuid4().hex[:6];results={}
try:
 with lab.Sandbox('/opt/config-repair/core-26.11.9/xray',run,8200,prefix='ctf') as box:
  def curl(ip):
   r=box.net(['/usr/bin/curl','--noproxy','*','--max-time','5','--silent','--output','/dev/null','--write-out','%{http_code}','https://'+('['+ip+']' if ':' in ip else ip)+'/cdn-cgi/trace'])
   return r.stdout.strip()==b'200'
  blocked=box.net(['/usr/bin/python3','-c','import socket;s=socket.socket(socket.AF_INET6);s.settimeout(.2);print(s.connect_ex(("2606:4700:4700::1111",443)))'])
  assert blocked.stdout.strip()!=b'0'
  box.policy({'cf':{'ips':['2606:4700:4700::1111','1.1.1.1'],'port':443,'ports':['443','53']}})
  results['ipv6_tls']=curl('2606:4700:4700::1111');results['ipv4_tls']=curl('1.1.1.1')
  code='import socket,struct;s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);s.settimeout(5);q=b"\\x12\\x34"+struct.pack("!HHHHH",256,1,0,0,0)+b"\\x07example\\x03com\\x00"+struct.pack("!HH",1,1);s.sendto(q,("2606:4700:4700::1111",53));r,_=s.recvfrom(4096);print(r[:2]==q[:2] and bool(r[2]&128))'
  results['ipv6_udp_dns']=box.net(['/usr/bin/python3','-c',code],timeout=7).stdout.strip()==b'True'
  denied=box.net(['/usr/bin/python3','-c','import socket;s=socket.socket(socket.AF_INET6);s.settimeout(.2);print(s.connect_ex(("2001:4860:4860::8888",443)))'])
  results['unlisted_blocked']=denied.stdout.strip()!=b'0'
  box.policy({});denied=box.net(['/usr/bin/python3','-c','import socket;s=socket.socket(socket.AF_INET6);s.settimeout(.2);print(s.connect_ex(("2606:4700:4700::1111",443)))'])
  results['revoked_blocked']=denied.stdout.strip()!=b'0'
finally:
 results['host_forwarding_unchanged']=pathlib.Path('/proc/sys/net/ipv6/conf/all/forwarding').read_text()==before
print(json.dumps(results));assert all(results.values()),results
