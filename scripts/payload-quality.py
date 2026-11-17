#!/usr/bin/env python3
"""Bounded full-payload qualification through SOCKS, never direct.
A finite server-side test, not app/Android/long-term stability evidence.
"""
import concurrent.futures
import json,os,pathlib,subprocess,sys,tempfile,time
VERSION='payload_v1'
DOWNLOAD=2097152
UPLOAD=1048576
def accepted(rc,m,expected,field=None,size=None):
 return rc==0 and m.get('ssl_verify_result')==0 and m.get('http_code') in expected and (field is None or m.get(field)==size)
def request(url,timeout,payload=None,size=None,http1=False):
 args=['/usr/bin/curl','--noproxy','','--proxy','socks5h://127.0.0.1:10808','--silent','--show-error','--connect-timeout',str(min(timeout,10)),'--max-time',str(timeout),'--max-filesize',str(DOWNLOAD),'--output','/dev/null','--write-out','%{json}','--header','Cache-Control: no-cache']
 if http1:args += ['--http1.1']
 if payload:args+=['--header','Content-Type: application/octet-stream','--data-binary','@'+str(payload)]
 args+=[url]
 try:
  r=subprocess.run(args,capture_output=True,timeout=timeout+2,env={'PATH':'/usr/bin:/usr/sbin'})
  try:m=json.loads(r.stdout)
  except ValueError:m={}
  rc=r.returncode
 except (OSError,subprocess.SubprocessError):m={};rc=124
 field='size_upload' if payload else 'size_download' if size is not None else None
 wanted=UPLOAD if payload else size
 passed=accepted(rc,m,{204} if size is None and payload is None else {200},field,wanted)
 return {'status':'passed' if passed else 'failed','bytes':int(m.get(field,0)) if field else 0,'ms':round(m.get('time_total',0)*1000),'curl_exit':rc,'http_status':int(m.get('http_code',0))}
def transient(row):
 return row['curl_exit'] in (5,6,7,18,28,35,52,55,56,92) or row.get('http_status') in (408,429,500,502,503,504)
def run(timeout):
 timeout=max(20,min(45,int(timeout)))
 with tempfile.TemporaryDirectory(prefix='config-payload-',dir='/dev/shm') as folder:
  payload=pathlib.Path(folder)/'upload.bin';payload.write_bytes(os.urandom(UPLOAD));payload.chmod(0o600)
  down_url='https://speed.cloudflare.com/__down?bytes='+str(DOWNLOAD)+'&nonce='+str(time.time_ns())
  up_url='https://speed.cloudflare.com/__up'
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
   download=pool.submit(request,down_url,timeout,size=DOWNLOAD)
   upload=pool.submit(request,up_url,timeout,payload=payload)
   down,up=download.result(),upload.result()
  # One recovery per failed leg; successful data is not downloaded again.
  for row,url,body,size in ((down,down_url,None,DOWNLOAD),(up,up_url,payload,None)):
   first=dict(row);row['attempts']=1
   if row['status']!='passed' and transient(row):
    recovery=min(45,max(timeout,30 if row['bytes']==0 else 45))
    row.update(request(url,recovery,body,size,http1=True));row['attempts']=2
   row['first_curl_exit']=first['curl_exit'];row['first_http_status']=first['http_status']
  check=request('https://www.gstatic.com/generate_204',min(timeout,10));check['attempts']=1
  if check['status']!='passed' and transient(check):
   check=request('https://www.gstatic.com/generate_204',min(timeout,10),http1=True);check['attempts']=2
 result={'payload_version':VERSION,'payload_download':down['status'],'payload_upload':up['status'],'payload_recheck':check['status']}
 for key,row in [('download',down),('upload',up),('recheck',check)]:
  for field in ('bytes','ms','curl_exit','http_status','attempts','first_curl_exit','first_http_status'):
   if field in row:result['payload_'+key+'_'+field]=str(row[field])
 return result
def verified(e):
 return e.get('payload_version')==VERSION and all(e.get('payload_'+k)=='passed' for k in ('download','upload','recheck')) and e.get('payload_download_bytes')==str(DOWNLOAD) and e.get('payload_upload_bytes')==str(UPLOAD)
if __name__=='__main__':print(json.dumps(run(int(sys.argv[1]))))
