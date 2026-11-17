#!/usr/bin/env python3
"""Offline contracts for the real-device agent; no health pass from fixtures."""
import copy,json,os,pathlib,importlib.util,types,subprocess,sys,tempfile,unittest
from unittest.mock import patch
from benchmarks.core import Session,encoded
from benchmarks.http import request
class Contracts(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name)
  self.core=self.root/'fixture-core';self.core.write_text('#!'+sys.executable+'\nimport json,socket,sys,time\nif "-test" in sys.argv:sys.exit(0)\nc=json.load(open(sys.argv[-1]));s=socket.socket();s.bind(("127.0.0.1",c["inbounds"][0]["port"]));s.listen();time.sleep(30)\n');self.core.chmod(0o700)
  self.config={'inbounds':[{'listen':'127.0.0.1','port':10808,'protocol':'socks'},{'listen':'127.0.0.1','port':39081,'protocol':'dokodemo-door'}],'outbounds':[{'tag':'proxy','settings':{'address':'127.0.0.1','port':39081,'id':'preserve'},'streamSettings':{'security':'tls','tlsSettings':{'allowInsecure':False}}}],'metrics':{'listen':'127.0.0.1:11111'},'routing':{'balancers':[{'strategy':{'type':'leastLoad','settings':{'expected':3}},'fallbackTag':'block'}]},'burstObservatory':{'pingConfig':{'interval':'15s','sampling':3,'timeout':'5s'}}}
 def tearDown(self):self.tmp.cleanup()
 def test_owned_session_remaps_graph_and_cleans_after_exception(self):
  before=encoded(self.config);session=Session(self.core,self.config,self.root/'case')
  with self.assertRaisesRegex(RuntimeError,'fixture error'):
   with session:
    runtime=json.loads(session.runtime_bytes);ports=[i['port'] for i in runtime['inbounds']]
    self.assertEqual(len(set(ports+[session.metrics_port])),3)
    self.assertEqual(runtime['outbounds'][0]['settings']['port'],ports[1]);self.assertEqual(runtime['outbounds'][0]['settings']['id'],'preserve')
    self.assertEqual(runtime['routing'],self.config['routing']);self.assertEqual(runtime['outbounds'][0]['streamSettings'],self.config['outbounds'][0]['streamSettings'])
    raise RuntimeError('fixture error')
  self.assertIsNotNone(session.process.poll());self.assertEqual(before,encoded(self.config));self.assertEqual((session.work/'original.json').read_bytes(),before)
 def test_reject_external_listener_before_runtime(self):
  self.config['inbounds'][1]['listen']='0.0.0.0';s=Session(self.core,self.config,self.root/'case')
  with self.assertRaisesRegex(ValueError,'unsupported_benchmark_inbounds'):s.__enter__()
  self.assertIsNone(s.process)
 def test_https_status_does_not_override_invalid_certificate(self):
  fake=subprocess.CompletedProcess([],60,json.dumps({'ssl_verify_result':10,'http_code':200}).encode(),b'')
  with patch('benchmarks.http.subprocess.run',return_value=fake) as run:
   r=request(12345,'https://example.com')
   args=run.call_args.args[0];self.assertIn('socks5h://127.0.0.1:12345',args);self.assertNotIn('--insecure',args);self.assertEqual(r['status'],'failed');self.assertEqual(r['transport_tls'],'unverified')
 def test_resume_preserves_evidence_age_and_rejects_changed_network(self):
  spec=importlib.util.spec_from_file_location('android_bench',pathlib.Path(__file__).with_name('android-bench.py'));agent=importlib.util.module_from_spec(spec);spec.loader.exec_module(agent)
  from benchmarks.core import digest
  key=digest(encoded(self.config));work=self.root/('case-000-'+key[:12]);work.mkdir()
  prior={'config_sha256':key,'core_sha256':'fixture','network_label':'network-a','benchmark_stage':'full','observation_seconds':55,'finished':123,'build':'passed'}
  (work/'result.json').write_text(json.dumps(prior))
  args=types.SimpleNamespace(output=str(self.root),core_sha='fixture',network_label='network-a',resume=True,stage='full',observe_seconds=55)
  with patch('benchmarks.core.validate',side_effect=AssertionError('must not fabricate fresh core evidence')):
   got=agent.run_one(args,(0,{'config':self.config}))
  self.assertTrue(got['historical_reused']);self.assertEqual(got['finished'],123)
  args.network_label='network-b'
  with self.assertRaisesRegex(ValueError,'resume_context_mismatch'):agent.run_one(args,(0,{'config':self.config}))
  self.assertEqual(json.loads((work/'result.json').read_text()),prior)
 def test_transfer_requires_exact_payload_size(self):
  fake=subprocess.CompletedProcess([],0,json.dumps({'ssl_verify_result':0,'http_code':200,'size_download':1}).encode(),b'')
  with patch('benchmarks.http.subprocess.run',return_value=fake):self.assertEqual(request(12345,'https://example.com',download_bytes=100)['status'],'failed')
if __name__=='__main__':unittest.main()
