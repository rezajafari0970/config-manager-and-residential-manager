import importlib.util,pathlib,tempfile,unittest,os,json,tarfile,time
spec=importlib.util.spec_from_file_location('archive',pathlib.Path(__file__).with_name('artifact-archive.py'));a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
class TestArchive(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name);self.src=self.root/'test-data';self.src.mkdir();(self.src/'receipt.json').write_text('{"passed":false}');(self.src/'data').mkdir();(self.src/'data'/'panel.db').write_bytes(b'exact-data'*1000);self.out=self.root/'test.tar.gz'
 def archive(self,**kw):return a.archive_one(self.src,self.out,age_seconds=0,active=lambda *_:False,**kw)
 def test_roundtrip_preserves_failure_receipts_and_data(self):
  before=a.manifest(self.src);r=self.archive();self.assertEqual(r['state'],'archived');self.assertFalse(self.src.exists());a.restore(self.out,self.src);self.assertEqual(a.manifest(self.src),before)
 def test_scope_rejects_other_projects_and_path_escapes(self):
  self.assertFalse(a.project_test_scope(pathlib.Path('/root/projects/dob-example/.local/rehearsal')))
  self.assertFalse(a.project_test_scope(pathlib.Path('/tmp/shen-egress-p39-worker-not-owned')))
  self.assertTrue(a.project_test_scope(pathlib.Path('/root/projects/config-manager-example/.local/rehearsal')))
 def test_active_source_is_untouched(self):
  self.assertEqual(a.archive_one(self.src,self.out,active=lambda *_:True)['state'],'active');self.assertTrue(self.src.exists());self.assertFalse(self.out.exists())
 def test_symlink_rejected(self):
  (self.src/'link').symlink_to('/etc/passwd')
  with self.assertRaises(a.UnsafeArtifact):self.archive()
  self.assertTrue(self.src.exists())
 def test_corrupt_existing_archive_preserves_source(self):
  self.out.write_bytes(b'corrupt')
  with self.assertRaises(tarfile.ReadError):self.archive()
  self.assertTrue(self.src.exists())
 def test_restore_never_overwrites_existing_target(self):
  self.archive();self.src.mkdir()
  with self.assertRaises(a.UnsafeArtifact):a.restore(self.out,self.src)
 def test_interrupted_removal_recovers_without_losing_archive(self):
  before=a.manifest(self.src);self.archive();a.restore(self.out,self.src)
  (self.src/'receipt.json').unlink() # Simulate partial original-directory removal.
  staged=self.src.with_name(self.src.name+'.archiving');self.src.rename(staged)
  self.archive();self.assertFalse(staged.exists());a.restore(self.out,self.src);self.assertEqual(a.manifest(self.src),before)
 def test_recent_is_retained(self):
  self.assertEqual(a.archive_one(self.src,self.out,age_seconds=3600,active=lambda *_:False)['state'],'recent');self.assertTrue(self.src.exists())
 def test_late_activity_keeps_original(self):
  calls=[0]
  def active(*_):calls[0]+=1;return calls[0]>=3
  with self.assertRaises(a.UnsafeArtifact):a.archive_one(self.src,self.out,age_seconds=0,active=active)
  self.assertTrue(self.src.exists())
if __name__=='__main__':unittest.main()
