#!/usr/bin/env python3
"""Verified archival of explicitly registered, inactive test artifacts.

No discovery-based deletion, live DB cleanup, release retention or global /tmp
sweep. Archive/manifest are retained; recovery is independent of production.
"""
import argparse, contextlib, fcntl, gzip, hashlib, json, os, pathlib, re, shutil, stat, tarfile, tempfile, time

class UnsafeArtifact(RuntimeError): pass

def digest(stream):
    return hashlib.file_digest(stream, 'sha256').hexdigest()

def manifest(root):
    root=pathlib.Path(root)
    if root.is_symlink() or not root.is_dir(): raise UnsafeArtifact('not_regular_directory')
    result={}
    for folder, dirs, files in os.walk(root, followlinks=False):
        for name in dirs+files:
            p=pathlib.Path(folder)/name; s=p.lstat()
            if stat.S_ISLNK(s.st_mode) or not (stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode)):
                raise UnsafeArtifact('special_file_or_symlink')
            row={'mode':s.st_mode,'uid':s.st_uid,'gid':s.st_gid,'size':s.st_size if p.is_file() else 0,'mtime_ns':s.st_mtime_ns}
            if p.is_file():
                with p.open('rb') as stream: row['sha256']=digest(stream)
                after=p.stat()
                if (s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_ino)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns,after.st_ino):raise UnsafeArtifact('file_changed')
            result[str(p.relative_to(root))]=row
    return result

def active_references(root, owner=None):
    prefixes=[str(pathlib.Path(root))]
    # A stopped configured unit/cron job is also a live reference.
    for base in ['/etc/systemd/system','/etc/cron.d']:
        for configured in pathlib.Path(base).rglob('*'):
            try:
                if configured.is_file() and configured.stat().st_size<262144 and prefixes[0].encode() in configured.read_bytes():return True
            except (OSError,RuntimeError):continue
    if owner: prefixes.append(str(pathlib.Path(owner)))
    def matches(value):
        return any(value==p or value.startswith(p+'/') for p in prefixes)
    for process in pathlib.Path('/proc').iterdir():
        if not process.name.isdigit() or int(process.name)==os.getpid():continue
        try:
            for name in ['cwd','exe']:
                with contextlib.suppress(FileNotFoundError):
                    if matches(os.readlink(process/name)):return True
            for fd in (process/'fd').iterdir():
                with contextlib.suppress(FileNotFoundError):
                    if matches(os.readlink(fd)):return True
            for name in ['cmdline','environ','maps']:
                data=(process/name).read_bytes()
                if any(p.encode() in data for p in prefixes):return True
        except (FileNotFoundError, ProcessLookupError):continue
        except PermissionError:raise UnsafeArtifact('process_visibility_incomplete')
    return False

def verify(archive, expected):
    seen=set()
    with tarfile.open(archive,'r:gz') as tar:
        for item in tar:
            if item.name=='.':continue
            name=item.name.removeprefix('./')
            if name not in expected or name in seen:raise UnsafeArtifact('archive_member_mismatch')
            row=expected[name];seen.add(name)
            if item.uid!=row['uid'] or item.gid!=row['gid'] or item.mode!=stat.S_IMODE(row['mode']):raise UnsafeArtifact('archive_metadata_mismatch')
            if stat.S_ISREG(row['mode']):
                if not item.isfile() or item.size!=row['size'] or digest(tar.extractfile(item))!=row['sha256']:raise UnsafeArtifact('archive_digest_mismatch')
            elif not item.isdir():raise UnsafeArtifact('archive_type_mismatch')
    if seen!=set(expected):raise UnsafeArtifact('archive_incomplete')

def archive_one(root, destination, *, owner=None, age_seconds=3600, active=active_references):
    root=pathlib.Path(root);destination=pathlib.Path(destination)
    staged=root.with_name(root.name+'.archiving')
    if not root.exists() and staged.exists():
        metadata=destination.with_name(destination.name+'.json')
        if staged.is_symlink() or not destination.exists() or not metadata.exists():raise UnsafeArtifact('unverified_interrupted_archive')
        saved=json.loads(metadata.read_text())
        if saved.get('source')!=str(root):raise UnsafeArtifact('interrupted_archive_source_mismatch')
        verify(destination,saved['manifest'])
        if active(staged,owner):return {'state':'active'}
        os.rename(staged,root)
    if not root.exists():return {'state':'absent'}
    if active(root,owner):return {'state':'active'}
    before=manifest(root)
    if not before:return {'state':'empty'}
    if max([root.stat().st_mtime]+[r['mtime_ns']/1e9 for r in before.values()])>time.time()-age_seconds:return {'state':'recent'}
    if active(root,owner):return {'state':'active'}
    archived_manifest=before
    if destination.exists():
        existing=destination.with_name(destination.name+'.json')
        if existing.exists():
            saved=json.loads(existing.read_text())
            if saved.get('source')!=str(root):raise UnsafeArtifact('archive_source_mismatch')
            original=saved['manifest']
            if any(original.get(k)!=v for k,v in before.items()):raise UnsafeArtifact('archived_source_changed')
            archived_manifest=original
        # Crash after verified publication: verify again before finishing removal.
        verify(destination,archived_manifest)
    else:
        total=sum(r['size'] for r in before.values())
        if shutil.disk_usage(destination.parent).free<max(512*2**20,total+128*2**20):raise UnsafeArtifact('archive_capacity_reserve')
        partial=destination.with_name(destination.name+'.partial')
        if partial.exists():partial.unlink() # Owned incomplete output, never source.
        try:
            with partial.open('xb') as raw:
                os.chmod(partial,0o600)
                with gzip.GzipFile(fileobj=raw,mode='wb',compresslevel=1,mtime=0) as gz:
                    with tarfile.open(fileobj=gz,mode='w',format=tarfile.PAX_FORMAT,dereference=True) as tar:
                        tar.add(root,arcname='.',recursive=True)
                raw.flush();os.fsync(raw.fileno())
            verify(partial,before)
            if manifest(root)!=before or active(root,owner):raise UnsafeArtifact('source_changed_or_active')
            os.replace(partial,destination)
        finally:
            if partial.exists():partial.unlink()
    if manifest(root)!=before or active(root,owner):raise UnsafeArtifact('source_changed_or_active')
    meta=destination.with_name(destination.name+'.json')
    receipt={'source':str(root),'archive':str(destination),'created':time.time(),'manifest':archived_manifest,'source_bytes':sum(r['size'] for r in archived_manifest.values())}
    tmp=meta.with_name(meta.name+'.partial');tmp.write_text(json.dumps(receipt));os.chmod(tmp,0o600)
    with tmp.open('rb') as f:os.fsync(f.fileno())
    os.replace(tmp,meta)
    # Persist verified recovery set before changing the disposable test copy.
    fd=os.open(destination.parent,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
    staged=root.with_name(root.name+'.archiving')
    if staged.exists():raise UnsafeArtifact('staging_path_exists')
    os.rename(root,staged)
    try:
        if manifest(staged)!=before or active(staged,owner) or active(root,owner):raise UnsafeArtifact('staged_artifact_active')
        shutil.rmtree(staged)
    except Exception:
        if staged.exists() and not root.exists():os.rename(staged,root)
        raise
    return {'state':'archived','source_bytes':receipt['source_bytes'],'archive_bytes':destination.stat().st_size,'files':len(archived_manifest)}

def restore(archive,target):
    archive=pathlib.Path(archive);target=pathlib.Path(target)
    if target.exists():raise UnsafeArtifact('restore_target_exists')
    receipt=json.loads(archive.with_name(archive.name+'.json').read_text());expected=receipt['manifest'];verify(archive,expected)
    for name in expected:
        p=pathlib.PurePosixPath(name)
        if p.is_absolute() or '..' in p.parts:raise UnsafeArtifact('unsafe_archive_path')
    with tempfile.TemporaryDirectory(prefix='.restore-',dir=target.parent) as staging:
        stage=pathlib.Path(staging)/'data';stage.mkdir(mode=0o700)
        with tarfile.open(archive,'r:gz') as tar:tar.extractall(stage,filter='data')
        # Restore original exact metadata after safe extraction.
        for name,row in sorted(expected.items(),key=lambda x:-len(pathlib.PurePosixPath(x[0]).parts)):
            p=stage/name;os.chmod(p,stat.S_IMODE(row['mode']));os.chown(p,row['uid'],row['gid']);os.utime(p,ns=(row['mtime_ns'],row['mtime_ns']))
        if manifest(stage)!=expected:raise UnsafeArtifact('restore_verification_failed')
        os.rename(stage,target)
    return {'state':'restored','files':len(expected)}

def project_test_scope(source):
    local=len(source.parts)>4 and source.parts[:3]==('/','root','projects') and (source.parts[3].startswith('config-manager-') or source.parts[3]=='v2ray-config-repair') and source.parts[4]=='.local'
    temporary=source.parent==pathlib.Path('/tmp') and re.fullmatch(r'shen-egress-p39-worker(?:-[0-9a-f]{8})?',source.name)
    return bool(local or temporary)

def go_build_scope(source):
    if source.parent!=pathlib.Path('/tmp') or not re.fullmatch(r'go-build[0-9]+',source.name):return False
    if not source.exists():return True # Already archived; no new deletion.
    projects=set()
    for cfg in source.glob('*/vet.cfg'):
        if cfg.is_symlink() or cfg.stat().st_size>1024*1024:return False
        try:directory=json.loads(cfg.read_text()).get('Dir','')
        except (OSError,ValueError):return False
        if directory.startswith('/root/projects/'):
            parts=pathlib.Path(directory).parts
            if len(parts)<4 or not (parts[3].startswith('config-manager-') or parts[3]=='v2ray-config-repair'):return False
            projects.add(parts[3])
    return bool(projects)

# Drivers authorize only their own generated artifacts. The archive/restore
# engine is independent of ownership recognition; unknown types retain data.
DRIVERS={'project-tests':project_test_scope,'go-build':go_build_scope}

def run_registry(path,apply=False):
    path=pathlib.Path(path);s=path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise UnsafeArtifact('registry_not_private_root_owned')
    cfg=json.loads(path.read_text());destination=pathlib.Path(cfg['destination'])
    if not destination.is_dir() or destination.is_symlink():raise UnsafeArtifact('archive_directory_missing')
    entries=list(cfg['artifacts'])
    # New test suites register directories only below this project's private
    # test-artifacts root. Closed receipts are required for unattended archival.
    for managed in cfg.get('managed_roots',[]):
        parent=pathlib.Path(managed)
        if len(parent.parts)!=6 or parent.parts[:3]!=('/','root','projects') or not (parent.parts[3].startswith('config-manager-') or parent.parts[3]=='v2ray-config-repair') or parent.parts[4:]!=('.local','test-artifacts') or parent.resolve()!=parent:raise UnsafeArtifact('invalid_managed_root')
        if parent.exists():
            for child in sorted(parent.iterdir()):
                if child.name.startswith('shen-egress-worker-') and child.is_dir() and not child.is_symlink() and (child/'artifact-closed.json').is_file():entries.append({'path':str(child),'owner':str(parent.parent.parent)})
    results=[]
    with open(destination/'archive.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        for entry in entries:
            source=pathlib.Path(entry['path']);owner=entry.get('owner')
            # Registry is an explicit allowlist of this project's TEST data only.
            driver=DRIVERS.get(entry.get('driver','project-tests'))
            if driver is None or not driver(source) or '..' in source.parts or source.is_symlink() or source.resolve()!=source:raise UnsafeArtifact('scope_not_test_artifact')
            result={'path':str(source)}
            try:
                if not source.exists() and not source.with_name(source.name+'.archiving').exists():result['state']='absent'
                elif not apply:result.update(state='planned',active=active_references(source,owner))
                else:
                    name=hashlib.sha256(str(source).encode()).hexdigest()[:16]+'-'+source.name+'.tar.gz'
                    result.update(archive_one(source,destination/name,owner=owner,age_seconds=cfg.get('minimum_age_seconds',86400)))
            except (OSError,UnsafeArtifact,tarfile.TarError) as e:result.update(state='retained',reason=str(e) if isinstance(e,UnsafeArtifact) else type(e).__name__)
            results.append(result)
            if apply:
                report=destination/'latest.json';temp=destination/'latest.partial';temp.write_text(json.dumps(results,indent=2));os.replace(temp,report)
    return results

if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--registry');a.add_argument('--apply',action='store_true');a.add_argument('--restore');a.add_argument('--target');args=a.parse_args()
    os.umask(0o077)
    print(json.dumps(restore(args.restore,args.target) if args.restore and args.target else run_registry(args.registry,args.apply),indent=2))
