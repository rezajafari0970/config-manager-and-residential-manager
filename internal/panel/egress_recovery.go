package panel

// A committed first receipt is final for automatic discovery, including
// inconclusive and unsupported results. Only residential maintenance and
// separately measured safety confirmations may acquire another lease.
func (s *Store) migrateV48() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version >= 48 {
		return err
	}
	_, err = tx.Exec(`
 -- Staging is an observation, never a new classification. Only the
 -- committed membership trigger may choose a new representative.
 DROP TRIGGER egress_stage;
 CREATE TRIGGER egress_stage AFTER INSERT ON staged BEGIN
   INSERT INTO egress_jobs(hash,kind,size,first_seen,last_seen)
   SELECT new.hash,new.kind,new.size,CAST(unixepoch('subsec')*1000 AS INTEGER),CAST(unixepoch('subsec')*1000 AS INTEGER)
   WHERE NOT EXISTS(SELECT 1 FROM input_exclusions WHERE identity=new.identity)
   ON CONFLICT(hash) DO UPDATE SET last_seen=excluded.last_seen;
   INSERT OR IGNORE INTO egress_owners SELECT new.hash,new.identity,new.source_id
   WHERE EXISTS(SELECT 1 FROM egress_jobs WHERE hash=new.hash);
 END;
 DROP VIEW egress_work;
 CREATE VIEW egress_work AS SELECT j.* FROM egress_inventory j
 JOIN egress_unique u ON u.hash=j.hash
 LEFT JOIN egress_iran_guard g ON g.identity=u.identity
 LEFT JOIN egress_network_results n ON n.identity=u.identity
 WHERE j.reason NOT IN ('initial_lease_interrupted','initial_lease_exhausted') AND (
 (j.tested=0 AND j.first_completed=0)
 OR (g.identity IS NULL AND n.held=1 AND n.clean_rounds=1 AND n.hash=j.hash AND n.candidate_hash=j.candidate_hash
 AND n.policy=(SELECT value FROM metadata WHERE key='ads-exit-network-policy')
 AND n.clean_until>CAST(unixepoch('subsec')*1000 AS INTEGER))
 OR (g.state='QUARANTINED')
 OR (g.identity IS NULL AND coalesce(n.held,0)=0 AND j.ever_accepted=1)
 OR (g.identity IS NULL AND j.retry_streak<3 AND EXISTS(SELECT 1 FROM egress_retirements r WHERE r.hash=j.hash
   AND r.hits>0 AND r.first_at>CAST(unixepoch('subsec')*1000 AS INTEGER)-600000)));
 CREATE INDEX IF NOT EXISTS egress_interrupted_initial ON egress_jobs(next_run) WHERE reason='initial_lease_interrupted' AND first_completed=0 AND tested=0;
 CREATE TRIGGER IF NOT EXISTS egress_recover_interrupted AFTER INSERT ON egress_events
 WHEN new.definitive=1 AND new.state IN ('RESIDENTIAL','NO_SPLIT') BEGIN
   UPDATE egress_jobs SET state='PENDING',reason='initial_lease_recovered',next_run=0
   WHERE reason='initial_lease_interrupted' AND first_completed=0 AND tested=0 AND next_run<new.at AND hash!=new.hash;
 END;
 -- Old global resets preserved the report while clearing its clock/state.
 -- Restore only measured non-residential rows. Never mint publishable evidence.
 UPDATE egress_jobs SET
 state=CASE json_extract(decision,'$.state') WHEN 'NO_SPLIT' THEN 'NO_SPLIT' WHEN 'UNSUPPORTED' THEN 'UNSUPPORTED' ELSE 'UNKNOWN' END,
 reason=coalesce(json_extract(decision,'$.reason'),'assessment_archived'),
 tested=json_extract(report,'$.finished'), valid_until=0
 WHERE tested=0 AND first_completed=1 AND ever_accepted=0 AND state='PENDING'
 AND reason IN('implementation_changed','full_rescan') AND json_extract(report,'$.finished')>0;
 UPDATE egress_jobs SET token='',lease_until=0,revision=revision+1 WHERE token!=''
 AND NOT EXISTS(SELECT 1 FROM egress_work w WHERE w.hash=egress_jobs.hash);
 UPDATE egress_run_members SET status='excluded',state='PREVIOUSLY_ASSESSED',completed_at=CAST(unixepoch('subsec')*1000 AS INTEGER)
 WHERE run=(SELECT max(id) FROM egress_runs) AND status='pending'
 AND EXISTS(SELECT 1 FROM egress_jobs j WHERE j.hash=egress_run_members.hash AND j.first_completed=1)
 AND NOT EXISTS(SELECT 1 FROM egress_work w WHERE w.hash=egress_run_members.hash);
 PRAGMA user_version=48;`)
	if err != nil {
		return err
	}
	return tx.Commit()
}
