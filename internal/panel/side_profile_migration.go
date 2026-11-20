package panel

import "encoding/json"

// Earlier workers could stop a runnable profile after any failed gate. Keep
// that exact historical receipt, but never combine it with checks performed on
// a different session. Only current, retained members qualify for one repair.
func (s *Store) migrateV57() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version >= 57 {
		return err
	}
	if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS side_partial_receipts(
 identity TEXT PRIMARY KEY REFERENCES side_jobs(identity) ON DELETE CASCADE,
 raw_hash TEXT NOT NULL,finished INTEGER NOT NULL,code TEXT NOT NULL,evidence TEXT NOT NULL
 ) WITHOUT ROWID;
 CREATE TEMP TABLE side_profile_members(
 identity TEXT NOT NULL,source_id TEXT NOT NULL,raw_hash TEXT NOT NULL,kind TEXT NOT NULL,size INTEGER NOT NULL,
 PRIMARY KEY(identity,source_id)) WITHOUT ROWID;`); err != nil {
		return err
	}
	services, err := json.Marshal(sideServices)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO side_profile_members
 SELECT j.identity,m.source_id,m.raw_hash,m.kind,m.size FROM side_jobs j
 JOIN memberships m ON m.artifact_id=j.identity JOIN sources s ON s.id=m.source_id
 JOIN artifacts a ON a.id=j.identity
 WHERE j.state='rejected' AND j.code='side_checks_failed' AND j.evidence->>'$.side_version'='side_v1'
 AND j.expires>`+sideNow+` AND a.expires>`+sideNow+` AND s.enabled=1 AND m.generation=s.generation
 AND s.last_success>`+sideNow+`-(SELECT retention_seconds*1000 FROM settings WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM input_exclusions WHERE identity=j.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_iran_guard WHERE identity=j.identity AND state='BLOCKED')
 AND NOT EXISTS(SELECT 1 FROM config_controls WHERE id=j.identity AND expires>`+sideNow+`)
 AND NOT EXISTS(SELECT 1 FROM side_partial_receipts WHERE identity=j.identity)
 AND EXISTS(SELECT 1 FROM json_each(?) k WHERE
 coalesce(json_extract(j.evidence,'$.'||k.value),'not_run')='not_run'
 OR (j.evidence->>'$.raw_failure'='side_checks_failed'
 AND coalesce(json_extract(j.evidence,'$.raw_'||k.value),'not_run')='not_run'))`, string(services)); err != nil {
		return err
	}
	// A renamed config can outlive its original blob. Prefer the previously
	// measured bytes when still owned, otherwise use a current alias of the
	// same canonical identity. Neither repair nor aliasing renews retention.
	if _, err = tx.Exec(`INSERT INTO side_partial_receipts
 SELECT identity,raw_hash,finished,code,evidence FROM side_jobs WHERE identity IN(SELECT identity FROM side_profile_members);
 WITH ranked AS MATERIALIZED (SELECT m.*,row_number() OVER (PARTITION BY m.identity
 ORDER BY (m.raw_hash=j.raw_hash) DESC,m.source_id) AS rank FROM side_profile_members m JOIN side_jobs j ON j.identity=m.identity)
 UPDATE side_jobs AS j SET raw_hash=m.raw_hash,kind=m.kind,size=m.size,state='pending',attempts=0,
 queued_at=` + sideNow + `,next_run=` + sideNow + `,finished=0,code='side_profile_completion',evidence='{}',
 token='',lease_until=0,last_token='',engine='',candidate_hash=''
 FROM ranked m WHERE j.identity=m.identity AND m.rank=1;
 INSERT OR IGNORE INTO side_sources SELECT m.source_id,j.identity,j.expires
 FROM side_profile_members m JOIN side_jobs j ON j.identity=m.identity;
 DROP TABLE side_profile_members;
 DROP TRIGGER IF EXISTS side_measured;` + sideMeasuredTrigger + `
 PRAGMA user_version=57`); err != nil {
		return err
	}
	return tx.Commit()
}
