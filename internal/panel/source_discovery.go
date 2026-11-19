package panel

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/collect"
)

// Use the same representative and raw provenance for accepted membership and
// for complete source responses held solely by the cardinality check.
const registerEgressIdentitySQL = ` INSERT INTO egress_jobs(hash,kind,size,first_seen,last_seen)
 SELECT new.raw_hash,new.kind,new.size,CAST(unixepoch('subsec')*1000 AS INTEGER),CAST(unixepoch('subsec')*1000 AS INTEGER)
 WHERE NOT EXISTS(SELECT 1 FROM input_exclusions WHERE identity=new.artifact_id)
 ON CONFLICT(hash) DO UPDATE SET last_seen=excluded.last_seen,
 state=CASE WHEN egress_jobs.reason IN('ordinary_delete','retention_expired') AND NOT EXISTS(SELECT 1 FROM egress_unique u WHERE u.hash=egress_jobs.hash) THEN 'PENDING' ELSE egress_jobs.state END,
 reason=CASE WHEN egress_jobs.reason IN('ordinary_delete','retention_expired') AND NOT EXISTS(SELECT 1 FROM egress_unique u WHERE u.hash=egress_jobs.hash) THEN 'unique_epoch' ELSE egress_jobs.reason END;
 INSERT OR IGNORE INTO egress_owners SELECT new.raw_hash,new.artifact_id,new.source_id WHERE EXISTS(SELECT 1 FROM egress_jobs WHERE hash=new.raw_hash);
 INSERT OR IGNORE INTO egress_unique SELECT new.artifact_id,new.raw_hash,CAST(unixepoch('subsec')*1000 AS INTEGER)
 WHERE EXISTS(SELECT 1 FROM egress_jobs WHERE hash=new.raw_hash AND state!='DELETED') AND NOT EXISTS(SELECT 1 FROM input_exclusions WHERE identity=new.artifact_id);`

const egressDiscoveryRegistrationDDL = `
 CREATE VIEW IF NOT EXISTS egress_discovery_inputs(source_id,artifact_id,raw_hash,kind,size)
 AS SELECT NULL,NULL,NULL,NULL,NULL WHERE 0;
 CREATE TRIGGER IF NOT EXISTS egress_discover_input INSTEAD OF INSERT ON egress_discovery_inputs BEGIN
 ` + registerEgressIdentitySQL + `
 END;`

// A small but fully parsed response can contain a new config that never
// appears again. Queue it while leaving the accepted source snapshot intact.
// The caller has validated the source lease and the successful extraction.
func rememberHeldSource(ctx context.Context, tx *sql.Tx, r collect.Result, job collect.Job, stamp int64) error {
	records := "SELECT source_id,identity,hash,kind,size FROM staged WHERE source_id=? AND token=?"
	args := []any{job.ID, job.Token}
	if !r.Staged {
		// Pass only input metadata to SQLite. Proposed repairs can contain
		// large decoded payloads and have no role in identity selection.
		type input struct {
			Identity string `json:"identity"`
			Hash     string `json:"hash"`
			Kind     string `json:"kind"`
			Size     int64  `json:"size"`
		}
		inputs := make([]input, 0, len(r.Items))
		for _, item := range r.Items {
			inputs = append(inputs, input{item.Identity, item.Hash, item.Kind, item.Size})
		}
		raw, err := json.Marshal(inputs)
		if err != nil {
			return err
		}
		records = `SELECT ? AS source_id, value->>'$.identity' AS identity,value->>'$.hash' AS hash,value->>'$.kind' AS kind,value->>'$.size' AS size FROM json_each(?)`
		args = []any{job.ID, string(raw)}
	}
	// Existing current members already use the ordinary registration path.
	// The same input can still need a pending first test under another source.
	records = `SELECT i.* FROM (` + records + `) i
    WHERE NOT EXISTS(SELECT 1 FROM memberships m WHERE m.source_id=i.source_id AND m.artifact_id=i.identity)
    AND NOT EXISTS(SELECT 1 FROM input_exclusions x WHERE x.identity=i.identity)
    AND NOT EXISTS(SELECT 1 FROM egress_iran_guard g WHERE g.identity=i.identity AND g.state='BLOCKED')
    AND NOT EXISTS(SELECT 1 FROM config_controls c WHERE c.id=i.identity AND c.expires>?)`
	args = append(args, stamp)
	if _, err := tx.ExecContext(ctx, `INSERT INTO egress_discovery_inputs(source_id,artifact_id,raw_hash,kind,size) `+records, args...); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO egress_first_backlog(source_id,hash)
    SELECT i.source_id,u.hash FROM (`+records+`) i JOIN egress_unique u ON u.identity=i.identity
    JOIN egress_jobs j ON j.hash=u.hash WHERE j.tested=0 AND j.first_completed=0 AND j.state!='DELETED'`, args...); err != nil {
		return err
	}
	return rememberOrdinaryFirst(ctx, tx, records, args...)
}
