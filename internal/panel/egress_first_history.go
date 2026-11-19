package panel

import (
	"errors"
	"io"
	"strings"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/protocolpolicy"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
)

// A source that staged a line could be only an observer. Before this repair,
// selecting a representative required a committed membership (or a validated,
// count-held source snapshot with its own durable first backlog). Exactly one
// historical source for these exact bytes therefore proves the owner's identity.
// Revision 1 also excludes manual raw deletion and earlier assessment epoch resets.
const egressNeverAssessedHistory = `SELECT u.hash,o.source,u.created,j.size,j.kind FROM egress_unique u
 CROSS JOIN egress_jobs j ON j.hash=u.hash
 CROSS JOIN egress_owners o ON o.hash=u.hash AND o.identity=u.identity
 CROSS JOIN sources s ON s.id=o.source
 WHERE j.revision=1 AND j.state='PENDING' AND j.reason='new_input' AND j.first_completed=0 AND j.tested=0 AND j.ever_accepted=0
 AND j.attempts=0 AND j.claimed_at=0 AND j.paused=0 AND j.token='' AND j.lease_until=0
 AND j.decision='{}' AND j.report='{}' AND j.candidate_hash='' AND j.valid_until=0
 AND j.deep_completed=0 AND j.failures=0 AND j.last_failure=0 AND j.retry_streak=0
 AND s.enabled=1 AND (s.revision=1 OR (s.updated+1)*1000<=u.created)
 AND NOT EXISTS(SELECT 1 FROM egress_owners x WHERE x.hash=u.hash AND (x.source!=o.source OR x.identity!=o.identity))
 AND NOT EXISTS(SELECT 1 FROM memberships m WHERE m.artifact_id=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_first_backlog b WHERE b.hash=u.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_settlements t WHERE t.hash=u.hash)
 AND u.hash NOT IN (SELECT hash FROM egress_events)
 AND u.hash NOT IN (SELECT hash FROM egress_run_members WHERE status='completed' OR settled_at>0)
 AND NOT EXISTS(SELECT 1 FROM egress_health p WHERE p.hash=u.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_geo_results p WHERE p.hash=u.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_countries p WHERE p.hash=u.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_retirements r WHERE r.hash=u.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_network_results n WHERE n.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_network_review v WHERE v.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_residential_history h WHERE h.hash=u.hash)
 AND NOT EXISTS(SELECT 1 FROM input_exclusions x WHERE x.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM config_controls c WHERE c.id=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_iran_guard g WHERE g.identity=u.identity)
 AND NOT EXISTS(SELECT 1 FROM egress_first_history h WHERE h.hash=u.hash)`

const historyOriginalOwnerRemoved = `
 UPDATE egress_jobs SET revision=revision+1,token='',lease_until=0 WHERE token!='' AND hash IN
 (SELECT hash FROM egress_first_history WHERE source_id=OLD.id AND phase='active');
 UPDATE egress_first_history SET origin_valid=0 WHERE source_id=OLD.id AND phase='promoted';
 UPDATE egress_first_history SET phase='cancelled' WHERE source_id=OLD.id AND (phase IN('active','waiting','paused','unavailable')
 OR (phase='promoted' AND NOT EXISTS(SELECT 1 FROM egress_unique u JOIN memberships m ON m.artifact_id=u.identity
 WHERE u.hash=egress_first_history.hash AND m.source_id!=OLD.id) AND NOT EXISTS(SELECT 1 FROM egress_first_backlog b
 WHERE b.hash=egress_first_history.hash AND b.source_id!=OLD.id)));`

const firstHistorySchema = `
 CREATE TABLE IF NOT EXISTS egress_first_history(
 hash TEXT PRIMARY KEY,source_id TEXT NOT NULL,created INTEGER NOT NULL,
 phase TEXT NOT NULL CHECK(phase IN ('waiting','active','promoted','completed','unavailable','paused','cancelled')),
 ready_at INTEGER NOT NULL,
 raw_available INTEGER NOT NULL CHECK(raw_available IN (0,1)),
 origin_valid INTEGER NOT NULL DEFAULT 1 CHECK(origin_valid IN (0,1))) WITHOUT ROWID;
 CREATE INDEX IF NOT EXISTS egress_first_history_due ON egress_first_history(ready_at,hash) WHERE phase IN ('waiting','active');
 CREATE INDEX IF NOT EXISTS egress_first_history_active_due ON egress_first_history(ready_at,hash) WHERE phase='active';
 CREATE INDEX IF NOT EXISTS egress_first_history_source ON egress_first_history(source_id,phase);
 CREATE TABLE IF NOT EXISTS egress_first_history_counts(phase TEXT PRIMARY KEY,total INTEGER NOT NULL CHECK(total>=0)) WITHOUT ROWID;
 CREATE TRIGGER IF NOT EXISTS egress_first_history_count_insert AFTER INSERT ON egress_first_history BEGIN
 INSERT INTO egress_first_history_counts VALUES(NEW.phase,1) ON CONFLICT(phase) DO UPDATE SET total=total+1;
 END;
 CREATE TRIGGER IF NOT EXISTS egress_first_history_count_phase AFTER UPDATE OF phase ON egress_first_history WHEN NEW.phase!=OLD.phase BEGIN
 UPDATE egress_first_history_counts SET total=total-1 WHERE phase=OLD.phase;
 INSERT INTO egress_first_history_counts VALUES(NEW.phase,1) ON CONFLICT(phase) DO UPDATE SET total=total+1;
 END;
 CREATE TRIGGER IF NOT EXISTS egress_first_history_count_delete AFTER DELETE ON egress_first_history BEGIN
 UPDATE egress_first_history_counts SET total=total-1 WHERE phase=OLD.phase;
 END;

 CREATE TRIGGER IF NOT EXISTS egress_first_history_job AFTER UPDATE OF first_completed,state,next_run,token,lease_until,paused ON egress_jobs
 WHEN EXISTS(SELECT 1 FROM egress_first_history h WHERE h.hash=NEW.hash AND h.phase NOT IN('cancelled','completed')) BEGIN
 UPDATE egress_first_history SET ready_at=CASE WHEN NEW.token!='' THEN NEW.lease_until ELSE max(created,NEW.next_run) END,
 raw_available=CASE WHEN NEW.token='' AND NEW.reason='input_unavailable' THEN 0 ELSE raw_available END,
 phase=CASE WHEN NEW.first_completed=1 THEN 'completed' WHEN NEW.state='DELETED' THEN 'cancelled'
 WHEN phase='promoted' THEN phase WHEN NEW.paused=1 OR NOT EXISTS(SELECT 1 FROM sources s WHERE s.id=source_id AND s.enabled=1) THEN 'paused'
 WHEN raw_available=0 OR (NEW.token='' AND NEW.reason='input_unavailable') THEN 'unavailable' WHEN NEW.token!='' THEN 'active' ELSE 'waiting' END WHERE hash=NEW.hash;
 END;
 CREATE TRIGGER IF NOT EXISTS egress_first_history_membership AFTER INSERT ON memberships BEGIN
 UPDATE egress_first_history SET phase='promoted' WHERE hash=(SELECT hash FROM egress_unique WHERE identity=NEW.artifact_id)
 AND phase IN('waiting','active','paused','unavailable');
 END;
 CREATE TRIGGER IF NOT EXISTS egress_first_history_backlog AFTER INSERT ON egress_first_backlog BEGIN
 UPDATE egress_first_history SET phase='promoted' WHERE hash=NEW.hash AND phase IN('waiting','active','paused','unavailable');
 END;
 CREATE TRIGGER IF NOT EXISTS egress_first_history_replaced AFTER DELETE ON egress_unique BEGIN
 UPDATE egress_first_history SET phase='cancelled' WHERE hash=OLD.hash AND phase NOT IN('completed','cancelled');
 END;
 CREATE TRIGGER IF NOT EXISTS egress_first_history_source_deleted AFTER DELETE ON sources BEGIN` + historyOriginalOwnerRemoved + `
 END;
 CREATE TRIGGER IF NOT EXISTS egress_first_history_source_replaced AFTER UPDATE OF url_hash ON sources WHEN NEW.url_hash!=OLD.url_hash BEGIN` + historyOriginalOwnerRemoved + `
 END;
 CREATE TRIGGER IF NOT EXISTS egress_first_history_source_enabled AFTER UPDATE OF enabled ON sources WHEN NEW.enabled!=OLD.enabled BEGIN
 UPDATE egress_jobs SET revision=revision+1,token='',lease_until=0 WHERE NEW.enabled=0 AND token!='' AND hash IN
 (SELECT hash FROM egress_first_history WHERE source_id=NEW.id AND phase='active');
 UPDATE egress_first_history SET phase=CASE WHEN NEW.enabled=0 OR (SELECT paused FROM egress_jobs WHERE egress_jobs.hash=egress_first_history.hash)=1 THEN 'paused'
 WHEN raw_available=0 THEN 'unavailable' ELSE 'waiting' END WHERE source_id=NEW.id AND phase IN('active','waiting','paused','unavailable');
 END;
 CREATE TRIGGER IF NOT EXISTS egress_first_history_exclusion AFTER INSERT ON input_exclusions BEGIN
 UPDATE egress_first_history SET phase='cancelled' WHERE hash=(SELECT hash FROM egress_unique WHERE identity=NEW.identity) AND phase NOT IN('cancelled','completed');
 END;
 CREATE TRIGGER IF NOT EXISTS egress_first_history_iran AFTER INSERT ON egress_iran_guard BEGIN
 UPDATE egress_first_history SET phase=CASE WHEN NEW.state='BLOCKED' THEN 'cancelled' ELSE 'promoted' END
 WHERE hash=(SELECT hash FROM egress_unique WHERE identity=NEW.identity) AND phase NOT IN('cancelled','completed');
 END;
 CREATE TRIGGER IF NOT EXISTS egress_first_history_iran_block AFTER UPDATE OF state ON egress_iran_guard WHEN NEW.state='BLOCKED' BEGIN
 UPDATE egress_first_history SET phase='cancelled' WHERE hash=(SELECT hash FROM egress_unique WHERE identity=NEW.identity) AND phase NOT IN('cancelled','completed');
 END;`

// A live source can promote a historical job, then be deleted independently of
// its original source. Revert only when the last live/pinned association goes.
// During ordinary source rotation these changes are within the same transaction.
const historyAfterModernWithdrawal = `UPDATE egress_first_history SET phase=CASE
 WHEN origin_valid=0 OR NOT EXISTS(SELECT 1 FROM sources WHERE id=source_id) THEN 'cancelled'
 WHEN (SELECT paused FROM egress_jobs WHERE egress_jobs.hash=egress_first_history.hash)=1
 OR (SELECT enabled FROM sources WHERE id=source_id)=0 THEN 'paused'
 WHEN raw_available=0 THEN 'unavailable' ELSE 'waiting' END
 WHERE phase='promoted'
 AND NOT EXISTS(SELECT 1 FROM egress_unique u JOIN memberships m ON m.artifact_id=u.identity WHERE u.hash=egress_first_history.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_first_backlog b WHERE b.hash=egress_first_history.hash)
 AND NOT EXISTS(SELECT 1 FROM egress_jobs j WHERE j.hash=egress_first_history.hash AND j.first_completed=1)
 AND hash=`

const firstHistoryWithdrawalTriggers = `CREATE TRIGGER IF NOT EXISTS egress_first_history_membership_removed AFTER DELETE ON memberships BEGIN ` +
	historyAfterModernWithdrawal + `(SELECT hash FROM egress_unique WHERE identity=OLD.artifact_id); END;
 CREATE TRIGGER IF NOT EXISTS egress_first_history_pin_removed AFTER DELETE ON egress_first_backlog BEGIN ` +
	historyAfterModernWithdrawal + `OLD.hash; END;`

func (s *Store) migrateV52() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version >= 52 {
		return err
	}
	if _, err = tx.Exec(firstHistorySchema + firstHistoryWithdrawalTriggers); err != nil {
		return err
	}
	// History-only rows enter the hot inventory only while admitted by the
	// dispatcher. The bulk readiness index never expands ordinary reads.
	var inventory string
	if err = tx.QueryRow("SELECT sql FROM sqlite_schema WHERE name='egress_inventory'").Scan(&inventory); err != nil {
		return err
	}
	if !strings.Contains(inventory, "egress_first_history") {
		const pin = "EXISTS(SELECT 1 FROM egress_first_backlog b WHERE b.hash=u.hash)"
		if strings.Count(inventory, pin) != 1 {
			return errors.New("unrecognized first-assessment inventory definition")
		}
		inventory = strings.Replace(inventory, pin, "("+pin+" OR EXISTS(SELECT 1 FROM egress_first_history a WHERE a.hash=u.hash AND a.phase='active'))", 1)
		if _, err = tx.Exec("DROP VIEW egress_inventory;" + inventory); err != nil {
			return err
		}
	}
	type archived struct {
		hash, source  string
		created, size int64
		kind          string
	}
	var input []archived
	rows, err := tx.Query(egressNeverAssessedHistory)
	if err != nil {
		return err
	}
	for rows.Next() {
		var a archived
		if err = rows.Scan(&a.hash, &a.source, &a.created, &a.size, &a.kind); err != nil {
			rows.Close()
			return err
		}
		input = append(input, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	insert, err := tx.Prepare("INSERT INTO egress_first_history(hash,source_id,created,phase,ready_at,raw_available) VALUES(?,?,?,?,?,?)")
	if err != nil {
		return err
	}
	defer insert.Close()
	for _, a := range input {
		phase := s.firstHistoryRawPhase(a.hash, a.size, a.kind)
		if _, err = insert.Exec(a.hash, a.source, a.created, phase, a.created, phase == "waiting"); err != nil {
			return err
		}
	}
	if err = rememberMeasuredOrdinaryReceipts(tx); err != nil {
		return err
	}
	if _, err = tx.Exec("PRAGMA user_version=52"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) firstHistoryRawPhase(hash string, size int64, kind string) string {
	if size <= 0 || size > repair.MaxBytes {
		return "unavailable"
	}
	r, err := s.vault.Open(hash)
	if err != nil {
		return "unavailable"
	}
	defer r.Close()
	// Vault.Open authenticates each frame and verifies the file name's digest
	// at EOF. Consume through the authenticated terminal record before admission.
	b, err := io.ReadAll(io.LimitReader(r, size+1))
	if err != nil || int64(len(b)) != size {
		return "unavailable"
	}
	if protocolpolicy.Disabled(kind, b) {
		return "cancelled"
	}
	return "waiting"
}
