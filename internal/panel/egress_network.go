package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

// Network eligibility is residential-only. egress_eligible is also an ordinary
// collection/retention safety input and must keep its existing route contract.
func (s *Store) migrateV45() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version >= 45 {
		return err
	}
	var geo string
	if err = tx.QueryRow("SELECT sql FROM sqlite_master WHERE type='view' AND name='egress_geo_eligible'").Scan(&geo); err != nil {
		return err
	}
	if !strings.Contains(geo, "FROM egress_eligible ") {
		return errors.New("unexpected country eligibility definition")
	}
	geo = strings.Replace(geo, "FROM egress_eligible ", "FROM egress_network_eligible ", 1)
	_, err = tx.Exec(`
 CREATE TABLE egress_network_results(
   identity TEXT PRIMARY KEY,
   hash TEXT NOT NULL, candidate_hash TEXT NOT NULL, policy TEXT NOT NULL,
   state TEXT NOT NULL, reason TEXT NOT NULL, checked_at INTEGER NOT NULL, valid_until INTEGER NOT NULL,
   held INTEGER NOT NULL, clean_rounds INTEGER NOT NULL, last_finished INTEGER NOT NULL,
   clean_until INTEGER NOT NULL, last_adverse TEXT NOT NULL, summary TEXT NOT NULL
 );
 CREATE INDEX egress_network_current_access ON egress_network_results(valid_until,identity) WHERE held=0 AND state='access';
 -- The subscription collector can replace the representative while retaining
 -- its semantic identity. Drop transferable positive proof, retain a holding
 -- decision and require two fresh clear reports for the new exact bytes.
 CREATE TRIGGER egress_network_representative_removed AFTER DELETE ON egress_unique BEGIN
   DELETE FROM egress_network_results WHERE identity=old.identity AND held=0;
   UPDATE egress_network_results SET valid_until=0,clean_rounds=0,clean_until=0 WHERE identity=old.identity AND held=1;
 END;
 CREATE VIEW egress_network_eligible AS
 SELECT e.*, n.valid_until AS network_valid_until FROM egress_eligible e
 JOIN egress_unique u ON u.hash=e.hash JOIN egress_network_results n ON n.identity=u.identity
 WHERE n.hash=e.hash AND n.candidate_hash=e.candidate_hash AND n.checked_at=e.tested
 AND n.held=0 AND n.state='access' AND n.policy=(SELECT value FROM metadata WHERE key='ads-exit-network-policy')
 AND n.valid_until>CAST(unixepoch('subsec')*1000 AS INTEGER);
 DROP VIEW egress_geo_eligible;` + geo + `;
 PRAGMA user_version=45;`)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// A new network evaluator only invalidates its own proofs. In particular it
// must not advance the egress route epoch, which would withdraw ordinary data.
func (s *Store) reconcileEgressNetworkPolicy() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`INSERT INTO metadata(key,value) VALUES('ads-exit-network-policy',?)
 ON CONFLICT(key) DO UPDATE SET value=excluded.value WHERE value!=excluded.value`, egress.NetworkVersion)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 0 {
		if _, err = tx.Exec("UPDATE egress_jobs SET next_run=0 WHERE ever_accepted=1 AND paused=0 AND state!='DELETED'"); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Called with the writer reservation and validated claim. An old worker or an
// incomplete attempt can withdraw publication, never erase a prior hosting
// observation. Access evidence is tied to this specific representative/template.
func saveEgressNetwork(ctx context.Context, tx *sql.Tx, r egress.Report, d egress.Decision, candidate string, now int64) (bool, error) {
	var identity string
	if err := tx.QueryRowContext(ctx, "SELECT identity FROM egress_unique WHERE hash=?", r.Hash).Scan(&identity); err != nil {
		return false, err
	}
	var held bool
	var cleanRounds int
	var previousHash, previousCandidate, previousPolicy, lastAdverse string
	var lastFinished, cleanUntil int64
	err := tx.QueryRowContext(ctx, "SELECT hash,candidate_hash,policy,held,clean_rounds,last_finished,clean_until,last_adverse FROM egress_network_results WHERE identity=?", identity).
		Scan(&previousHash, &previousCandidate, &previousPolicy, &held, &cleanRounds, &lastFinished, &cleanUntil, &lastAdverse)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	if lastAdverse == "" {
		lastAdverse = "{}"
	}
	n := d.Network
	b, err := json.Marshal(n)
	if err != nil {
		return false, err
	}
	until := int64(0)
	clean := d.Eligible && !d.CountryConflict && n.Version == egress.NetworkVersion && n.State == "access" && n.Eligible && n.Until > now && candidate != ""
	switch {
	case n.Version == egress.NetworkVersion && (n.State == "hosting" || n.State == "mixed"):
		held, cleanRounds, cleanUntil, lastAdverse = true, 0, 0, string(b)
	case clean:
		until = min(n.Until, d.Until)
		if cleanUntil <= now || previousHash != r.Hash || previousCandidate != candidate || previousPolicy != n.Version {
			cleanRounds = 0
		}
		if held && r.Started > lastFinished {
			cleanRounds++
			cleanUntil = until
			if cleanRounds >= 2 {
				held = false
			}
		}
	default:
		cleanRounds, cleanUntil = 0, 0
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO egress_network_results(identity,hash,candidate_hash,policy,state,reason,checked_at,valid_until,held,clean_rounds,last_finished,clean_until,last_adverse,summary)
 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(identity) DO UPDATE SET hash=excluded.hash,candidate_hash=excluded.candidate_hash,
 policy=excluded.policy,state=excluded.state,reason=excluded.reason,checked_at=excluded.checked_at,valid_until=excluded.valid_until,
 held=excluded.held,clean_rounds=excluded.clean_rounds,last_finished=excluded.last_finished,clean_until=excluded.clean_until,
 last_adverse=excluded.last_adverse,summary=excluded.summary`, identity, r.Hash, candidate, n.Version, n.State, n.Reason, now, until,
		held, cleanRounds, max(r.Finished, lastFinished), cleanUntil, lastAdverse, string(b))
	return held && clean && cleanRounds == 1, err
}
