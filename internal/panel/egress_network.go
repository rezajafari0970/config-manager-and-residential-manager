package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
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

// Route, health, Iran and country evidence retain their original deadlines.
// Ownership data only vetoes a positively observed hosting exit on an Ads flow.
func (s *Store) migrateV46() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version >= 46 {
		return err
	}
	_, err = tx.Exec(`
 DROP VIEW egress_network_eligible;
 CREATE VIEW egress_network_eligible AS
 SELECT e.*, e.valid_until AS network_valid_until FROM egress_eligible e
 JOIN egress_unique u ON u.hash=e.hash
 WHERE NOT EXISTS (SELECT 1 FROM egress_network_results n WHERE n.identity=u.identity AND n.held=1);
 PRAGMA user_version=46;`)
	if err != nil {
		return err
	}
	if err = s.reassessFreshLegacyHolds(tx); err != nil {
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
 ON CONFLICT(key) DO UPDATE SET value=excluded.value WHERE value!=excluded.value`, egress.NetworkPolicyVersion)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 0 {
		if _, err = tx.Exec("UPDATE egress_jobs SET next_run=0 WHERE ever_accepted=1 AND paused=0 AND state!='DELETED' AND NOT EXISTS(SELECT 1 FROM egress_unique u JOIN egress_network_results n ON n.identity=u.identity WHERE u.hash=egress_jobs.hash)"); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Keep every positively observed hosting flow until the identity recovers. V45
// persisted just the first adverse flow in Domain, Variant and Family.
func mergeHostingFlows(current, previous egress.NetworkVerdict) egress.NetworkVerdict {
	seen := make(map[egress.NetworkFlow]bool)
	for _, flow := range current.HostingFlows {
		seen[flow] = true
	}
	previousFlows := previous.HostingFlows
	if len(previousFlows) == 0 && previous.Domain != "" {
		previousFlows = []egress.NetworkFlow{{Domain: previous.Domain, Variant: previous.Variant, Family: previous.Family}}
	}
	for _, flow := range previousFlows {
		if !seen[flow] {
			current.HostingFlows = append(current.HostingFlows, flow)
			seen[flow] = true
		}
	}
	asns := append(slices.Clone(previous.HostingASNs), previous.ASN, current.ASN)
	for _, asn := range asns {
		if asn != 0 && !slices.Contains(current.HostingASNs, asn) {
			current.HostingASNs = append(current.HostingASNs, asn)
		}
	}
	slices.Sort(current.HostingASNs)
	return current
}

// Bound startup work to the freshest current routes. Remaining legacy
// identities use the same replay at their next previously scheduled renewal.
func (s *Store) reassessFreshLegacyHolds(tx *sql.Tx) error {
	rows, err := tx.Query(`SELECT n.hash FROM egress_network_results n
 JOIN egress_eligible e ON e.hash=n.hash JOIN egress_unique u ON u.hash=e.hash AND u.identity=n.identity
 WHERE n.held=1 AND n.state IN ('hosting','mixed') AND n.checked_at=e.tested
 AND n.candidate_hash=e.candidate_hash AND n.last_adverse=n.summary
 AND json_type(n.last_adverse,'$.hosting_flows') IS NULL ORDER BY e.valid_until DESC,n.hash LIMIT 256`)
	if err != nil {
		return err
	}
	var hashes []string
	for rows.Next() {
		var hash string
		if err = rows.Scan(&hash); err != nil {
			rows.Close()
			return err
		}
		hashes = append(hashes, hash)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, hash := range hashes {
		reader, err := s.vault.Open(hash)
		if err != nil {
			continue // Missing original bytes never clear a hold.
		}
		raw, err := io.ReadAll(io.LimitReader(reader, repair.MaxBytes+1))
		reader.Close()
		if err != nil || len(raw) > repair.MaxBytes || egress.Hash(raw) != hash {
			continue
		}
		n, replayed, err := replayLegacyHosting(context.Background(), tx, hash, egress.Prepare(raw))
		if err != nil {
			return err
		}
		if replayed {
			summary, err := json.Marshal(n)
			if err != nil {
				return err
			}
			_, err = tx.Exec(`UPDATE egress_network_results SET held=?,state=?,reason=?,summary=?,valid_until=?,
 clean_rounds=0,clean_until=0,last_adverse=CASE WHEN ? THEN ? ELSE last_adverse END WHERE hash=? AND held=1
 AND identity=(SELECT identity FROM egress_unique WHERE hash=?)`, n.BlocksResidential(), n.State, n.Reason, string(summary), n.Until, n.BlocksResidential(), string(summary), hash, hash)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// V45 stored one adverse scope. Only its exact original receipt can correct
// that decision in-place. Other, newer measurements use normal confirmation.
func replayLegacyHosting(ctx context.Context, tx *sql.Tx, hash string, plan egress.Plan) (egress.NetworkVerdict, bool, error) {
	var empty egress.NetworkVerdict
	if len(plan.Variants) != 2 || !plan.Complete {
		return empty, false, nil
	}
	var report, lastAdverse []byte
	var checkedAt, finished int64
	err := tx.QueryRowContext(ctx, `SELECT j.report,n.last_adverse,n.checked_at,n.last_finished FROM egress_jobs j
 JOIN egress_unique u ON u.hash=j.hash JOIN egress_network_results n ON n.identity=u.identity
 WHERE j.hash=? AND n.hash=j.hash AND n.checked_at=j.tested AND n.last_adverse=n.summary AND n.held=1
 AND n.candidate_hash=j.candidate_hash AND j.candidate_hash=? AND n.state IN ('hosting','mixed')`, hash, plan.Variants[1].Hash).Scan(&report, &lastAdverse, &checkedAt, &finished)
	if errors.Is(err, sql.ErrNoRows) {
		return empty, false, nil
	}
	if err != nil {
		return empty, false, err
	}
	var r egress.Report
	var prior egress.NetworkVerdict
	if json.Unmarshal(report, &r) != nil || json.Unmarshal(lastAdverse, &prior) != nil || !prior.BlocksResidential() || len(prior.HostingFlows) != 0 || r.Finished != finished {
		return empty, false, nil
	}
	d := egress.Evaluate(r, plan, hash, checkedAt)
	n := d.Network
	flow := egress.NetworkFlow{Domain: prior.Domain, Variant: prior.Variant, Family: prior.Family}
	original := egress.SharedNetwork{NetworkFlow: flow, Provider: prior.Provider, ASN: prior.ASN}
	provenShared := d.Eligible && !d.CountryConflict && slices.Contains(n.SharedFlows, flow) && slices.Contains(n.SharedHosting, original)
	if n.BlocksResidential() {
		if !provenShared {
			n = mergeHostingFlows(n, prior)
		}
		return n, true, nil
	}
	if provenShared && n.SharedHostingOnly() {
		return n, true, nil
	}
	return empty, false, nil
}

// Called with the writer reservation and validated claim. A failed or unknown
// observation cannot erase an existing hosting veto or create a new one.
func saveEgressNetwork(ctx context.Context, tx *sql.Tx, r egress.Report, plan egress.Plan, d egress.Decision, candidate string, now int64) (bool, error) {
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
	var previous egress.NetworkVerdict
	if held {
		if err = json.Unmarshal([]byte(lastAdverse), &previous); err != nil {
			return false, err
		}
		if len(previous.HostingFlows) == 0 && previousHash == r.Hash {
			replay, matched, err := replayLegacyHosting(ctx, tx, r.Hash, plan)
			if err != nil {
				return false, err
			}
			if matched && !replay.BlocksResidential() {
				held, cleanRounds, cleanUntil = false, 0, 0
				previous = egress.NetworkVerdict{}
			} else {
				if matched {
					previous = replay
				} else {
					previous = mergeHostingFlows(previous, previous)
				}
				adverse, err := json.Marshal(previous)
				if err != nil {
					return false, err
				}
				lastAdverse = string(adverse)
			}
		}
	}
	wasHeld := held
	until := n.Until
	clean := held && d.Eligible && !d.CountryConflict && candidate != "" &&
		n.ClearanceUntil > now && n.ClearsHosting(previous)
	switch {
	case n.BlocksResidential():
		adverse, err := json.Marshal(mergeHostingFlows(n, previous))
		if err != nil {
			return false, err
		}
		held, cleanRounds, cleanUntil, lastAdverse = true, 0, 0, string(adverse)
	case clean:
		if cleanUntil <= now || previousHash != r.Hash || previousCandidate != candidate || previousPolicy != n.Policy {
			cleanRounds = 0
		}
		if r.Started > lastFinished {
			cleanRounds++
			cleanUntil = min(d.Until, n.ClearanceUntil)
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
 last_adverse=excluded.last_adverse,summary=excluded.summary`, identity, r.Hash, candidate, n.Policy, n.State, n.Reason, now, until,
		held, cleanRounds, max(r.Finished, lastFinished), cleanUntil, lastAdverse, string(b))
	if err != nil {
		return false, err
	}
	if !wasHeld && n.BlocksResidential() {
		// Only a *new* loss on a previously qualified identity opens work.
		// Two following grants can supply both clean measurements. An outage
		// or worker restart consumes the same durable allowance.
		res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO egress_hosting_confirmations
 SELECT j.hash,j.attempts+2,? FROM egress_jobs j JOIN egress_residential_history h ON h.hash=j.hash
 WHERE j.hash=? AND j.ever_accepted=1`, now+egress.IranInterval, r.Hash)
		if err != nil {
			return false, err
		}
		count, err := res.RowsAffected()
		return count == 1, err
	}
	if wasHeld && (!held || n.BlocksResidential() && r.Started > lastFinished) {
		// Two independent adverse reports leave the canonical raw rejection
		// in place. No future first or maintenance test is granted for it.
		if _, err := tx.ExecContext(ctx, "DELETE FROM egress_hosting_confirmations WHERE hash=?", r.Hash); err != nil {
			return false, err
		}
	}
	return held && clean && cleanRounds == 1, nil
}
